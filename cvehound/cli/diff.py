"""`cvehound diff`: what a commit range or a patch does to the CVE verdicts.

Every rule whose files the change touches runs at both ends; the pair of
verdicts says whether the change fixed the CVE, introduced it, or left it
where it was. Alongside, the commit messages are read for the fix and
introducing commits the metadata knows, which covers CVEs no rule exists for.
"""

import argparse
import os
import sys
import tempfile
from typing import Any

from cvehound import CVEhound
from cvehound.cli.common import (
    ReportFile,
    Task,
    add_cve_options,
    build_hound,
    common_parser,
    configure_logging,
    confine,
    disable_astcache,
    fail,
    load_settings,
    quiet_loglevel,
    require_kernel,
    resolve_arch,
    resolve_metadata,
    resolve_spatch,
    run_pool,
    select_cves,
    split_range,
    tools_report,
)
from cvehound.gitevidence import RangeEvidence, commit_table, range_evidence
from cvehound.gitrepo import GitRepo
from cvehound.gitrev import (
    FIXED,
    INTRODUCED,
    STILL_VULNERABLE,
    UNAFFECTED,
    ChangedFiles,
    RevTree,
    classify,
    first_flip,
    materialize_present,
    materialize_tree,
    signed_walk,
)
from cvehound.oracle import BlobMaterializer, Sig
from cvehound.util import get_kernel_version

FAIL_ON = ('none', 'introduced', 'detected')
# Distinct from 1 (usage/environment error) so a CI job can tell "the change
# introduces a CVE" from "cvehound could not run".
EXIT_FAILED_POLICY = 3

FROM, TO = 'from', 'to'


def build_parser(prog: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=prog,
        parents=[common_parser()],
        description='Tell which CVEs a commit range or a patch fixes or introduces',
        epilog='Each rule whose files the change touches runs at both ends of it; the pair'
        ' of verdicts is classified as fixed, introduced or still-vulnerable. Commit'
        ' messages are read as well, for the fix and introducing commits the CVE'
        ' metadata knows about. Nothing is checked out and the working tree is not'
        ' touched; --patch leaves only dangling objects in the object database.',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    add_cve_options(parser, greedy=False)
    parser.add_argument(
        'range',
        nargs='?',
        metavar='A..B',
        help='the commit range to analyse, as two revisions of the repository at --kernel',
    )
    parser.add_argument(
        '--patch',
        metavar='FILE',
        help='analyse this patch (or series; - reads stdin) applied on --base instead of a range',
    )
    parser.add_argument(
        '--base',
        default='HEAD',
        metavar='REV',
        help='the revision --patch applies on',
    )
    parser.add_argument(
        '--per-commit',
        action='store_true',
        help='for a verdict that changes across a range, name the commit that changed it'
        " (walks only the commits touching the rule's files)",
    )
    parser.add_argument(
        '--fail-on',
        choices=FAIL_ON,
        default='none',
        help=f'exit {EXIT_FAILED_POLICY} when the change introduces a CVE (introduced),'
        ' or when any touched CVE is detected at its end (detected)',
    )
    return parser


def read_patch(path: str) -> bytes:
    if path == '-':
        return sys.stdin.buffer.read()
    try:
        with open(path, 'rb') as fh:
            return fh.read()
    except OSError as err:
        fail(f"Can't read patch: {err}")


def end_report(tree: RevTree) -> dict[str, Any]:
    return tree.report() | {'kernel': get_kernel_version(tree.path)}


def files_present(tree: RevTree, files: list[str]) -> bool:
    return any(os.path.exists(os.path.join(tree.path, f)) for f in files)


def main(args: list[str], prog: str = 'cvehound diff') -> int:
    parser = build_parser(prog)
    cmdargs = parser.parse_args(args)
    args_cfg = load_settings(parser, cmdargs)
    kernel = require_kernel(parser, args_cfg)
    metadata_path = resolve_metadata(args_cfg)

    if bool(args_cfg['range']) == bool(args_cfg['patch']):
        fail('give either a commit range A..B or --patch FILE')
    if args_cfg['per_commit'] and not args_cfg['range']:
        fail('--per-commit walks a commit range; it does not apply to --patch')

    repo = GitRepo(kernel)
    spatch = resolve_spatch(args_cfg)
    loglevel = configure_logging(args_cfg['verbose'])
    disable_astcache(args_cfg)
    patch = read_patch(args_cfg['patch']) if args_cfg['patch'] else None

    with tempfile.TemporaryDirectory(prefix='cvehound-diff-', ignore_cleanup_errors=True) as root:
        materializer = BlobMaterializer(repo, root)
        if patch is not None:
            base = repo.rev_parse(args_cfg['base'])
            tree_from = materialize_tree(materializer, repo, args_cfg['base'], base)
            label_to = f'{args_cfg["base"]} + {args_cfg["patch"]}'
            tree_to = materialize_tree(materializer, repo, label_to, repo.patch_tree(base, patch))
            messages = iter([('patch', patch.decode(errors='replace'))])
        else:
            rev_from, rev_to = split_range(args_cfg['range'])
            tree_from = materialize_tree(materializer, repo, rev_from, repo.rev_parse(rev_from))
            tree_to = materialize_tree(materializer, repo, rev_to, repo.rev_parse(rev_to))
            messages = repo.log_messages(f'{tree_from.sha}..{tree_to.sha}')
        changed = repo.diff_names(tree_from.sha, tree_to.sha)

        args_cfg['arch'] = resolve_arch(args_cfg, {}, tree_from.path)
        hound = build_hound(tree_from.path, args_cfg, metadata_path, spatch)
        evidence = range_evidence(messages, commit_table(hound))
        touched = ChangedFiles(changed)
        candidates = [
            cve
            for cve in select_cves(hound, args_cfg)
            if touched.touches(hound.get_rule_files(cve))
        ]

        report: dict[str, Any] = {
            'args': {
                'cve': candidates,
                'kernel': args_cfg['kernel'],
                'range': args_cfg['range'],
                'patch': args_cfg['patch'],
                'base': args_cfg['base'] if patch is not None else None,
                'per_commit': args_cfg['per_commit'],
                'fail_on': args_cfg['fail_on'],
                'exclude': sorted(args_cfg['exclude']),
                'exploit': args_cfg['exploit'],
                'metadata': metadata_path,
            },
            'range': {
                FROM: end_report(tree_from),
                TO: end_report(tree_to),
                'changed_files': changed,
            },
            'evidence': evidence.report(),
            'tools': tools_report(hound, metadata_path),
            'results': {},
            'errors': {},
        }

        with ReportFile(args_cfg['report']) as out:
            confine(tree_from.path, hound, metadata_path, args_cfg['sandbox'], repo=repo)
            statuses = evaluate_ends(hound, loglevel, candidates, tree_from, tree_to, report)
            if args_cfg['per_commit']:
                locate_flips(hound, loglevel, repo, materializer, tree_from, tree_to, report)
            print_summary(report, evidence, tree_from, tree_to, len(candidates), len(changed))
            out.write(report)
    return exit_code(args_cfg['fail_on'], statuses)


def evaluate_ends(
    hound: CVEhound,
    loglevel: int,
    candidates: list[str],
    tree_from: RevTree,
    tree_to: RevTree,
    report: dict[str, Any],
) -> list[str]:
    tasks: list[Task] = []
    for cve in candidates:
        tasks.append((cve, False, tree_from.path))
        tasks.append((cve, False, tree_to.path))
    outcomes = run_pool(hound, quiet_loglevel(loglevel), tasks)
    statuses = []
    for cve in candidates:
        at_from = outcomes[(cve, False, tree_from.path)]
        at_to = outcomes[(cve, False, tree_to.path)]
        # Keyed by end, so a rule that fails at both (UnsupportedVersion does,
        # always) reports both rather than the last one written.
        errors = {end: o.error for end, o in ((FROM, at_from), (TO, at_to)) if o.error is not None}
        if errors:
            report['errors'][cve] = errors
            continue
        status = classify(bool(at_from.result), bool(at_to.result))
        if status == UNAFFECTED:
            continue
        statuses.append(status)
        files = hound.get_rule_files(cve)
        report['results'][cve] = hound.get_cve_metadata(cve) | {
            'status': status,
            FROM: at_from.result,
            TO: at_to.result,
            'files_present': {
                FROM: files_present(tree_from, files),
                TO: files_present(tree_to, files),
            },
        }
    return statuses


def locate_flips(
    hound: CVEhound,
    loglevel: int,
    repo: GitRepo,
    materializer: BlobMaterializer,
    tree_from: RevTree,
    tree_to: RevTree,
    report: dict[str, Any],
) -> None:
    """Name the commit at which each changed verdict changed.

    Only commits that touch the rule's files can move its verdict, so the walk
    is over those; identical signatures collapse, so spatch runs once per
    distinct content, however many commits share it.
    """
    flipped = [cve for cve, r in report['results'].items() if r['status'] in (FIXED, INTRODUCED)]
    if not flipped:
        return
    # Walk and sign once per distinct Files: set (rules cluster on hot files);
    # tasks stay per (cve, tree), since the verdict is the rule's, not the tree's.
    walks: dict[tuple[str, ...], list[tuple[str, Sig]]] = {}
    trees: dict[Sig, str] = {}
    tasks: list[Task] = []
    for cve in flipped:
        files = tuple(hound.get_rule_files(cve))
        if files not in walks:
            walks[files] = signed_walk(repo, materializer, tree_from.sha, tree_to.sha, files)
            trees |= materialize_present(materializer, (sig for _, sig in walks[files]))
        for sig in dict.fromkeys(sig for _, sig in walks[files] if sig in trees):
            tasks.append((cve, False, trees[sig]))
    outcomes = run_pool(hound, quiet_loglevel(loglevel), tasks)

    for cve in flipped:
        seq = walks[tuple(hound.get_rule_files(cve))]
        verdicts: list[bool | None] = []
        for _, sig in seq:
            if sig not in trees:
                verdicts.append(False)
                continue
            outcome = outcomes[(cve, False, trees[sig])]
            verdicts.append(None if outcome.error is not None else bool(outcome.result))
        entry = report['results'][cve]
        flip = None if None in verdicts else first_flip([bool(v) for v in verdicts])
        entry['commit'] = None if flip is None else seq[flip][0]
        if flip is not None:
            entry['commit_subject'] = repo.commit_subject(seq[flip][0])


def print_summary(
    report: dict[str, Any],
    evidence: RangeEvidence,
    tree_from: RevTree,
    tree_to: RevTree,
    candidates: int,
    changed: int,
) -> None:
    a, b = tree_from.rev, tree_to.rev
    counts = dict.fromkeys((FIXED, INTRODUCED, STILL_VULNERABLE), 0)
    for cve, entry in sorted(report['results'].items()):
        status = entry['status']
        counts[status] += 1
        present = entry['files_present']
        if status == FIXED:
            detail = f'detected at {a}, not at {b}'
            if not present[TO]:
                detail = f'rule files absent at {b}'
        elif status == INTRODUCED:
            detail = f'not at {a}, detected at {b}'
            if not present[FROM]:
                detail = f'rule files absent at {a}'
        else:
            detail = 'detected at both ends'
        if entry.get('commit'):
            detail += f'; by {entry["commit_subject"]}'
        print(f'{cve}: {status} ({detail})')
    for cve, errors in sorted(report['errors'].items()):
        for end, error in errors.items():
            print(f'{cve}: not evaluated at {end} ({error["error"]})')
    print(f'git history: {evidence.summary()}')
    print(
        f'{candidates} rule{"s" if candidates != 1 else ""} matched {changed} changed'
        f' file{"s" if changed != 1 else ""}: {counts[FIXED]} fixed, {counts[INTRODUCED]}'
        f' introduced, {counts[STILL_VULNERABLE]} still vulnerable'
    )


def exit_code(fail_on: str, statuses: list[str]) -> int:
    if fail_on == 'introduced' and INTRODUCED in statuses:
        return EXIT_FAILED_POLICY
    if fail_on == 'detected' and (INTRODUCED in statuses or STILL_VULNERABLE in statuses):
        return EXIT_FAILED_POLICY
    return 0
