"""`cvehound bisect`: the commit at which one rule's verdict changed.

Where a fix landed on a branch, or which commit re-opened a CVE the history
says is fixed. Only commits that touch the rule's files can move its verdict,
so the walk is over those, identical file contents collapse into one step,
and the steps are bisected -- log2 spatch runs over tens of candidates, not a
checkout per commit.
"""

import argparse
import logging
import os
import tempfile
from typing import Any

from cvehound import CVEhound
from cvehound.cli.common import (
    CVE_GROUPS,
    ReportFile,
    build_hound,
    common_parser,
    configure_logging,
    confine,
    disable_astcache,
    error_record,
    fail,
    load_settings,
    normalize_cve,
    quiet_loglevel,
    require_kernel,
    resolve_arch,
    resolve_metadata,
    resolve_spatch,
    split_range,
    tools_report,
)
from cvehound.gitevidence import UPSTREAM_CITE
from cvehound.gitrepo import GitRepo
from cvehound.gitrev import (
    collapse_steps,
    find_flip,
    materialize_present,
    materialize_tree,
    signed_walk,
)
from cvehound.oracle import BlobMaterializer, Sig, hound_at, sig_has_rule_files

DETECTED, CLEAN = 'detected', 'clean'


def build_parser(prog: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=prog,
        parents=[common_parser()],
        description="Find the commit at which a rule's verdict flips between two revisions",
        epilog='Walks only the commits that touch the files the rule reads, collapses'
        ' those that leave them unchanged, and bisects the rest. Nothing is checked out.',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument('--cve', '-c', required=True, metavar='CVE', help='the CVE to bisect')
    parser.add_argument(
        'range',
        metavar='A..B',
        help='the two revisions to bisect between, in the repository at --kernel',
    )
    return parser


def main(args: list[str], prog: str = 'cvehound bisect') -> int:
    parser = build_parser(prog)
    cmdargs = parser.parse_args(args)
    args_cfg = load_settings(parser, cmdargs)
    kernel = require_kernel(parser, args_cfg)
    metadata_path = resolve_metadata(args_cfg)

    if args_cfg['cve'] in CVE_GROUPS:
        fail('bisect takes exactly one --cve, not a group')
    cve = normalize_cve(args_cfg['cve'])
    rev_from, rev_to = split_range(args_cfg['range'])

    repo = GitRepo(kernel)
    spatch = resolve_spatch(args_cfg)
    loglevel = configure_logging(args_cfg['verbose'])
    disable_astcache(args_cfg)
    # The checks run in this process; their "Found:" would only repeat what
    # the search prints.
    logging.getLogger().setLevel(quiet_loglevel(loglevel))

    with tempfile.TemporaryDirectory(prefix='cvehound-bisect-', ignore_cleanup_errors=True) as root:
        materializer = BlobMaterializer(repo, root)
        sha_from, sha_to = repo.rev_parse(rev_from), repo.rev_parse(rev_to)
        base = materialize_tree(materializer, repo, rev_from, sha_from)
        args_cfg['arch'] = resolve_arch(args_cfg, {}, base.path)
        hound = build_hound(base.path, args_cfg, metadata_path, spatch)
        if cve not in hound.get_all_cves():
            fail('Unknown CVE:', cve)
        files = hound.get_rule_files(cve)

        commits = signed_walk(repo, materializer, sha_from, sha_to, files)
        steps = collapse_steps(commits)
        # Every step's tree, before the sandbox: the store is under the temp dir
        # the sandbox lets us write, but building trees is not what a scan does
        # post-lock, and hardlinks make it cheap to do up front.
        trees = materialize_present(materializer, (sig for sig, _ in steps))
        present_from, present_to = steps[0][0] in trees, steps[-1][0] in trees

        report: dict[str, Any] = {
            'args': {
                'cve': [cve],
                'kernel': args_cfg['kernel'],
                'range': args_cfg['range'],
                'metadata': metadata_path,
            },
            'range': {
                'from': {'rev': rev_from, 'commit': sha_from, 'files_present': present_from},
                'to': {'rev': rev_to, 'commit': sha_to, 'files_present': present_to},
            },
            'files': files,
            'candidates': len(commits) - 1,
            'steps': len(steps),
            'tools': tools_report(hound, metadata_path),
            'flip': None,
            'runs': 0,
            'errors': {},
        }
        print(
            f'{cve}: bisecting {len(commits) - 1} commits touching {", ".join(files)}'
            f' between {rev_from} and {rev_to} ({len(steps)} distinct contents)'
        )

        with ReportFile(args_cfg['report']) as out:
            confine(base.path, hound, metadata_path, args_cfg['sandbox'], repo=repo)
            verdicts = Verdicts(hound, cve, trees, report)
            try:
                # The ends first: with a single step find_flip() evaluates nothing,
                # and a failure there must land in the report like any other.
                first = verdicts.at(steps[0][0])
                last = verdicts.at(steps[-1][0])
                flip = find_flip(len(steps), lambda i: verdicts.at(steps[i][0]))
            except _Failed:
                report['runs'] = verdicts.runs
                out.write(report)
                return 1
            report['runs'] = verdicts.runs
            print(
                f'{cve}: {state(first, present_from)} at {rev_from},'
                f' {state(last, present_to)} at {rev_to}'
            )
            if flip is None:
                print(f'{cve}: no change between {rev_from} and {rev_to}')
            else:
                was_present = steps[flip - 1][0] in trees
                report['flip'] = describe_flip(repo, steps[flip], first, was_present)
                print(f'{cve}: {report["flip"]["text"]}')
            print(f'spatch runs: {verdicts.runs}')
            out.write(report)
    return 0


def state(verdict: bool, files_present: bool) -> str:
    """A verdict for a human, honest about the vacuous case: a False at a
    content with none of the rule's files is not a clean bill."""
    if not files_present:
        return 'rule files absent'
    return DETECTED if verdict else CLEAN


class _Failed(Exception):
    """A step could not be evaluated: the search has no verdict to go on."""


class Verdicts:
    """check_cve() per distinct content, memoized, with the runs counted."""

    def __init__(self, hound: CVEhound, cve: str, trees: dict[Sig, str], report: dict) -> None:
        self.hound = hound
        self.cve = cve
        self.trees = trees
        self.report = report
        self.memo: dict[Sig, bool] = {}
        self.runs = 0

    def at(self, sig: Sig) -> bool:
        if sig in self.memo:
            return self.memo[sig]
        # No rule file at this content: the rule cannot fire, and says nothing.
        if sig not in self.trees:
            self.memo[sig] = False
            return False
        self.runs += 1
        try:
            verdict = bool(
                hound_at(self.hound, self.trees[sig]).check_cve(self.cve, jobs=os.cpu_count() or 1)
            )
        except Exception as err:
            self.report['errors'][self.trees[sig]] = error_record(self.cve, err)
            logging.error('%s: cannot bisect past a step that fails to evaluate', self.cve)
            raise _Failed from err
        self.memo[sig] = verdict
        return verdict


def describe_flip(
    repo: GitRepo, step: tuple[Sig, list[str]], first: bool, was_present: bool
) -> dict[str, Any]:
    """The step the verdict changed at. `was_present`: whether the rule's files
    existed at the step before it -- a flip out of nothing is the files
    appearing, not a bug being introduced."""
    sig, commits = step
    commit = commits[0]
    direction = f'{DETECTED} -> {CLEAN}' if first else f'{CLEAN} -> {DETECTED}'
    blind = not sig_has_rule_files(sig)
    subject = repo.commit_subject(commit)
    cites = sorted(
        {
            c
            for _, message in repo.log_messages(f'{commit}~..{commit}')
            for c in UPSTREAM_CITE.findall(message)
        }
    )
    text = f'verdict flips at {subject} ({direction})'
    if blind:
        text += ' -- rule blind here: none of its files exist at this commit'
    elif not was_present:
        text += " -- the rule's files first appear here; the range starts before them"
    if cites:
        text += f'; cites upstream commit {", ".join(c[:12] for c in cites)}'
    if len(commits) > 1:
        text += f'; {len(commits) - 1} later commit(s) leave the files unchanged'
    return {
        'commit': commit,
        'subject': subject,
        'direction': direction,
        'blind': blind,
        'cites': cites,
        'text': text,
    }
