"""`cvehound scan`: check one kernel tree -- the working directory, or a revision.

The historical `cvehound --kernel DIR` invocation lands here unchanged. With
--rev the tree scanned is materialized from the object database instead
(cvehound.gitrev), so the working directory can be dirty, mid-rebase or on
another branch entirely; several revisions scan in one run.
"""

import argparse
import contextlib
import logging
import os
import sys
import tempfile
from dataclasses import dataclass, field
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
    ensure_rules,
    fail,
    fold_outcomes,
    load_settings,
    new_hound,
    require_kernel,
    resolve_arch,
    resolve_metadata,
    resolve_spatch,
    run_pool,
    select_cves,
    tools_report,
)
from cvehound.exception import GitError
from cvehound.gitevidence import finding_fixes, fix_evidence, prune_unintroduced
from cvehound.gitrepo import GitRepo
from cvehound.gitrev import RevTree, head_info, materialize_tree, tree_paths
from cvehound.oracle import BlobMaterializer, hound_at
from cvehound.util import (
    astcache_clear,
    astcache_dir,
    find_spatch,
    get_config_data,
    get_kernel_version,
    get_rule_cves,
)


def build_parser(prog: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=prog,
        parents=[common_parser()],
        description='A tool to check linux kernel sources dump for known CVEs',
        epilog="subcommands: 'cvehound scan' (the default) checks a tree, 'cvehound diff'"
        " tells what a commit range or patch fixes or introduces, 'cvehound bisect'"
        " finds the commit where a rule's verdict flips, 'cvehound update' refreshes"
        " the detection rules and CVE metadata (see 'cvehound <subcommand> --help')",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    add_cve_options(parser, greedy=True)
    parser.add_argument('--list', action='store_true', help='list all known CVEs and exit')
    parser.add_argument(
        '--prune-unintroduced',
        action='store_true',
        help='skip rules whose introducing commit is provably not in the history of the'
        ' scanned revision. Off by default: a rebased or squashed vendor tree has no'
        ' upstream commit in its ancestry, and there this would skip everything',
    )
    parser.add_argument(
        '--rev',
        nargs='+',
        metavar='REV',
        help='scan these revisions of the git repository at --kernel (a tag, branch or'
        ' commit) instead of its working tree; the files each rule reads are taken'
        ' straight from the object database, so nothing is checked out. Several'
        ' revisions scan in one run and report side by side',
    )
    parser.add_argument(
        '--files',
        nargs='+',
        default=[],
        metavar='PATH',
        help='check only files (e.g. kernel drivers/block/floppy.c arch/x86)',
    )
    parser.add_argument(
        '--ignore-files',
        nargs='+',
        default=[],
        metavar='PATH',
        help='exclude kernel files from check (e.g. kernel/bpf)',
    )
    parser.add_argument(
        '--kernel-config', nargs='?', const='-', metavar='.config', help='check kernel config'
    )
    parser.add_argument(
        '--arch',
        metavar='ARCH',
        help='kernel architecture (default: from the .config banner, else x86)',
    )
    parser.add_argument(
        '--check-strict', action='store_true', help='output only CVEs enabled in .config'
    )
    parser.add_argument(
        '--all-files', action='store_true', help="don't use files hint from cocci rules"
    )
    parser.add_argument(
        '--cache',
        nargs='?',
        const='auto',
        default=os.environ.get('CVEHOUND_SPATCH_ASTCACHE'),
        metavar='DIR',
        help='reuse parsed C between rules that target the same file, in DIR'
        ' (default: off; bare --cache uses a directory under the cvehound cache)'
        ' -- worth it when rescanning a tree or running thousands of rules,'
        ' and it costs ~310MB per tree scanned',
    )
    parser.add_argument(
        '--cache-clear',
        action='store_true',
        help='empty the AST cache and exit',
    )
    return parser


def resolve_kernel_config(args_cfg: dict[str, Any], kernel: str) -> None:
    """Turn a bare --kernel-config into <kernel>/.config, or explain why not."""
    if args_cfg['kernel_config'] == '-':
        config = os.path.normpath(os.path.join(kernel, '.config'))
        if os.path.isfile(config):
            args_cfg['kernel_config'] = config
        elif args_cfg['check_strict']:
            fail('--check-strict needs a kernel .config, but', config, 'not found')
        else:
            print(
                'No',
                config,
                'found: inferring CONFIG_ options without a .config check',
                file=sys.stderr,
            )
    elif args_cfg['kernel_config'] and not os.path.isfile(args_cfg['kernel_config']):
        fail("Can't find config file", args_cfg['kernel_config'])

    if args_cfg['kernel_config'] and args_cfg['verbose'] == 0:
        args_cfg['verbose'] = 1

    if args_cfg['check_strict'] and not args_cfg['kernel_config']:
        fail('Please, use --check-strict with --kernel-config')


def args_report(
    args_cfg: dict[str, Any], cves: list[str], metadata_path: str | None
) -> dict[str, Any]:
    return {
        'cve': cves,
        'kernel': args_cfg['kernel'],
        'rev': args_cfg.get('rev'),
        'config': args_cfg['kernel_config'],
        'only_files': args_cfg['files'],
        'ignore_files': args_cfg['ignore_files'],
        'all_files': args_cfg['all_files'],
        'check_strict': args_cfg['check_strict'],
        'arch': args_cfg['arch'],
        'exclude': sorted(args_cfg['exclude']),
        'exploit': args_cfg['exploit'],
        'metadata': metadata_path,
    }


@dataclass
class Target:
    """One tree this run scans: a revision, or the checkout itself.

    Everything per tree lives here -- the scanner, the tasks, the report block
    the outcomes fold into -- so the checkout and N revisions are one loop.
    """

    label: str  # what the user called it; 'HEAD' for the checkout
    sha: str  # '' when the checkout is not a repository
    path: str
    hound: CVEhound
    block: dict[str, Any]
    tasks: list[Task] = field(default_factory=list)


def main(args: list[str], prog: str = 'cvehound scan') -> int:
    parser = build_parser(prog)
    cmdargs = parser.parse_args(args)

    if cmdargs.list:
        (all_rules, _, _) = get_rule_cves()
        ensure_rules(all_rules)
        print('\n'.join(sorted(all_rules)))
        return 0

    args_cfg = load_settings(parser, cmdargs)

    if args_cfg['cache_clear']:
        # Before the --kernel check: emptying the cache is maintenance, and
        # asking for a kernel tree to do it would be nonsense.
        setting = args_cfg['cache'] or 'auto'
        astcache = astcache_dir(setting, find_spatch(args_cfg['spatch']))
        if astcache is None:
            fail('AST cache is disabled, nothing to clear')
        freed = astcache_clear(astcache)
        print(f'Cleared {freed / 1e6:.1f} MB from {astcache}')
        return 0

    kernel = require_kernel(parser, args_cfg)
    metadata_path = resolve_metadata(args_cfg)
    resolve_kernel_config(args_cfg, kernel)
    spatch = resolve_spatch(args_cfg)
    loglevel = configure_logging(args_cfg['verbose'])

    # Each label once: the report keys its per-revision blocks by label.
    revs: list[str] = list(dict.fromkeys(args_cfg.get('rev') or []))
    repo: GitRepo | None = None
    if revs:
        if args_cfg['all_files']:
            fail(
                '--all-files needs a full tree, which --rev does not build;'
                ' check the revision out (git worktree add) and scan that'
            )
        repo = GitRepo(kernel)
        disable_astcache(args_cfg)
    elif not os.path.isfile(os.path.join(kernel, 'Makefile')):
        fail(kernel, "isn't a kernel directory")
    elif os.path.exists(os.path.join(kernel, '.git')):
        # A checkout: git can say where each finding's fix stands. Best effort;
        # a tree git cannot open scans exactly as a plain directory does.
        try:
            repo = GitRepo(kernel)
        except GitError as err:
            logging.info('%s', err)
    if args_cfg['prune_unintroduced'] and repo is None:
        fail('--prune-unintroduced needs a git repository at --kernel')

    config_info: dict[str, str] = {}
    if args_cfg['kernel_config'] and args_cfg['kernel_config'] != '-':
        config_info = get_config_data(args_cfg['kernel_config'])

    with_kbuild = bool(args_cfg['kernel_config'])
    with contextlib.ExitStack() as stack:
        root = ''
        if revs:
            root = stack.enter_context(
                tempfile.TemporaryDirectory(prefix='cvehound-rev-', ignore_cleanup_errors=True)
            )
        trees: list[RevTree] = []
        git_info: dict[str, Any] = {}
        if repo is not None and revs:
            materializer = BlobMaterializer(repo, root)
            for rev in revs:
                sha = repo.rev_parse(rev)
                paths = tree_paths(repo, sha, with_kbuild)
                trees.append(materialize_tree(materializer, repo, rev, sha, paths))
            scan_dir = trees[0].path
        else:
            scan_dir = kernel
            if repo is not None:
                git_info = head_info(repo)

        args_cfg['arch'] = resolve_arch(args_cfg, config_info, scan_dir)
        hound = build_hound(scan_dir, args_cfg, metadata_path, spatch)
        cves_sorted = select_cves(hound, args_cfg)

        report: dict[str, Any] = {
            'args': args_report(args_cfg, cves_sorted, metadata_path),
            'config': config_info,
            'tools': tools_report(hound, metadata_path),
        }
        if len(trees) > 1:
            # Side by side: one block per revision, and none of the flat keys, so
            # a consumer cannot mistake one revision's findings for the run's.
            report['revs'] = {}
            targets = []
            for i, tree in enumerate(trees):
                block = report['revs'][tree.rev] = {
                    'kernel': get_kernel_version(tree.path) | tree.report()
                }
                # One scanner per tree, all built before the sandbox: the Kbuild
                # map is a function of the tree's own Makefiles, and building it
                # opens the .config, which the policy never grants.
                tree_hound = hound if i == 0 else hound_at(hound, tree.path)
                if with_kbuild and i > 0:
                    tree_hound = new_hound(tree.path, args_cfg, metadata_path, spatch)
                targets.append(Target(tree.rev, tree.sha, tree.path, tree_hound, block))
        else:
            # A single --rev reads like a checkout of it: the flat shape, plus
            # which revision it was.
            report['kernel'] = get_kernel_version(scan_dir) | git_info
            if trees:
                report['kernel'] |= trees[0].report()
            label, sha = (
                (trees[0].rev, trees[0].sha) if trees else ('HEAD', git_info.get('commit', ''))
            )
            targets = [Target(label, sha, scan_dir, hound, report)]

        for target in targets:
            target.block['results'] = {}
            target.block['errors'] = {}
            cves = cves_sorted
            if args_cfg['prune_unintroduced'] and repo is not None and target.sha:
                cves, target.block['skipped'] = prune_unintroduced(
                    repo, hound, cves_sorted, target.sha
                )
                logging.info(
                    'Skipping %d rules whose introducing commit is not in history',
                    len(target.block['skipped']),
                )
            tree = target.path if trees else None
            target.tasks = [(cve, args_cfg['all_files'], tree) for cve in cves]

        with ReportFile(args_cfg['report']) as out:
            confine(scan_dir, hound, metadata_path, args_cfg['sandbox'], repo=repo)
            run_targets(targets, loglevel)
            if repo is not None:
                # After every pool: the git walk this needs would otherwise
                # sit between two pools with every CPU idle.
                for target in targets:
                    if target.sha:
                        annotate_findings(repo, hound, target)
            out.write(report)
    return 0


def run_targets(targets: list[Target], loglevel: int) -> None:
    """Every target's tasks through the pool, one pool per target.

    The workers print the findings, so a shared pool would leave "Found:" lines
    with no revision to belong to; the "Checking" line before each pool is what
    attributes them. The pool's start-up is ~60ms, and only the last rule of
    one revision idles the cores before the next begins.
    """
    for target in targets:
        if len(targets) > 1:
            logging.warning('Checking %s (%s)', target.label, target.sha[:12])
        fold_outcomes(target.block, run_pool(target.hound, loglevel, target.tasks))


def annotate_findings(repo: GitRepo, hound: CVEhound, target: Target) -> None:
    """Attach what history says about each finding's fix, and say it.

    After the scan and only for what fired, so a clean tree costs nothing; the
    walk it may need is one `git log` bounded to the fixes involved. git failing
    here is reported, never turned into a verdict.
    """
    results = target.block['results']
    findings = finding_fixes(hound, results)
    if not findings:
        return
    try:
        evidence = fix_evidence(repo, target.sha, findings)
    except GitError as err:
        logging.warning('git evidence unavailable: %s', err)
        return
    logging.warning('git evidence (%s):', target.label)
    for cve in sorted(results):
        found = evidence.get(cve)
        if found is None:
            results[cve]['git'] = None
            logging.warning('  %s: no fix commit on record', cve)
            continue
        results[cve]['git'] = found.report()
        logging.warning('  %s: %s', cve, found.describe())
