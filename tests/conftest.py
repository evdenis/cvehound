#!/usr/bin/env python3

import os
import shutil
import tempfile
import textwrap
import time
from subprocess import PIPE, Popen, run
from urllib.request import urlretrieve

import psutil
import pytest
from filelock import FileLock
from git import Repo
from git.exc import GitCommandError
from kerneltree import BlobMaterializer, cached_check, hound_at
from resultcache import ResultCache

from cvehound import CVEhound, get_rule_cves
from cvehound.content import DEFAULT_BASE, METADATA_NAME
from cvehound.kbuild import KbuildParser
from cvehound.scripts.update_metadata import get_cache_dir
from cvehound.util import resolve_metadata_path

INITIAL_COMMIT = 'v2.6.12-rc2'
INITIAL_COMMIT_HASH = '1da177e4c3f41524e886b7f1b8a0c1fc7321cac2'
INITIAL_COMMITS = {INITIAL_COMMIT, INITIAL_COMMIT_HASH}
FETCH_INTERVAL = 6 * 3600

missing_backports = [
    ('CVE-2022-0998', 'stable/linux-5.15.y'),
    ('CVE-2023-4133', 'stable/linux-5.10.y'),
    ('CVE-2023-4133', 'stable/linux-5.15.y'),
    ('CVE-2023-4133', 'stable/linux-6.1.y'),
    ('CVE-2023-23005', 'stable/linux-6.1.y'),
    ('CVE-2024-26595', 'stable/linux-5.10.y'),
    ('CVE-2024-26595', 'stable/linux-5.15.y'),
    ('CVE-2024-26799', 'stable/linux-6.1.y'),
]


def pytest_addoption(parser):
    parser.addoption(
        '--cve',
        action='append',
        default=[],
        help='list of CVEs',
    )
    parser.addoption(
        '--branch',
        action='append',
        default=[],
        help='list of linux-stable branches to run tests on',
    )
    parser.addoption('--runslow', action='store_true', default=False, help='run slow tests')
    parser.addoption(
        '--runmetadata',
        action='store_true',
        default=False,
        help='run tests that check kernel_cves.json against the kernel git tree',
    )
    parser.addoption(
        '--dir',
        action='store',
        default=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'linux'),
        help='linux kernel sources dir',
    )
    parser.addoption(
        '--between-mode',
        action='store',
        default='tags',
        choices=('tags', 'commits'),
        help='test_05 verification points: tags incl. -rc (default) or every commit',
    )
    parser.addoption(
        '--no-result-cache',
        action='store_true',
        default=False,
        help='run every spatch check even when a cached verdict exists',
    )


linux_repo = None
_cvehound = None
_kernel_checkout = None
_materializer = None
_shared_root = None
_result_cache = None
_fresh_worktrees = set()
branches = []
cves = []


def _is_worker(config):
    return hasattr(config, 'workerinput')


def use_worktrees():
    env = os.environ.get('CVEHOUND_TEST_WORKTREES')
    if env is not None:
        return env != '0'
    return os.environ.get('GITHUB_ACTIONS') != 'true'


class KernelCheckout:
    def __init__(self, repo):
        self.repo = repo
        self.current = None
        self.commits = {}

    def add_commits(self, commits):
        self.commits.update(commits)

    def checkout(self, commit):
        identity = self.commits.get(commit, commit)
        if self.current == identity:
            return

        self.current = None
        self.repo.git.checkout('--force', commit)
        self.current = identity


def _tune_repo(repo):
    """Apply idempotent git performance settings to the kernel repo.

    checkout.workers=0 parallelizes working-tree updates across all cores and
    feature.manyFiles enables index v4 plus the untracked cache. The one-time
    Bloom-filter commit-graph (--changed-paths) accelerates the path-limited
    `git log` queries in test_05 and the topo-order ranking at collection time;
    fetch.writeCommitGraph keeps it current (new layers inherit the filters).
    """
    for key, value in (
        ('checkout.workers', '0'),
        ('feature.manyFiles', 'true'),
        ('fetch.writeCommitGraph', 'true'),
    ):
        repo.git.config(key, value)
    try:
        done = repo.git.config('--get', 'cvehound.commitgraphbloom')
    except GitCommandError:
        done = ''
    if done != '1':
        repo.git.commit_graph('write', '--reachable', '--changed-paths', '--split=replace')
        repo.git.config('cvehound.commitgraphbloom', '1')


def _reset_worktree(repo):
    # A clean tree needs no reset/clean/checkout: tests force-checkout the
    # commits they need and never rely on where HEAD currently points.
    # --ignored: build products (.config, *.o, include/generated/) are
    # invisible to plain --porcelain but must still trigger the `-x` clean,
    # or all_files scans grep stale artifacts forever.
    if not repo.git.status('--porcelain', '--ignored'):
        return
    repo.head.reset(index=True, working_tree=True)
    repo.git.clean('-f', '-x', '-d')
    repo.git.checkout('origin/master')


def _spatch_version_line():
    out = run(['spatch', '--version'], capture_output=True, check=True, text=True)
    return out.stdout.splitlines()[0]


def _fetch_remotes(repo):
    if os.environ.get('CVEHOUND_TEST_OFFLINE'):
        return
    fetch_head = os.path.join(repo.git_dir, 'FETCH_HEAD')
    if os.path.isfile(fetch_head) and time.time() - os.path.getmtime(fetch_head) < FETCH_INTERVAL:
        return
    try:
        repo.remotes.origin.fetch()
        repo.remotes.stable.fetch()
        repo.remotes.next.fetch()
    except Exception:
        pass


def _ensure_metadata():
    """Point CVEHOUND_METADATA at a usable blob when the checkout has none.

    The metadata blob is not git-tracked (CI publishes it as a content-latest
    release asset); fetch it once into the cvehound cache dir.
    """
    if os.environ.get('CVEHOUND_METADATA'):
        return
    # CVEHOUND_CONTENT=none is already set, so this resolves to the packaged
    # blob or None -- exactly "does the checkout have a blob".
    if resolve_metadata_path(None):
        return
    blob_name = os.path.basename(METADATA_NAME)
    cache = get_cache_dir()
    dest = os.path.join(cache, blob_name)
    if not os.path.isfile(dest):
        os.makedirs(cache, exist_ok=True)
        # Download to a temp name first: an interrupted download must not
        # leave a truncated blob that poisons every later run.
        tmp = dest + '.download'
        urlretrieve(DEFAULT_BASE + '/' + blob_name, tmp)
        os.replace(tmp, dest)
    os.environ['CVEHOUND_METADATA'] = dest


def pytest_configure(config):
    global linux_repo
    global _cvehound
    global _kernel_checkout
    global _materializer
    global _shared_root
    global _result_cache
    global branches
    global cves

    # The suite must parametrize over the repository's own rules and metadata,
    # never over a developer's content overlay.
    os.environ['CVEHOUND_CONTENT'] = 'none'
    _ensure_metadata()

    config.addinivalue_line('markers', 'slow: mark test as slow to run')
    config.addinivalue_line('markers', 'fast: fast tests that are duplicated by slow ones')
    config.addinivalue_line('markers', 'notbackported: mark test as failed')
    config.addinivalue_line('markers', 'ownfixes: mark test as failed')
    config.addinivalue_line('markers', 'nometadata: mark test as failed')
    config.addinivalue_line(
        'markers', 'kernel_history(*route): declare the full-tree checkout route for a test'
    )

    try:
        p = psutil.Process()
        p.nice(-100)
        p.ionice(psutil.IOPRIO_CLASS_RT, value=0)
    except Exception:
        pass

    cves = config.getoption('cve')
    if not cves:
        (cves, _, _) = get_rule_cves()
        cves = cves.keys()

    if _is_worker(config):
        # Repo prep already happened on the xdist controller; reuse its state.
        linux_repo = Repo(config.getoption('dir'))
        _shared_root = config.workerinput['cvehound_root']
    else:
        linux = config.getoption('dir')
        repo = None
        if os.path.isdir(os.path.join(linux, '.git')):
            repo = Repo(linux)
            _tune_repo(repo)
            _reset_worktree(repo)
            _fetch_remotes(repo)
        else:
            cwd = os.getcwd()
            os.makedirs(linux, exist_ok=True)
            os.chdir(linux)
            repo = Repo.clone_from(
                'git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git', '.'
            )
            repo.create_remote(
                'stable', 'git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git'
            )
            repo.create_remote(
                'next', 'git://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git'
            )
            repo.remotes.stable.fetch()
            repo.remotes.next.fetch()
            os.chdir(cwd)
            _tune_repo(repo)

        linux_repo = repo
        _shared_root = tempfile.mkdtemp(prefix='cvehound-tests-')

    _cvehound = CVEhound(linux_repo.working_tree_dir)
    _kernel_checkout = KernelCheckout(linux_repo)
    _materializer = BlobMaterializer(linux_repo, os.path.join(_shared_root, 'store'))
    if not config.getoption('--no-result-cache'):
        _result_cache = ResultCache(
            os.path.join(os.path.dirname(os.path.realpath(__file__)), '.result_cache'),
            _spatch_version_line(),
            worker=os.environ.get('PYTEST_XDIST_WORKER', 'main'),
        )

    branches = config.getoption('branch')
    if not branches:
        branches = [
            'origin/master',
            'next/master',
            'stable/linux-6.18.y',
            'stable/linux-6.12.y',
            'stable/linux-6.6.y',
            'stable/linux-6.1.y',
            'stable/linux-5.15.y',
            'stable/linux-5.10.y',
        ]


def pytest_unconfigure(config):
    if _is_worker(config):
        return
    if _result_cache:
        if _result_cache.hits or _result_cache.misses:
            print(f'\nresult cache: {_result_cache.hits} hits, {_result_cache.misses} misses')
        _result_cache.compact()
    if _shared_root:
        shutil.rmtree(_shared_root, ignore_errors=True)


@pytest.hookimpl(optionalhook=True)
def pytest_configure_node(node):
    # xdist controller hook: hand each worker the shared blob store so the
    # per-session trees are materialized once, not per worker.
    node.workerinput['cvehound_root'] = _shared_root


def pytest_sessionfinish(session, exitstatus):
    if _result_cache and _is_worker(session.config):
        session.config.workeroutput['cvehound_cache'] = [
            _result_cache.hits,
            _result_cache.misses,
        ]


@pytest.hookimpl(optionalhook=True)
def pytest_testnodedown(node, error):
    stats = getattr(node, 'workeroutput', {}).get('cvehound_cache')
    if stats and _result_cache:
        _result_cache.hits += stats[0]
        _result_cache.misses += stats[1]


def write_tree(root, files):
    """Materialize a synthetic kernel tree: {relative path: file content}."""
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(content))


def build_map(root, arch='x86'):
    """Build the Kbuild config map of a tree, keyed by relative path."""
    kernel = os.path.abspath(str(root))
    config = KbuildParser(None, arch, kernel).parse_tree()
    return {os.path.relpath(k, kernel): v for k, v in config.items()}


@pytest.fixture
def repo():
    return linux_repo


@pytest.fixture
def hound():
    return _cvehound


@pytest.fixture
def kernel_checkout():
    return _kernel_checkout


@pytest.fixture
def materializer():
    return _materializer


@pytest.fixture
def between_mode(request):
    return request.config.getoption('--between-mode')


@pytest.fixture
def result_cache():
    return _result_cache


@pytest.fixture
def sig_check(materializer, hound, result_cache):
    """Factory: cached bool verdict for a rule on a blob signature."""

    def check(sig, cve):
        return cached_check(hound, materializer, result_cache, sig, cve)

    return check


@pytest.fixture
def tree_check(materializer, hound, sig_check):
    """Factory: cached bool verdict for a rule at a commit, without checkouts."""

    def check(commit, cve):
        return sig_check(materializer.sig(commit, hound.get_rule_files(cve)), cve)

    return check


def _branch_worktree(branch_name):
    """A persistent detached worktree at the branch head.

    Worktrees survive the session (a full kernel checkout costs ~5-15s per
    branch, and /tmp clears on reboot anyway); each session refreshes a reused
    worktree to the current branch head once. The lock covers creation and
    refresh against concurrent pytest sessions.
    """
    root = os.path.join(tempfile.gettempdir(), f'cvehound-worktrees-{os.getuid()}')
    os.makedirs(root, exist_ok=True)
    path = os.path.join(root, branch_name.replace('/', '-'))
    if path in _fresh_worktrees:
        return path
    with FileLock(path + '.lock'):
        if not os.path.isdir(path):
            try:
                linux_repo.git.worktree('add', '--detach', '--force', path, branch_name)
            except GitCommandError:
                # A stale admin entry (e.g. after a /tmp wipe) blocks the add:
                # prune and retry. Pruning only on this failure path keeps it
                # away from sibling workers' in-flight worktree adds.
                linux_repo.git.worktree('prune')
                linux_repo.git.worktree('add', '--detach', '--force', path, branch_name)
        else:
            run(
                ['git', '-C', path, 'checkout', '--force', '--detach', branch_name],
                capture_output=True,
                check=True,
            )
    _fresh_worktrees.add(path)
    return path


@pytest.fixture
def branch_hound(hound, kernel_checkout):
    """Factory: a CVEhound over a full tree at a branch head.

    A detached worktree per branch when enabled (the default outside CI),
    falling back to checkouts in the shared tree otherwise.
    """

    def make(branch_name):
        if not use_worktrees():
            kernel_checkout.checkout(branch_name)
            return _cvehound
        return hound_at(hound, _branch_worktree(branch_name))

    return make


@pytest.fixture
def all_files_jobs():
    """spatch -j for whole-tree scans: divide cores by concurrent scans.

    Worktree mode runs one scan per branch group; shared-tree mode serializes
    every scan into a single group, so the lone scan may use all cores.
    """
    workers = int(os.environ.get('PYTEST_XDIST_WORKER_COUNT', '1'))
    concurrent = min(workers, len(branches)) if use_worktrees() else 1
    return max(1, (os.cpu_count() or 1) // concurrent)


def pytest_generate_tests(metafunc):
    if 'branch' in metafunc.fixturenames:
        params = branches
        if metafunc.definition.get_closest_marker('kernel_history'):
            # Full-tree tests declare kernel_history('branch'): serialize each
            # branch group (worktree mode) or every scan (shared tree) under
            # --dist loadgroup. Marking at parametrize time guarantees xdist's
            # nodeid rewrite sees the marker regardless of hook ordering.
            params = [
                pytest.param(
                    branch,
                    marks=pytest.mark.xdist_group(
                        'branch:' + branch if use_worktrees() else 'shared-tree'
                    ),
                )
                for branch in branches
            ]
        metafunc.parametrize('branch', params)

    if 'cve' in metafunc.fixturenames:
        metafunc.parametrize('cve', cves)


def _get_kernel_route(item):
    marker = item.get_closest_marker('kernel_history')
    if marker is None:
        return ()
    if marker.args != ('branch',):
        # The richer fix/fixes/initial vocabulary died with the checkout-based
        # tests; only the branch route (test_06's shared-tree fallback) is left.
        raise pytest.UsageError(f'unknown kernel_history route {marker.args!r} on {item.nodeid}')
    return (item.callspec.params['branch'],)


def _resolve_kernel_commits(refs):
    refs = list(dict.fromkeys(refs))
    result = run(
        ['git', 'cat-file', '--batch-check=%(objectname) %(objecttype)'],
        cwd=linux_repo.working_tree_dir,
        input=''.join(f'{ref}^{{commit}}\n' for ref in refs),
        capture_output=True,
        check=True,
        text=True,
    )

    resolved = {}
    missing = []
    for ref, line in zip(refs, result.stdout.splitlines(), strict=True):
        fields = line.split()
        if len(fields) != 2 or fields[1] != 'commit':
            missing.append(ref)
            continue
        resolved[ref] = fields[0]

    if missing:
        raise pytest.UsageError('kernel commits not found: ' + ', '.join(missing))
    return resolved


def _rank_kernel_commits(commits):
    commits = set(commits)
    process = Popen(
        ['git', 'rev-list', '--topo-order', *sorted(commits)],
        cwd=linux_repo.working_tree_dir,
        stdout=PIPE,
        stderr=PIPE,
        text=True,
    )
    ranks = {}
    assert process.stdout is not None
    for rank, line in enumerate(process.stdout):
        commit = line.rstrip()
        if commit not in commits:
            continue
        ranks[commit] = rank
        if len(ranks) == len(commits):
            process.terminate()
            break

    process.stdout.close()
    assert process.stderr is not None
    stderr = process.stderr.read()
    returncode = process.wait()
    if len(ranks) != len(commits):
        missing = sorted(commits - ranks.keys())
        message = 'kernel commits not reachable: ' + ', '.join(missing)
        if returncode:
            message += '\n' + stderr.strip()
        raise pytest.UsageError(message)
    return ranks


def _apply_kernel_order(items, records, ranks):
    slots = [record[0] for record in records]
    ordered = sorted(
        records,
        key=lambda record: (
            ranks[record[2][0]],
            ranks[record[2][-1]],
            record[0],
        ),
    )
    for slot, record in zip(slots, ordered, strict=True):
        items[slot] = record[1]


def _reorder_kernel_tests(items):
    records = []
    refs = []
    for index, item in enumerate(items):
        if item.get_closest_marker('skip') is not None:
            continue
        route = _get_kernel_route(item)
        if not route:
            continue
        records.append((index, item, route))
        refs.extend(route)

    if len(records) < 2:
        return

    resolved = _resolve_kernel_commits(refs)
    _kernel_checkout.add_commits(resolved)
    records = [
        (index, item, tuple(resolved[ref] for ref in route)) for index, item, route in records
    ]
    ranks = _rank_kernel_commits(resolved.values())
    _apply_kernel_order(items, records, ranks)


def pytest_collection_modifyitems(config, items):
    runslow = config.getoption('--runslow')
    runmetadata = config.getoption('--runmetadata')
    skip_slow = pytest.mark.skip(reason='need --runslow option to run')
    skip_fast = pytest.mark.skip(reason='slow tests cover these testcases')
    skip_metadata = pytest.mark.skip(reason='need --runmetadata option to run')
    fail_notbackported = pytest.mark.xfail(reason='CVE not backported yet')
    for item in items:
        if not runslow and 'slow' in item.keywords:
            item.add_marker(skip_slow)
        if runslow and 'fast' in item.keywords:
            item.add_marker(skip_fast)
        if not runmetadata and 'metadata' in item.keywords:
            item.add_marker(skip_metadata)
        if 'notbackported' in item.keywords:
            params = item.callspec.params
            mark = None
            for m in item.own_markers:
                if m.name == 'notbackported':
                    mark = m
                    break
            if (params['cve'], params['branch']) in mark.args[1]:
                item.add_marker(fail_notbackported)
        for name in ('ownfixes', 'nometadata'):
            if name not in item.keywords:
                continue
            params = item.callspec.params
            mark = None
            for m in item.own_markers:
                if m.name == name:
                    mark = m
                    break
            for rec in mark.args[1]:
                # A record is either a (cve, reason) pair or a bare CVE id, in
                # which case the reason is shared by the whole list
                if isinstance(rec, str):
                    rec = (rec, mark.kwargs.get('reason', name))
                if params['cve'] == rec[0]:
                    item.add_marker(pytest.mark.xfail(reason=rec[1]))

    _reorder_kernel_tests(items)
