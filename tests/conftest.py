#!/usr/bin/env python3

import os
import tempfile
import textwrap
from subprocess import PIPE, CalledProcessError, Popen, run
from urllib.request import urlretrieve

import psutil
import pytest
from git import Repo
from git.exc import GitCommandError

from cvehound import CVEhound, get_rule_cves
from cvehound.content import DEFAULT_BASE, METADATA_NAME
from cvehound.kbuild import KbuildParser
from cvehound.scripts.update_metadata import get_cache_dir
from cvehound.util import resolve_metadata_path

INITIAL_COMMIT = 'v2.6.12-rc2'
INITIAL_COMMIT_HASH = '1da177e4c3f41524e886b7f1b8a0c1fc7321cac2'
INITIAL_COMMITS = {INITIAL_COMMIT, INITIAL_COMMIT_HASH}
TMPFS_CVE_THRESHOLD = 5
TMPFS_SIZE_GB = 3

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


def mount_tmpfs(target, req_mem_gb):
    if os.path.ismount(target):
        return True
    lines = []
    with open('/proc/meminfo') as fh:
        lines = fh.readlines()
    meminfo = {i.split()[0].rstrip(':'): int(i.split()[1]) for i in lines}
    av_mem_gb = int(meminfo['MemAvailable'] / 1024**2)
    if av_mem_gb >= req_mem_gb + 1:
        ret = run(
            [
                'sudo',
                '--non-interactive',
                'mount',
                '-t',
                'tmpfs',
                '-o',
                'rw,noatime,nosuid,nodev,noexec,size=' + str(req_mem_gb) + 'G',
                'tmpfs',
                target,
            ]
        )
        return ret.returncode == 0
    else:
        return False


def umount(target):
    if os.path.ismount(target):
        run(['sudo', '--non-interactive', 'umount', target])


def should_use_tmpfs(selected_cves):
    return os.environ.get('GITHUB_ACTIONS') != 'true' and len(selected_cves) >= TMPFS_CVE_THRESHOLD


def clone_shared_repo(source, target):
    run(
        [
            'git',
            'clone',
            '--shared',
            '--no-checkout',
            '--quiet',
            '--',
            source.working_tree_dir,
            target,
        ],
        capture_output=True,
        check=True,
        text=True,
    )

    refs = source.git.for_each_ref('--format=update %(refname) %(objectname)')
    if refs:
        run(
            ['git', 'update-ref', '--stdin'],
            cwd=target,
            input=refs + '\n',
            capture_output=True,
            check=True,
            text=True,
        )

    repo = Repo(target)
    repo.git.checkout('--force', 'origin/master')
    return repo


def create_tmpfs_repo(repo):
    target = tempfile.mkdtemp()
    if not mount_tmpfs(target, TMPFS_SIZE_GB):
        os.rmdir(target)
        return repo, None

    try:
        return clone_shared_repo(repo, target), target
    except (CalledProcessError, GitCommandError, OSError):
        umount(target)
        os.rmdir(target)
        return repo, None


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


linux_mount = None
linux_repo = None
_cvehound = None
_kernel_checkout = None
branches = []
cves = []


class KernelCheckout:
    def __init__(self, repo):
        self.repo = repo
        self.current = None
        self.commits = {}

    def add_commits(self, commits):
        self.commits.update(commits)

    def checkout(self, commit, paths=None):
        if paths is not None:
            self.current = None
            self.repo.git.checkout('--force', commit, '--', paths)
            return

        identity = self.commits.get(commit, commit)
        if self.current == identity:
            return

        self.current = None
        self.repo.git.checkout('--force', commit)
        self.current = identity


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
    global linux_mount
    global linux_repo
    global _cvehound
    global _kernel_checkout
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

    linux = config.getoption('dir')
    repo = None
    if os.path.isdir(os.path.join(linux, '.git')):
        repo = Repo(linux)
        repo.head.reset(index=True, working_tree=True)
        repo.git.clean('-f', '-x', '-d')
        repo.git.checkout('origin/master')
        try:
            repo.remotes.origin.fetch()
            repo.remotes.stable.fetch()
            repo.remotes.next.fetch()
        except Exception:
            pass
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

    if should_use_tmpfs(cves):
        linux_repo, linux_mount = create_tmpfs_repo(repo)
    else:
        linux_repo = repo
        linux_mount = None

    _cvehound = CVEhound(linux_repo.working_tree_dir)
    _kernel_checkout = KernelCheckout(linux_repo)

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
    if linux_mount:
        umount(linux_mount)
        os.rmdir(linux_mount)


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
def branch(request, kernel_checkout):
    kernel_checkout.checkout(request.param)
    return request.param


def pytest_generate_tests(metafunc):
    if 'branch' in metafunc.fixturenames:
        metafunc.parametrize('branch', branches, indirect=True)

    if 'cve' in metafunc.fixturenames:
        metafunc.parametrize('cve', cves)


def _get_kernel_route(item):
    marker = item.get_closest_marker('kernel_history')
    if marker is None:
        return ()

    params = item.callspec.params
    cve = params.get('cve')
    route = []
    for step in marker.args:
        parent = step.endswith('~')
        name = step.removesuffix('~')
        if name == 'branch':
            commit = params['branch']
        elif name == 'initial':
            commit = INITIAL_COMMIT
        elif name == 'fix':
            commit = _cvehound.get_rule_fix(cve)
        elif name == 'fixes':
            commit = _cvehound.get_rule_fixes(cve)
        else:
            raise pytest.UsageError(f'unknown kernel_history step {step!r} on {item.nodeid}')

        if parent:
            if commit in INITIAL_COMMITS:
                continue
            commit += '~'
        route.append(commit)

    return tuple(route)


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
