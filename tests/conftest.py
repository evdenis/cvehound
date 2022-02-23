#!/usr/bin/env python3

import os
import pytest
import tempfile
import psutil
from cvehound import CVEhound, get_rule_cves
from git import Repo
from subprocess import run

def mount_tmpfs(target, req_mem_gb):
    if os.path.ismount(target):
        return True
    lines = []
    with open('/proc/meminfo') as fh:
        lines = fh.readlines()
    meminfo = dict((i.split()[0].rstrip(':'),int(i.split()[1])) for i in lines)
    av_mem_gb = int(meminfo['MemAvailable'] / 1024 ** 2)
    if av_mem_gb >= req_mem_gb + 1:
        ret = run(['sudo', '--non-interactive',
                   'mount', '-t', 'tmpfs', '-o', 'rw,noatime,nosuid,nodev,noexec,size=' + str(req_mem_gb) + 'G', 'tmpfs', target])
        return ret.returncode == 0
    else:
        return False

def mount_overlayfs(lower, upper, workdir, target):
    if os.path.ismount(target):
        return True
    ret = run(['sudo', '--non-interactive',
               'mount', '-t', 'overlay', '-o', 'rw,lowerdir=' + lower + ',upperdir=' + upper + ',workdir=' + workdir, 'overlay', target])
    return ret.returncode == 0

def umount(target):
    if os.path.ismount(target):
        run(['sudo', '--non-interactive', 'umount', target])

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
    parser.addoption(
        '--runslow', action='store_true', default=False, help='run slow tests'
    )
    parser.addoption(
        '--runlkc', action='store_true', default=False, help='run lkc metadata tests'
    )
    parser.addoption(
        '--dir', action='store',
        default=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'linux'),
        help='linux kernel sources dir'
    )

overlaydir = None
linux_mount = None
linux_repo = None
_cvehound = None
branches = []
cves = []

def pytest_configure(config):
    global overlaydir
    global linux_mount
    global linux_repo
    global _cvehound
    global branches
    global cves

    config.addinivalue_line('markers', 'slow: mark test as slow to run')
    config.addinivalue_line('markers', 'fast: fast tests that are duplicated by slow ones')
    config.addinivalue_line('markers', 'notbackported: mark test as failed')
    config.addinivalue_line('markers', 'ownfixes: mark test as failed')

    try:
        p = psutil.Process()
        p.nice(-100)
        p.ionice(psutil.IOPRIO_CLASS_RT, value=0)
    except:
        pass

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
        except:
            pass
    else:
        cwd = os.getcwd()
        os.makedirs(linux, exist_ok=True)
        os.chdir(linux)
        repo = Repo.clone_from('git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git', '.')
        repo.create_remote('stable', 'git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git')
        repo.create_remote('next', 'git://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git')
        repo.remotes.stable.fetch()
        repo.remotes.next.fetch()
        os.chdir(cwd)

    overlaydir = tempfile.mkdtemp()
    linux_mount = tempfile.mkdtemp()
    if mount_tmpfs(overlaydir, 2):
        upperdir = os.path.join(overlaydir, 'upper')
        workdir = os.path.join(overlaydir, 'work')
        os.mkdir(upperdir)
        os.mkdir(workdir)
        mount_overlayfs(linux, upperdir, workdir, linux_mount)
        linux_repo = Repo(linux_mount)
    else:
        linux_repo = repo

    _cvehound = CVEhound(linux_repo.working_tree_dir)

    branches = config.getoption('branch')
    if not branches:
        branches = [
            'origin/master',
            'next/master',
            'stable/linux-5.15.y',
            'stable/linux-5.10.y',
            'stable/linux-5.4.y',
            'stable/linux-4.19.y',
            'stable/linux-4.14.y',
            'stable/linux-4.9.y',
        ]

    cves = config.getoption('cve')
    if not cves:
        (cves, _, _) = get_rule_cves()
        cves = cves.keys()

def pytest_unconfigure(config):
    umount(linux_mount)
    umount(overlaydir)
    os.rmdir(overlaydir)
    os.rmdir(linux_mount)

@pytest.fixture
def repo():
    return linux_repo

@pytest.fixture
def hound():
    return _cvehound

prev_branch = None
@pytest.fixture
def branch(request):
    global prev_branch
    if prev_branch != request.param:
        linux_repo.git.checkout('--force', request.param)
        prev_branch = request.param
    return request.param

def pytest_generate_tests(metafunc):
    if 'branch' in metafunc.fixturenames:
        metafunc.parametrize('branch', branches, indirect=True)

    if 'cve' in metafunc.fixturenames:
        metafunc.parametrize('cve', cves)

def pytest_collection_modifyitems(config, items):
    runslow = config.getoption('--runslow')
    runlkc = config.getoption('--runlkc')
    skip_slow = pytest.mark.skip(reason='need --runslow option to run')
    skip_fast = pytest.mark.skip(reason='slow tests cover these testcases')
    skip_lkc = pytest.mark.skip(reason='need --runlkc option to run')
    fail_notbackported = pytest.mark.xfail(reason='CVE not backported yet')
    for item in items:
        if not runslow and 'slow' in item.keywords:
            item.add_marker(skip_slow)
        if runslow and 'fast' in item.keywords:
            item.add_marker(skip_fast)
        if not runlkc and 'lkc' in item.keywords:
            item.add_marker(skip_lkc)
        if 'notbackported' in item.keywords:
            params = item.callspec.params
            mark = None
            for m in item.own_markers:
                if m.name == 'notbackported':
                    mark = m
                    break
            if (params['cve'], params['branch']) in mark.args[1]:
                item.add_marker(fail_notbackported)
        if 'ownfixes' in item.keywords:
            params = item.callspec.params
            mark = None
            for m in item.own_markers:
                if m.name == 'ownfixes':
                    mark = m
                    break
            for rec in mark.args[1]:
                if params['cve'] == rec[0]:
                    item.add_marker(pytest.mark.xfail(reason=rec[1]))
