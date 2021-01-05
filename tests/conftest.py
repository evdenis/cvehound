#!/usr/bin/env python3

import os
import pytest
from cvehound import get_all_cves
from git import Repo

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
        '--dir', action='store',
        default=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'linux'),
        help='linux kernel sources dir'
    )

linux_repo = None
branches = []
cves = []

def pytest_configure(config):
    global linux_repo
    global branches
    global cves

    config.addinivalue_line('markers', 'slow: mark test as slow to run')
    config.addinivalue_line('markers', 'notbackported: mark test as failed')

    linux = config.getoption('dir')
    if os.path.isdir(os.path.join(linux, '.git')):
        linux_repo = Repo(linux)
        linux_repo.head.reset(index=True, working_tree=True)
        linux_repo.git.clean('-f', '-x', '-d')
        linux_repo.git.checkout('master')
        try:
            linux_repo.remotes.origin.pull()
        except:
            pass
    else:
        linux_repo = Repo.clone_from('git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git', linux)

    branches = config.getoption('branch')
    if not branches:
        branches = [
            'origin/master',
            'origin/linux-5.10.y',
            'origin/linux-5.4.y',
            'origin/linux-4.19.y',
            'origin/linux-4.14.y',
            'origin/linux-4.9.y',
            'origin/linux-4.4.y'
        ]

    cves = config.getoption('cve')
    if not cves:
        cves = get_all_cves().keys()

@pytest.fixture
def repo(request):
    return linux_repo

def pytest_generate_tests(metafunc):
    if 'branch' in metafunc.fixturenames:
        metafunc.parametrize('branch', branches)

    if 'cve' in metafunc.fixturenames:
        metafunc.parametrize('cve', cves)

def pytest_collection_modifyitems(config, items):
    runslow = config.getoption('--runslow')
    skip_slow = pytest.mark.skip(reason='need --runslow option to run')
    fail_notbackported = pytest.mark.xfail(reason='CVE not backported yet')
    for item in items:
        if not runslow and 'slow' in item.keywords:
            item.add_marker(skip_slow)
        if 'notbackported' in item.keywords:
            params = item.callspec.params
            mark = None
            for m in item.own_markers:
                if m.name == 'notbackported':
                    mark = m
                    break
            if (params['branch'], params['cve']) in mark.args[1]:
                item.add_marker(fail_notbackported)
