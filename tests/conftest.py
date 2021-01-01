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
        '--runslow', action='store_true', default=False, help='run slow tests'
    )
    parser.addoption(
        '--dir', action='store',
        default=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'linux'),
        help='linux kernel sources dir'
    )

def pytest_configure(config):
    config.addinivalue_line('markers', 'slow: mark test as slow to run')

def pytest_generate_tests(metafunc):
    if 'repo' in metafunc.fixturenames:
        linux = metafunc.config.getoption('dir')
        if os.path.isdir(os.path.join(linux, '.git')):
            repo = Repo(linux)
            repo.head.reset(index=True, working_tree=True)
            repo.git.clean('-f', '-x', '-d')
            repo.git.checkout('master')
            repo.remotes.origin.pull()
        else:
            repo = Repo.clone_from('git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git', linux)
        assert not repo.bare, 'bare repo'
        assert not repo.is_dirty(), 'dirty repo'
        assert not repo.untracked_files, 'there are untracked files'
        metafunc.parametrize('repo', [repo])

    if 'cve' in metafunc.fixturenames:
        cves = metafunc.config.getoption('cve')
        if not cves:
            cves = get_all_cves()
        metafunc.parametrize('cve', cves)

def pytest_collection_modifyitems(config, items):
    if config.getoption('--runslow'):
        # --runslow given in cli: do not skip slow tests
        return
    skip_slow = pytest.mark.skip(reason='need --runslow option to run')
    for item in items:
        if 'slow' in item.keywords:
            item.add_marker(skip_slow)
