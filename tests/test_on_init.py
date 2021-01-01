#!/usr/bin/env python3

import pkg_resources
import pytest
import os
import sys

from git import Repo
from cvehound import check_cve

devnull = open(os.devnull, 'w')
curdir = os.path.dirname(os.path.realpath(__file__))
linux = os.path.join(curdir, 'linux')

repo = None
if os.path.isdir(os.path.join(linux, '.git')):
    repo = Repo(linux)
else:
    repo = Repo.clone_from('git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git', linux)


def test_kernel_setup():
    assert not repo.bare, 'bare repo'
    assert not repo.is_dirty(), 'dirty repo'
    assert not repo.untracked_files, 'there are untracked files'

def test_init(cve):
    tests = { 'CVE-2020-28974': True, 'CVE-2020-27777': True }
    repo.git.checkout('v2.6.12-rc2')
    assert check_cve(linux, cve) == tests.get(cve, False), cve + ' on first commit'
