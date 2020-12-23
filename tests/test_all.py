#!/usr/bin/env python3

import pkg_resources
import pytest
import os
import sys

from git import Repo
from cvehound import check_cve, get_all_cves

devnull = open(os.devnull, 'w')
cves = get_all_cves()
curdir = os.path.dirname(os.path.realpath(__file__))
linux = os.path.join(curdir, 'linux')

repo = None
if os.path.isdir(os.path.join(linux, '.git')):
    repo = Repo(linux)
    repo.git.checkout('master')
    repo.head.reset(index=True, working_tree=True)
    repo.remotes.origin.pull()
else:
    repo = Repo.clone_from('git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git', linux)


def test_kernel_setup():
    assert not repo.bare, 'bare repo'
    assert not repo.is_dirty(), 'dirty repo'
    assert not repo.untracked_files, 'there are untracked files'
    assert not repo.head.is_detached, 'head should point to master branch'

def test_all_master():
    for cve in cves:
        assert check_cve(linux, cve) == False, cve + ' on master'

def test_all_init():
    tests = { 'CVE-2020-28974': True, 'CVE-2020-27777': True }
    repo.git.checkout('v2.6.12-rc2')
    for cve in cves:
        assert check_cve(linux, cve) == tests.get(cve, False), cve + ' on first commit'

def test_all_fix():
    for cve in cves:
        cocci = pkg_resources.resource_filename('cvehound', 'cve/' + cve + '.cocci')
        grep = pkg_resources.resource_filename('cvehound', 'cve/' + cve + '.grep')
        rule = cocci
        if os.path.isfile(grep):
            rule = grep
        fix = None
        with open(rule, 'r') as fh:
            while True:
                line = fh.readline()
                if not line:
                    break
                if 'Fix:' in line:
                    fix = line.partition('Fix:')[2].strip()
                    break
        assert fix
        repo.git.checkout(fix)
        assert check_cve(linux, cve) == False, cve + ' fails on fix commit'
        repo.git.checkout(fix + '~')
        assert check_cve(linux, cve) == True, cve + ' fails to detect fix~ commit'

def test_all_fixes():
    for cve in cves:
        cocci = pkg_resources.resource_filename('cvehound', 'cve/' + cve + '.cocci')
        grep = pkg_resources.resource_filename('cvehound', 'cve/' + cve + '.grep')
        rule = cocci
        if os.path.isfile(grep):
            rule = grep
        fix = None
        fixes = None
        with open(rule, 'r') as fh:
            while True:
                line = fh.readline()
                if not line:
                    break
                if 'Fix:' in line:
                    fix = line.partition('Fix:')[2].strip()
                elif 'Fixes:' in line:
                    fixes = line.partition('Fixes:')[2].strip()
                    break
                elif 'Detect-To:' in line:
                    fixes = line.partition('Detect-To:')[2].strip()
                    break
        if not fixes:
            continue

        repo.git.checkout(fixes)
        assert check_cve(linux, cve) == True
        tags = repo.git.rev_list('--no-merges', '--simplify-by-decoration',
                                 '--ancestry-path', fixes + '..' + fix)
        for tag in tags.split():
            repo.git.checkout(tag)
            assert check_cve(linux, cve) == True, cve + ' fails to detect on ' + tag
