#!/usr/bin/env python3

import pkg_resources
import os

from cvehound import check_cve

def test_on_fix(repo, cve):
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
    assert check_cve(repo.working_tree_dir, cve) == False, cve + ' fails on fix commit'
    repo.git.checkout(fix + '~')
    assert check_cve(repo.working_tree_dir, cve) == True, cve + ' fails to detect fix~ commit'
