#!/usr/bin/env python3

import pkg_resources
import os

from cvehound import check_cve, get_rule_metadata

def test_on_fix(repo, cve):
    fix = get_rule_metadata(cve)['fix']
    repo.git.checkout(fix)
    assert check_cve(repo.working_tree_dir, cve) == False, cve + ' fails on fix commit'
    repo.git.checkout(fix + '~')
    assert check_cve(repo.working_tree_dir, cve) == True, cve + ' fails to detect fix~ commit'
