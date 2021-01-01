#!/usr/bin/env python3

from cvehound import check_cve

def test_on_master(repo, cve):
    repo.git.checkout('master')
    assert check_cve(repo.working_tree_dir, cve) == False, cve + ' on master'
