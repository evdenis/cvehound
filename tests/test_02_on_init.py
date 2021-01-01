#!/usr/bin/env python3

from cvehound import check_cve

def test_on_init(repo, cve):
    tests = { 'CVE-2020-28974': True, 'CVE-2020-27777': True }
    repo.git.checkout('v2.6.12-rc2')
    assert check_cve(repo.working_tree_dir, cve) == tests.get(cve, False), cve + ' on first commit'
