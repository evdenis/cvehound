#!/usr/bin/env python3

import pkg_resources
import pytest
import os

from cvehound import check_cve, get_rule_metadata

def test_on_fixes(repo, cve):
    meta = get_rule_metadata(cve)
    if 'fixes' not in meta:
        pytest.skip('No Fixes/Detect-To tag')
    fixes = meta['fixes']

    repo.git.checkout(fixes)
    assert check_cve(repo.working_tree_dir, cve) == True, 'fails to detect on fixes tag'

    if fixes != 'v2.6.12-rc2' and \
       fixes != '1da177e4c3f41524e886b7f1b8a0c1fc7321cac2':
        repo.git.checkout('HEAD~')
        assert check_cve(repo.working_tree_dir, cve) == False, 'detects on fixes~ tag'
