#!/usr/bin/env python3

import pkg_resources
import pytest
import os

from cvehound import check_cve, get_rule_metadata

def test_on_fixes(repo, cve):
    meta = get_rule_metadata(cve)
    if 'fixes' not in meta:
        pytest.skip('No Fixes/Detect-To tag')

    repo.git.checkout(meta['fixes'])
    assert check_cve(repo.working_tree_dir, cve) == True, 'fails to detect on fixes tag'
