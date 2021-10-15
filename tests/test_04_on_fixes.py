#!/usr/bin/env python3

import pkg_resources
import pytest
import os

from cvehound.exception import UnsupportedVersion

def test_on_fixes(hound, repo, cve):
    fixes = hound.get_rule_fixes(cve)

    repo.git.checkout('--force', fixes)
    try:
        assert hound.check_cve(cve), 'fails to detect on fixes tag'

        if fixes != 'v2.6.12-rc2' and \
           fixes != '1da177e4c3f41524e886b7f1b8a0c1fc7321cac2':
            repo.git.checkout('HEAD~')
            assert not hound.check_cve(cve), 'detects on fixes~ tag'
    except UnsupportedVersion:
        pytest.skip('Unsupported spatch version')
