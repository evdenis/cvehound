#!/usr/bin/env python3

import pytest
from cvehound.exception import UnsupportedVersion

def test_on_init(hound, repo, cve):
    fixes = hound.get_rule_fixes(cve)

    detect = False
    if fixes == 'v2.6.12-rc2' or \
       fixes == '1da177e4c3f41524e886b7f1b8a0c1fc7321cac2':
        detect = True
    repo.git.checkout('--force', 'v2.6.12-rc2')
    try:
        if detect:
            assert hound.check_cve(cve), cve + ' on first commit'
        else:
            assert not hound.check_cve(cve), cve + ' on first commit'
    except UnsupportedVersion:
        pytest.skip('Unsupported spatch version')
