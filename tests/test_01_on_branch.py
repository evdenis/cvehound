#!/usr/bin/env python3

import pytest
from conftest import missing_backports

from cvehound.exception import UnsupportedVersion


@pytest.mark.fast
@pytest.mark.notbackported(('cve', 'branch'), missing_backports)
def test_on_branch(tree_check, branch, cve):
    try:
        assert not tree_check(branch, cve), cve + ' on ' + branch
    except UnsupportedVersion:
        pytest.skip('Unsupported spatch version')
