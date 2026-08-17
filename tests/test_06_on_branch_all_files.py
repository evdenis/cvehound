#!/usr/bin/env python3

import pytest
from conftest import missing_backports

from cvehound.exception import UnsupportedVersion


@pytest.mark.slow
@pytest.mark.notbackported(('cve', 'branch'), missing_backports)
@pytest.mark.kernel_history('branch')
def test_on_branch(hound, branch, cve):
    try:
        assert not hound.check_cve(cve, True), cve + ' on ' + branch
    except UnsupportedVersion:
        pytest.skip('Unsupported spatch version')
