#!/usr/bin/env python3

import pytest
from conftest import missing_backports
from cvehound.exception import UnsupportedVersion

@pytest.mark.fast
@pytest.mark.notbackported(
    ('cve', 'branch'),
    missing_backports
)
def test_on_branch(hound, branch, cve):
    try:
        assert not hound.check_cve(cve), cve + ' on ' + branch
    except UnsupportedVersion:
        pytest.skip('Unsupported spatch version')
