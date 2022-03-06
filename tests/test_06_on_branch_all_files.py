#!/usr/bin/env python3

import pytest
from cvehound.exception import UnsupportedVersion

@pytest.mark.slow
@pytest.mark.notbackported(
    ('cve', 'branch'),
    [
        ('CVE-2019-12382', 'stable/linux-4.9.y'), # Disputed
        ('CVE-2020-27777', 'stable/linux-4.9.y'),
        ('CVE-2019-12455', 'stable/linux-4.9.y'), # Disputed
        ('CVE-2019-12455', 'stable/linux-4.14.y'), # Disputed
        ('CVE-2019-12455', 'stable/linux-4.19.y'), # Disputed
        ('CVE-2021-22543', 'stable/linux-4.9.y'),
        ('CVE-2021-41864', 'stable/linux-4.14.y'),
        ('CVE-2021-41864', 'stable/linux-4.9.y'),
        ('CVE-2021-4149', 'stable/linux-4.9.y'),
        ('CVE-2021-4149', 'stable/linux-4.14.y'),
        ('CVE-2021-4149', 'stable/linux-4.19.y'),
    ]
)
def test_on_branch(hound, branch, cve):
    try:
        assert not hound.check_cve(cve, True), cve + ' on ' + branch
    except UnsupportedVersion:
        pytest.skip('Unsupported spatch version')
