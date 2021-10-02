#!/usr/bin/env python3

import pytest
from cvehound.exception import UnsupportedVersion

@pytest.mark.slow
@pytest.mark.notbackported(
    ('cve', 'branch'),
    [
        ('CVE-2019-12382', 'stable/linux-4.4.y'),
        ('CVE-2019-12382', 'stable/linux-4.9.y'),
        ('CVE-2019-15924', 'stable/linux-4.4.y'),
        ('CVE-2020-27777', 'stable/linux-4.4.y'),
        ('CVE-2020-27777', 'stable/linux-4.9.y'),
        ('CVE-2019-12455', 'stable/linux-4.9.y'),
        ('CVE-2019-12455', 'stable/linux-4.14.y'),
        ('CVE-2019-12455', 'stable/linux-4.19.y'),
        ('CVE-2021-22543', 'stable/linux-4.9.y'),
        ('CVE-2019-12819', 'origin/master'), # https://lore.kernel.org/netdev/20210926045313.2267655-1-yanfei.xu@windriver.com/raw
        ('CVE-2019-12819', 'next/master'),
    ]
)
def test_on_branch(hound, branch, cve):
    try:
        assert not hound.check_cve(cve, True), cve + ' on ' + branch
    except UnsupportedVersion:
        pytest.skip('Unsupported spatch version')
