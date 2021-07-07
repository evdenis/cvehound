#!/usr/bin/env python3

import pytest
from cvehound.exception import UnsupportedVersion

@pytest.mark.fast
@pytest.mark.notbackported(
    ('branch', 'cve'),
    [
        ('stable/linux-4.4.y', 'CVE-2019-12382'),
        ('stable/linux-4.9.y', 'CVE-2019-12382'),
        ('stable/linux-4.4.y', 'CVE-2019-15924'),
        ('stable/linux-4.4.y', 'CVE-2020-27777'),
        ('stable/linux-4.9.y', 'CVE-2020-27777'),
        ('stable/linux-4.4.y', 'CVE-2020-29569'),
        ('stable/linux-4.19.y', 'CVE-2019-12455'),
        ('stable/linux-4.14.y', 'CVE-2019-12455'),
        ('stable/linux-4.9.y', 'CVE-2019-12455'),
        ('stable/linux-5.4.y', 'CVE-2020-27825'),
        ('stable/linux-4.19.y', 'CVE-2020-27825'),
        ('stable/linux-4.14.y', 'CVE-2020-27825'),
        ('stable/linux-4.9.y', 'CVE-2020-27825'),
        ('stable/linux-4.4.y', 'CVE-2020-27825'),
        ('stable/linux-4.19.y', 'CVE-2021-22543'),
        ('stable/linux-4.14.y', 'CVE-2021-22543'),
        ('stable/linux-4.9.y', 'CVE-2021-22543'),
    ]
)
def test_on_branch(hound, repo, branch, cve):
    repo.git.checkout(branch)
    try:
        assert not hound.check_cve(cve), cve + ' on ' + branch
    except UnsupportedVersion:
        pytest.skip('Unsupported spatch version')
