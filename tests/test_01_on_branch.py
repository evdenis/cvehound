#!/usr/bin/env python3

import pytest
from cvehound import check_cve

@pytest.mark.notbackported(
    ('branch', 'cve'),
    [
        ('origin/linux-4.4.y', 'CVE-2020-27777'),
        ('origin/linux-4.9.y', 'CVE-2020-27777'),
        ('origin/linux-4.4.y', 'CVE-2020-29569'),
        ('origin/linux-4.19.y', 'CVE-2019-12455'),
        ('origin/linux-4.14.y', 'CVE-2019-12455'),
        ('origin/linux-4.9.y', 'CVE-2019-12455'),
    ]
)
def test_on_branch(repo, branch, cve):
    repo.git.checkout(branch)
    assert check_cve(repo.working_tree_dir, cve) == False, cve + ' on ' + branch
