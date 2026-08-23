#!/usr/bin/env python3

import pytest
from conftest import missing_backports

from cvehound.exception import UnsupportedVersion


@pytest.mark.slow
@pytest.mark.notbackported(('cve', 'branch'), missing_backports)
@pytest.mark.kernel_history('branch')
def test_on_branch(branch_hound, all_files_jobs, branch, cve):
    try:
        assert not branch_hound(branch).check_cve(cve, True, jobs=all_files_jobs), (
            cve + ' on ' + branch
        )
    except UnsupportedVersion:
        pytest.skip('Unsupported spatch version')
