#!/usr/bin/env python3


import pytest
from conftest import INITIAL_COMMITS

from cvehound.exception import UnsupportedVersion


@pytest.mark.slow
@pytest.mark.kernel_history('fixes', 'fixes~')
def test_on_fixes(hound, kernel_checkout, cve):
    fixes = hound.get_rule_fixes(cve)

    kernel_checkout.checkout(fixes)
    try:
        assert hound.check_cve(cve), 'fails to detect on fixes tag'

        if fixes not in INITIAL_COMMITS:
            kernel_checkout.checkout(fixes + '~')
            assert not hound.check_cve(cve), 'detects on fixes~ tag'
    except UnsupportedVersion:
        pytest.skip('Unsupported spatch version')
