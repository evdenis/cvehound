#!/usr/bin/env python3


import pytest

from cvehound.exception import UnsupportedVersion


@pytest.mark.kernel_history('fix', 'fix~')
def test_on_fix(hound, kernel_checkout, cve):
    fix = hound.get_rule_fix(cve)

    kernel_checkout.checkout(fix)
    try:
        assert not hound.check_cve(cve), cve + ' fails on fix commit'
        kernel_checkout.checkout(fix + '~')
        assert hound.check_cve(cve), cve + ' fails to detect fix~ commit'
    except UnsupportedVersion:
        pytest.skip('Unsupported spatch version')
