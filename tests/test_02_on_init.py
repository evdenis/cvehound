#!/usr/bin/env python3

import pytest
from conftest import INITIAL_COMMIT, INITIAL_COMMITS

from cvehound.exception import UnsupportedVersion


@pytest.mark.slow
@pytest.mark.kernel_history('initial')
def test_on_init(hound, kernel_checkout, cve):
    fixes = hound.get_rule_fixes(cve)

    detect = fixes in INITIAL_COMMITS
    kernel_checkout.checkout(INITIAL_COMMIT)
    try:
        if detect:
            assert hound.check_cve(cve), cve + ' on first commit'
        else:
            assert not hound.check_cve(cve), cve + ' on first commit'
    except UnsupportedVersion:
        pytest.skip('Unsupported spatch version')
