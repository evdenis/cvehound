#!/usr/bin/env python3


import pytest
from conftest import INITIAL_COMMITS

from cvehound.exception import UnsupportedVersion


@pytest.mark.slow
def test_on_fixes(hound, tree_check, cve):
    fixes = hound.get_rule_fixes(cve)

    try:
        assert tree_check(fixes, cve), 'fails to detect on fixes tag'

        if fixes not in INITIAL_COMMITS:
            assert not tree_check(fixes + '~', cve), 'detects on fixes~ tag'
    except UnsupportedVersion:
        pytest.skip('Unsupported spatch version')
