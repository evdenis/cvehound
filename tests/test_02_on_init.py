#!/usr/bin/env python3

import pytest
from conftest import INITIAL_COMMIT, INITIAL_COMMITS

from cvehound.exception import UnsupportedVersion


@pytest.mark.slow
def test_on_init(hound, tree_check, cve):
    fixes = hound.get_rule_fixes(cve)

    detect = fixes in INITIAL_COMMITS
    try:
        assert tree_check(INITIAL_COMMIT, cve) == detect, cve + ' on first commit'
    except UnsupportedVersion:
        pytest.skip('Unsupported spatch version')
