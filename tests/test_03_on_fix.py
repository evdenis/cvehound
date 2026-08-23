#!/usr/bin/env python3


import pytest

from cvehound.exception import UnsupportedVersion


def test_on_fix(hound, tree_check, cve):
    fix = hound.get_rule_fix(cve)

    try:
        assert not tree_check(fix, cve), cve + ' fails on fix commit'
        assert tree_check(fix + '~', cve), cve + ' fails to detect fix~ commit'
    except UnsupportedVersion:
        pytest.skip('Unsupported spatch version')
