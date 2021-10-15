#!/usr/bin/env python3

import pytest
import pkg_resources
import os

from cvehound.exception import UnsupportedVersion

def test_on_fix(hound, repo, cve):
    fix = hound.get_rule_fix(cve)

    repo.git.checkout('--force', fix)
    try:
        assert not hound.check_cve(cve), cve + ' fails on fix commit'
        repo.git.checkout(fix + '~')
        assert hound.check_cve(cve), cve + ' fails to detect fix~ commit'
    except UnsupportedVersion:
        pytest.skip('Unsupported spatch version')
