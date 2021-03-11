#!/usr/bin/env python3

import pkg_resources
import pytest
import os

from cvehound.exception import UnsupportedVersion

@pytest.mark.slow
def test_between_fixes_fix(hound, repo, cve):
    fix = hound.get_rule_fix(cve)
    fixes = hound.get_rule_fixes(cve)

    repo.git.checkout(fixes)
    tags = repo.git.rev_list('--no-merges', '--simplify-by-decoration',
                             '--ancestry-path', fixes + '..' + fix)
    for tag in tags.split():
        repo.git.checkout(tag)
        try:
            assert hound.check_cve(cve), cve + ' fails to detect on ' + tag
        except UnsupportedVersion:
            pytest.skip('Unsupported spatch version')
