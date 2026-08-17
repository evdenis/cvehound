#!/usr/bin/env python3

import re

import pytest
from git import GitCommandError

from cvehound.exception import UnsupportedVersion


@pytest.mark.slow
@pytest.mark.kernel_history('fixes')
def test_between_fixes_fix(hound, repo, kernel_checkout, cve):
    fix = hound.get_rule_fix(cve)
    fixes = hound.get_rule_fixes(cve)
    files = hound.get_rule_files(cve)
    pathspec = re.compile(r"error: pathspec '([^']+)'")

    kernel_checkout.checkout(fixes)

    commits = repo.git.log(
        '--format=%H', '--no-merges', '--ancestry-path', fixes + '..' + fix + '~', '--', files
    )
    for commit in commits.split():
        checkout_files = files
        try:
            kernel_checkout.checkout(commit, checkout_files)
        except GitCommandError as e:
            remove_files = set(pathspec.findall(e.stderr))
            kernel_checkout.checkout(commit, list(set(checkout_files) - remove_files))

        try:
            assert hound.check_cve(cve), cve + ' fails to detect on ' + commit
        except UnsupportedVersion:
            pytest.skip('Unsupported spatch version')
