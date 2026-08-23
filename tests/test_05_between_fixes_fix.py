#!/usr/bin/env python3

import pytest
from kerneltree import sig_has_rule_files

from cvehound.exception import UnsupportedVersion


@pytest.mark.slow
def test_between_fixes_fix(hound, repo, materializer, sig_check, cve, between_mode):
    fix = hound.get_rule_fix(cve)
    fixes = hound.get_rule_fixes(cve)
    files = hound.get_rule_files(cve)

    if between_mode == 'tags':
        # Tagged kernels (-rc included) between the introducing and the fixing
        # commit; the signature dedupe keeps only tags where the files changed.
        refs = repo.git.tag(
            '--contains', fixes, '--merged', fix + '~', '-l', 'v*', '--sort=creatordate'
        ).split()
    else:
        refs = repo.git.log(
            '--format=%H', '--no-merges', '--ancestry-path', fixes + '..' + fix + '~', '--', files
        ).split()

    checked = set()
    for ref in refs:
        sig = materializer.sig(ref, files)
        if sig in checked or not sig_has_rule_files(sig):
            continue
        checked.add(sig)
        try:
            assert sig_check(sig, cve), cve + ' fails to detect on ' + ref
        except UnsupportedVersion:
            pytest.skip('Unsupported spatch version')
