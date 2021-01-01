#!/usr/bin/env python3

import pkg_resources
import pytest
import os

from cvehound import check_cve

@pytest.mark.slow
def test_between_fixes_fix(repo, cve):
    cocci = pkg_resources.resource_filename('cvehound', 'cve/' + cve + '.cocci')
    grep = pkg_resources.resource_filename('cvehound', 'cve/' + cve + '.grep')
    rule = cocci
    if os.path.isfile(grep):
        rule = grep
    fix = None
    fixes = None
    with open(rule, 'r') as fh:
        while True:
            line = fh.readline()
            if not line:
                break
            if 'Fix:' in line:
                fix = line.partition('Fix:')[2].strip()
            elif 'Fixes:' in line:
                fixes = line.partition('Fixes:')[2].strip()
                break
            elif 'Detect-To:' in line:
                fixes = line.partition('Detect-To:')[2].strip()
                break
    if not fixes:
        pytest.skip('No Fixes/Detect-To tag')

    repo.git.checkout(fixes)
    tags = repo.git.rev_list('--no-merges', '--simplify-by-decoration',
                             '--ancestry-path', fixes + '..' + fix)
    for tag in tags.split():
        repo.git.checkout(tag)
        assert check_cve(repo.working_tree_dir, cve) == True, cve + ' fails to detect on ' + tag
