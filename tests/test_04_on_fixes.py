#!/usr/bin/env python3

import pkg_resources
import pytest
import os

from cvehound import check_cve

def test_on_fixes(repo, cve):
    cocci = pkg_resources.resource_filename('cvehound', 'cve/' + cve + '.cocci')
    grep = pkg_resources.resource_filename('cvehound', 'cve/' + cve + '.grep')
    rule = cocci
    if os.path.isfile(grep):
        rule = grep
    fixes = None
    with open(rule, 'r') as fh:
        while True:
            line = fh.readline()
            if not line:
                break
            elif 'Fixes:' in line:
                fixes = line.partition('Fixes:')[2].strip()
                break
            elif 'Detect-To:' in line:
                fixes = line.partition('Detect-To:')[2].strip()
                break
    if not fixes:
        pytest.skip('No Fixes/Detect-To tag')

    repo.git.checkout(fixes)
    assert check_cve(repo.working_tree_dir, cve) == True, 'fails to detect on fixes tag'
