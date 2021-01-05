#!/usr/bin/env python3

import pkg_resources
import pytest
import os

from cvehound import check_cve, get_rule_metadata

@pytest.mark.slow
def test_between_fixes_fix(repo, cve):
    meta = get_rule_metadata(cve)
    if 'fixes' not in meta:
        pytest.skip('No Fixes/Detect-To tag')

    repo.git.checkout(meta['fixes'])
    tags = repo.git.rev_list('--no-merges', '--simplify-by-decoration',
                             '--ancestry-path', meta['fixes'] + '..' + meta['fix'])
    for tag in tags.split():
        repo.git.checkout(tag)
        assert check_cve(repo.working_tree_dir, cve) == True, cve + ' fails to detect on ' + tag
