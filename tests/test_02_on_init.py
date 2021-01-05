#!/usr/bin/env python3

from cvehound import check_cve, get_rule_metadata

def test_on_init(repo, cve):
    fixes = get_rule_metadata(cve).get('fixes', '')
    detect = False
    if fixes == 'v2.6.12-rc2' or \
       fixes == '1da177e4c3f41524e886b7f1b8a0c1fc7321cac2':
        detect = True
    repo.git.checkout('v2.6.12-rc2')
    assert check_cve(repo.working_tree_dir, cve) == detect, cve + ' on first commit'
