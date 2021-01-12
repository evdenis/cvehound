#!/usr/bin/env python3

import re
from cvehound import get_rule_metadata, get_all_cves, read_cve_metadata

def test_metadata(cve):
    meta = get_rule_metadata(cve)

    assert 'files' in meta, 'no "Files:" tag in the rule'
    assert 'fix' in meta, 'no "Fix:" tag in the rule'
    assert 'fixes' in meta, 'no "Fixes:" or "Detect-To:" tag in the rule'

    found = False
    cve_id = re.compile(r'CVE-\d{4}-\d{4,7}')
    rule = get_all_cves()[cve]
    with open(rule, 'rt') as fh:
        for line in fh:
            res = cve_id.search(line)
            if res:
                assert res.group(0) == cve, 'wrong CVE-id in the rule'
                found = True

    assert found, 'no CVE-id in the rule'

    meta = read_cve_metadata()
    assert cve in meta, 'no metadata in kernel_cves.json'
