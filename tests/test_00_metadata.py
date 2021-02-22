#!/usr/bin/env python3

import re

def test_metadata(hound, cve):
    meta = hound.get_rule_metadata(cve)

    assert 'files' in meta, 'no "Files:" tag in the rule'
    assert 'fix' in meta, 'no "Fix:" tag in the rule'
    assert 'fixes' in meta, 'no "Fixes:" or "Detect-To:" tag in the rule'

    found = False
    cve_id = re.compile(r'CVE-\d{4}-\d{4,7}')
    with open(hound.get_rule(cve), 'rt') as fh:
        for line in fh:
            res = cve_id.search(line)
            if res:
                assert res.group(0) == cve, 'wrong CVE-id in the rule'
                found = True

    assert found, 'no CVE-id in the rule'
    assert hound.get_cve_metadata(cve), 'no metadata in kernel_cves.json'
