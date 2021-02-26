#!/usr/bin/env python3

import re
from cvehound.cwe import CWE
from cvehound.util import get_cves_metadata

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

def test_cwe():
    for cwe in CWE:
        if cwe == 'Other' or cwe == 'Unspecified':
            continue
        assert CWE[cwe], 'No CWE-id for "{}"'.format(cwe)

def test_cves_metadata_cwe(hound):
    meta = hound.metadata
    for cve in meta:
        if 'cwe' in meta[cve]:
            assert meta[cve]['cwe'] in CWE, 'Unknown CWE description "{}"'.format(meta[cve]['cwe'])
