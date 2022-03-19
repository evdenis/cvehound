#!/usr/bin/env python3

import re
import pytest
from cvehound.cwe import CWE

def test_metadata(hound, cve):
    meta = hound.get_rule_metadata(cve)

    assert 'files' in meta, 'no "Files:" tag in the rule'
    assert 'fix' in meta, 'no "Fix:" tag in the rule'
    assert 'fixes' in meta, 'no "Fixes:" or "Detect-To:" tag in the rule'

    rule = hound.get_rule(cve)
    if rule.endswith('.grep'):
        return

    found = False
    cve_id = re.compile(r'CVE-\d{4}-\d{4,7}')
    with open(rule, 'rt') as fh:
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

@pytest.mark.ownfixes(
    ('cve', 'reason'),
    [
        ('CVE-2021-0605',  "limited SA dump is not implemented in Linux-2.6.12-rc2"),
        ('CVE-2020-27825', "wrong fixes tag, see https://lore.kernel.org/linux-arm-msm/20210121140951.2a554a5e@gandalf.local.home/"),
        ('CVE-2020-14386', "wrong fixes tag, see https://seclists.org/oss-sec/2020/q3/150"),
        ('CVE-2019-15924', "wrong fixes tag, create_workqueue also can return NULL"),
        ('CVE-2021-20265', "wrong fixes tag, see https://lkml.org/lkml/2016/2/24/1054"),
        ('CVE-2015-8961', "wrong fixes tag, the error was introduced in 9d5065940693"),
        ('CVE-2017-12188', "wrong fixes tag, see https://www.spinics.net/lists/kvm/msg156651.html"),
        ('CVE-2017-7558', "wrong fixes tag, 52c52a61a39f intoduces it a bit earlier"),
    ]
)
def test_fixes(hound, repo, cve):
    cve_fix = hound.get_rule_fix(cve)
    cve_fixes = repo.git.rev_parse('--verify', hound.get_rule_fixes(cve) + '^{commit}')
    cve_fixes = cve_fixes[0:12]

    msg = repo.git.show('-s', '--format=%s\n%b', cve_fix)
    msg_fixes = list(map(lambda x: repo.git.rev_parse('--verify', x)[0:12],
                         re.findall(r'Fixes:\s*([0-9a-fA-F]{7,40})', msg)))
    if msg_fixes:
        if len(msg_fixes) == 1:
            msg_fixes = msg_fixes[0]
        assert cve_fixes in msg_fixes, \
            "{} vs {}".format(cve_fixes[0:12], msg_fixes)

def test_cve_disputed(hound, cve):
    meta = hound.get_cve_metadata(cve)
    rule = hound.cve_all_rules[cve]
    if 'nvd_text' in meta and not 'disputed' in rule:
        assert ' DIS' not in meta['nvd_text'], "{} DISPUTED".format(cve)

def test_cve_rejected(hound, cve):
    meta = hound.get_cve_metadata(cve)
    if 'nvd_text' in meta:
        assert ' REJ' not in meta['nvd_text'], "{} REJECTED".format(cve)

@pytest.mark.lkc
def test_cves_metadata_fix(hound, cve):
    fix = hound.get_rule_fix(cve)
    lkc_fix = hound.get_cve_metadata(cve)['fixes']
    assert fix == lkc_fix, "{} vs. {}".format(fix[0:12], lkc_fix[0:12])

@pytest.mark.lkc
def test_cves_metadata_fixes(hound, cve):
    fixes = hound.get_rule_fixes(cve)
    lkc_fixes = hound.get_cve_metadata(cve)['breaks']
    if fixes == 'v2.6.12-rc2':
        fixes = '1da177e4c3f41524e886b7f1b8a0c1fc7321cac2'
    assert fixes == lkc_fixes, "{} vs. {}".format(fixes[0:12], lkc_fixes[0:12])

@pytest.mark.lkc
def test_cves_metadata_fix_all(hound, repo):
    broken = []
    meta = hound.metadata
    for cve in meta:
        data = meta[cve]
        if 'fixes' not in data:
            continue
        if 'vendor_specific' in data and data['vendor_specific']:
            continue

        fix = data['fixes']
        if not fix:
            continue
        if not re.match(r'[0-9a-fA-F]{7,40}', fix):
            continue

        try:
            repo.git.rev_parse('--verify', fix + '^{commit}')
        except Exception:
            broken.append(cve)
    assert not broken, broken

@pytest.mark.lkc
def test_cves_metadata_fixes_all(hound, repo):
    broken = []
    meta = hound.metadata
    for cve in meta:
        data = meta[cve]
        if 'breaks' not in data:
            continue

        fixes = data['breaks']
        if not fixes:
            continue
        if not re.match(r'[0-9a-fa-f]{7,40}', fixes):
            continue

        try:
            repo.git.rev_parse('--verify', fixes + '^{commit}')
        except Exception:
            broken.append(cve)
    assert not broken, broken

@pytest.mark.lkc
def test_cves_metadata_fixes_all_git(hound, repo):
    broken = []
    meta = hound.metadata
    for cve in meta:
        data = meta[cve]
        if 'breaks' not in data:
            continue

        fixes = data['breaks']
        if not fixes:
            continue
        if not re.match(r'[0-9a-fa-f]{7,40}', fixes):
            continue

        try:
            fixes = repo.git.rev_parse('--verify', fixes + '^{commit}')
            fixes = fixes[0:12]
            msg = repo.git.show('-s', '--format=%s\n%b', fixes)
            msg_fixes = list(map(lambda x: repo.git.rev_parse('--verify', x)[0:12],
                             re.findall(r'Fixes:\s*([0-9a-fA-F]{7,40})', msg)))
        except Exception:
            continue

        if msg_fixes:
            if len(msg_fixes) == 1:
                msg_fixes = msg_fixes[0]
            if fixes not in msg_fixes:
                broken.append(cve)

    assert not broken, broken

@pytest.mark.lkc
def test_cves_metadata_title(hound, repo):
    broken = []
    meta = hound.metadata
    for cve in meta:
        data = meta[cve]

        if 'cmt_msg' not in data:
            continue
        data_msg = data['cmt_msg']

        fix = data['fixes']
        if not fix:
            continue
        if not re.match(r'[0-9a-fa-f]{7,40}', fix):
            continue

        try:
            fix = repo.git.rev_parse('--verify', fix + '^{commit}')
            fix = fix[0:12]
            git_msg = repo.git.show('-s', '--format=%s', fix)
        except Exception:
            continue

        if data_msg != git_msg:
            broken.append(cve)

    assert not broken, broken
