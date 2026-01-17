#!/usr/bin/env python3

import re

import pytest


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
    with open(rule) as fh:
        for line in fh:
            res = cve_id.search(line)
            if res:
                assert res.group(0) == cve, 'wrong CVE-id in the rule'
                found = True

    assert found, 'no CVE-id in the rule'


@pytest.mark.ownfixes(
    ('cve', 'reason'),
    [
        ('CVE-2021-0605', 'limited SA dump is not implemented in Linux-2.6.12-rc2'),
        (
            'CVE-2020-27825',
            'wrong fixes tag, see https://lore.kernel.org/linux-arm-msm/20210121140951.2a554a5e@gandalf.local.home/',
        ),
        ('CVE-2020-14386', 'wrong fixes tag, see https://seclists.org/oss-sec/2020/q3/150'),
        ('CVE-2019-15924', 'wrong fixes tag, create_workqueue also can return NULL'),
        ('CVE-2021-20265', 'wrong fixes tag, see https://lkml.org/lkml/2016/2/24/1054'),
        ('CVE-2015-8961', 'wrong fixes tag, the error was introduced in 9d5065940693'),
        ('CVE-2017-12188', 'wrong fixes tag, see https://www.spinics.net/lists/kvm/msg156651.html'),
        ('CVE-2017-7558', 'wrong fixes tag, 52c52a61a39f intoduces it a bit earlier'),
        (
            'CVE-2016-9919',
            'wrong fixes tag, see https://bugzilla.redhat.com/show_bug.cgi?id=1403260',
        ),
        ('CVE-2019-18809', 'wrong fixes tag (too far)'),
        ('CVE-2019-19051', 'wrong fixes tag because the fix fixing the fix fixing the memory leak'),
        ('CVE-2021-3635', 'wrong fixes tag, commit fixes not only flowtables but also objs'),
        ('CVE-2022-3170', 'CVE fix consists of 2 commits, 2nd commit fixes 1st one'),
        ('CVE-2024-0193', 'wrong fixes tag, 5f68718b34a5 fixes race'),
        ('CVE-2024-26720', 'the problem is also present in the earlier commits'),
    ],
)
def test_fixes(hound, repo, cve):
    cve_fix = hound.get_rule_fix(cve)
    cve_fixes = repo.git.rev_parse('--verify', hound.get_rule_fixes(cve) + '^{commit}')
    cve_fixes = cve_fixes[0:12]

    msg = repo.git.show('-s', '--format=%s\n%b', cve_fix)
    msg_fixes = [
        repo.git.rev_parse('--verify', x)[0:12]
        for x in re.findall(r'Fixes:\s*([0-9a-fA-F]{7,40})', msg)
    ]
    if msg_fixes:
        if len(msg_fixes) == 1:
            msg_fixes = msg_fixes[0]
        assert cve_fixes in msg_fixes, f'{cve_fixes[0:12]} vs {msg_fixes}'
