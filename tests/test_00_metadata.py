#!/usr/bin/env python3

import re

import pytest
from kerneltree import object_header

# CVEs that neither kernel.org vulns.git nor CIP kernel-sec covers. They are all
# still PUBLISHED at cve.org - mostly 2013-2018 entries and Android/Qualcomm
# bulletins that were never tracked upstream - so there is nothing to look up.
no_metadata = [
    'CVE-2013-2930', 'CVE-2013-6383', 'CVE-2014-0049', 'CVE-2014-0100', 'CVE-2014-0101',
    'CVE-2014-0155', 'CVE-2014-1737', 'CVE-2014-1738', 'CVE-2014-1874', 'CVE-2014-5077',
    'CVE-2014-7841', 'CVE-2014-7975', 'CVE-2014-8480', 'CVE-2014-8481', 'CVE-2014-8709',
    'CVE-2014-9715', 'CVE-2014-9903', 'CVE-2014-9904', 'CVE-2015-1339', 'CVE-2015-1421',
    'CVE-2015-1593', 'CVE-2015-3636', 'CVE-2015-4004', 'CVE-2015-4700', 'CVE-2015-7566',
    'CVE-2015-8746', 'CVE-2015-8785', 'CVE-2015-8787', 'CVE-2015-8961', 'CVE-2016-10764',
    'CVE-2016-10907', 'CVE-2016-2070', 'CVE-2016-2117', 'CVE-2016-2383', 'CVE-2016-3713',
    'CVE-2016-4568', 'CVE-2016-5828', 'CVE-2016-6156', 'CVE-2016-6162', 'CVE-2016-6516',
    'CVE-2016-8399', 'CVE-2016-9919', 'CVE-2017-11089', 'CVE-2017-18360', 'CVE-2017-18549',
    'CVE-2017-18550', 'CVE-2017-18595', 'CVE-2017-8240', 'CVE-2018-10074', 'CVE-2018-1091',
    'CVE-2018-11232', 'CVE-2018-14619', 'CVE-2018-16658', 'CVE-2018-19406', 'CVE-2018-25015',
    'CVE-2018-5873', 'CVE-2018-8043', 'CVE-2018-9363', 'CVE-2018-9385', 'CVE-2019-18680',
    'CVE-2019-9003', 'CVE-2020-0465', 'CVE-2020-0466', 'CVE-2020-27068', 'CVE-2021-0605',
]  # fmt: skip

metadata_fix_exceptions = [
    (
        'CVE-2017-7308',
        'the rule targets the private-area overflow, not the later tp_reserve overflow',
    ),
    (
        'CVE-2018-10878',
        'the rule targets block-group bounds, not the later metadata-overlap check',
    ),
    (
        'CVE-2019-19769',
        'the rule targets the UAF fix, not the later optimization reinstatement',
    ),
    (
        'CVE-2020-27067',
        'the CVE bundles several L2TP fixes and the rule targets an earlier fix in the series',
    ),
    (
        'CVE-2021-0935',
        'the record combines independent IPv6 datagram and L2TP fixes',
    ),
    (
        'CVE-2021-20194',
        'the rule targets the negative optlen race, not the later upper-bound check',
    ),
    (
        'CVE-2021-29155',
        'the rule targets one detector-specific fix in a larger BPF hardening series',
    ),
    (
        'CVE-2021-3347',
        'the rule targets one futex flaw from a multi-fix CVE record',
    ),
    (
        'CVE-2021-45402',
        'the rule targets missing mov32 bounds updates, not the later helper hardening',
    ),
    (
        'CVE-2023-1989',
        'the rule targets the first UAF fix; the later commit corrects its placement',
    ),
    (
        'CVE-2023-21102',
        'the rule targets the security fix; the later commit adds its missing include',
    ),
]

metadata_break_exceptions = [
    (
        'CVE-2020-24490',
        'the source duplicates one bundle across three CVEs; the rule targets extended reports',
    ),
    (
        'CVE-2020-14331',
        'CIP records a Linux release commit while the fix trailer identifies the introduction',
    ),
    (
        'CVE-2021-0935',
        'the record combines independent IPv6 datagram and L2TP introductions',
    ),
]


def has_detect_to(hound, cve):
    with open(hound.get_rule(cve)) as fh:
        for line in fh:
            if not line.startswith('///'):
                break
            if 'Detect-To:' in line:
                return True
    return False


def test_metadata(hound, cve):
    meta = hound.get_rule_metadata(cve)

    assert 'files' in meta, 'no "Files:" tag in the rule'
    assert 'fix' in meta, 'no "Fix:" tag in the rule'
    assert 'fixes' in meta, 'no "Fixes:" or "Detect-To:" tag in the rule'

    rule = hound.get_rule(cve)
    if rule.endswith('.grep'):
        return

    with open(rule) as fh:
        text = fh.read()

    # Scriptless rules carry their identity in the filename alone; any CVE id
    # that does appear (comments, a leftover report string) must match it.
    cve_id = re.compile(r'CVE-\d{4}-\d{4,7}')
    for res in cve_id.finditer(text):
        assert res.group(0) == cve, 'wrong CVE-id in the rule'

    # The '*' lines are the whole report: a rule with none matches silently,
    # which is a false negative no other test can see. And the shipped spatch
    # is built without Python, so a script rule cannot run at all.
    assert any(line.startswith('*') for line in text.splitlines()), 'nothing starred in the rule'
    assert 'script:python' not in text, 'rules must run under a spatch built without Python'


@pytest.mark.nometadata(
    ('cve',), no_metadata, reason='not covered by kernel.org vulns.git or CIP kernel-sec'
)
def test_cve_in_metadata(hound, cve):
    if hound.get_rule(cve).endswith('.grep'):
        pytest.skip('grep rules are not required to be in the metadata')
    assert hound.get_cve_metadata(cve), 'no metadata in kernel_cves.json'


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
        ('CVE-2017-7558', 'wrong fixes tag, 52c52a61a39f intoduces it a bit earlier'),
        ('CVE-2017-5970', 'the skb_dst dereference predates the fix commit trailer'),
        (
            'CVE-2016-9919',
            'wrong fixes tag, see https://bugzilla.redhat.com/show_bug.cgi?id=1403260',
        ),
        ('CVE-2019-18809', 'wrong fixes tag (too far)'),
        ('CVE-2019-19057', 'the allocation leak predates the fix commit trailer'),
        ('CVE-2019-19051', 'wrong fixes tag because the fix fixing the fix fixing the memory leak'),
        ('CVE-2019-8912', 'the unsigned ownership bug predates the fix commit trailer'),
        ('CVE-2021-3635', 'wrong fixes tag, commit fixes not only flowtables but also objs'),
        ('CVE-2022-3170', 'CVE fix consists of 2 commits, 2nd commit fixes 1st one'),
        ('CVE-2022-34918', 'the vulnerable set element layout predates the fix commit trailer'),
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


# DISPUTED has no source any more. kernel.org does not record it and CIP says so
# for only two CVEs, so disputed rules are tracked purely by living in
# cvehound/cve/disputed/. REJECTED comes from vulns.git's cve/rejected/ directory
# and from CIP's 'ignore: all:' note.
def test_cve_rejected(hound, cve):
    meta = hound.get_cve_metadata(cve)
    if 'disputed' in hound.cve_all_rules[cve]:
        pytest.skip('disputed rules are allowed to be rejected upstream')
    assert not meta.get('rejected'), f'{cve} REJECTED'


@pytest.mark.metadata
@pytest.mark.ownfixes(('cve', 'reason'), metadata_fix_exceptions)
def test_cves_metadata_fix(hound, cve):
    meta_fix = hound.get_cve_metadata(cve).get('fixes')
    if not meta_fix:
        pytest.skip('no fix commit in the metadata')
    fix = hound.get_rule_fix(cve)
    assert fix == meta_fix, f'{fix[0:12]} vs. {meta_fix[0:12]}'


@pytest.mark.metadata
@pytest.mark.ownfixes(('cve', 'reason'), metadata_break_exceptions)
def test_cves_metadata_fixes(hound, cve):
    meta_breaks = hound.get_cve_metadata(cve).get('breaks')
    if not meta_breaks:
        pytest.skip('no introducing commit in the metadata')
    if has_detect_to(hound, cve):
        pytest.skip('Detect-To is a detector boundary, not the vulnerability introduction')
    fixes = hound.get_rule_fixes(cve)
    if fixes == 'v2.6.12-rc2':
        fixes = '1da177e4c3f41524e886b7f1b8a0c1fc7321cac2'
    assert fixes == meta_breaks, f'{fixes[0:12]} vs. {meta_breaks[0:12]}'


def _commit_exists(repo, rev):
    """Does `rev` name a commit, without spawning a process to ask?

    The two sweeps below ask this ~33,000 times between them, once per metadata
    entry. A `git rev-parse` each is ~1ms of fork/exec inside two single test
    items that xdist cannot spread; over the persistent stream it is ~9us.

    ^{commit} carries the type check: anything that is not a commit fails to
    peel and comes back as None.
    """
    return object_header(repo, rev + '^{commit}') is not None


@pytest.mark.metadata
def test_cves_metadata_fix_all(hound, repo):
    broken = []
    meta = hound.metadata
    for cve in meta:
        data = meta[cve]
        if 'fixes' not in data:
            continue

        fix = data['fixes']
        if not fix:
            continue
        if not re.match(r'[0-9a-fA-F]{7,40}', fix):
            continue

        if not _commit_exists(repo, fix):
            broken.append(cve)
    assert not broken, broken


@pytest.mark.metadata
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

        if not _commit_exists(repo, fixes):
            broken.append(cve)
    assert not broken, broken


@pytest.mark.metadata
def test_cves_metadata_title(hound, repo):
    broken = []
    meta = hound.metadata
    for cve in meta:
        data = meta[cve]

        if 'cmt_msg' not in data:
            continue
        data_msg = data['cmt_msg']

        fix = data.get('fixes')
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
