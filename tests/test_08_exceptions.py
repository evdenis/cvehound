#!/usr/bin/env python3

"""Guard the missing_backports exception list against silent staleness.

A pair whose CVE or branch no longer exists is never collected, so the strict
xfail in conftest can never report it. These checks are what notice instead.
"""

from conftest import DEFAULT_BRANCHES, missing_backports

from cvehound import get_rule_cves

DROP = 'delete the pair from missing_backports in tests/conftest.py'


def test_missing_backports_rules_exist():
    known = get_rule_cves()[0]
    unknown = sorted({cve for cve, _ in missing_backports if cve not in known})
    assert not unknown, f'no rule for {", ".join(unknown)}: {DROP}'


def test_missing_backports_branches_supported():
    stale = sorted({b for _, b in missing_backports if b not in DEFAULT_BRANCHES})
    assert not stale, f'{", ".join(stale)} is no longer tested: {DROP}'


def test_missing_backports_has_no_duplicates():
    dupes = sorted({p for p in missing_backports if missing_backports.count(p) > 1})
    assert not dupes, f'duplicated entries: {dupes}'
