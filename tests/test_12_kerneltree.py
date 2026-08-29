#!/usr/bin/env python3

import os

import pytest

from cvehound import KCONFIG_H
from cvehound.oracle import hound_at

CVE = 'CVE-2014-0100'
FILE = 'net/ipv4/inet_fragment.c'


def test_sig_rejects_unresolvable_ref(materializer):
    with pytest.raises(ValueError, match='unresolvable'):
        materializer.sig('stable/linux-0.0.y', ['kernel/fork.c'])


def test_sig_probes_kconfig(materializer, hound):
    fix = hound.get_rule_fix(CVE)
    paths = [p for p, _ in materializer.sig(fix, hound.get_rule_files(CVE))]
    assert FILE in paths
    assert KCONFIG_H in paths


def test_sig_omits_missing_paths(materializer):
    sig = materializer.sig('v2.6.12-rc2', ['does/not/exist.c', 'kernel/fork.c'])
    assert [p for p, _ in sig] == ['kernel/fork.c']


def test_sig_expands_directories(materializer):
    paths = [p for p, _ in materializer.sig('v2.6.12-rc2', ['ipc'])]
    assert paths
    assert all(p.startswith('ipc/') for p in paths)
    assert 'ipc/util.c' in paths


def test_materialize_is_idempotent_and_shared(materializer, hound):
    fix = hound.get_rule_fix(CVE)
    sig = materializer.sig(fix, hound.get_rule_files(CVE))
    tree = materializer.materialize(sig)
    assert tree == materializer.materialize(sig)
    blob = os.path.join(materializer.blob_dir, dict(sig)[FILE])
    assert os.path.samefile(blob, os.path.join(tree, FILE))


def test_blob_publish_is_write_once(materializer, hound, monkeypatch):
    oid = dict(materializer.sig(hound.get_rule_fix(CVE), [FILE]))[FILE]
    before = os.stat(materializer._fetch_blob(oid)).st_ino
    # a racing worker that passed the exists() check before the first writer landed
    monkeypatch.setattr(os.path, 'exists', lambda _: False)
    assert os.stat(materializer._fetch_blob(oid)).st_ino == before


def test_hound_at_verdicts(materializer, hound):
    fix = hound.get_rule_fix(CVE)
    files = hound.get_rule_files(CVE)
    vuln = materializer.materialize(materializer.sig(fix + '~', files))
    fixed = materializer.materialize(materializer.sig(fix, files))
    assert hound_at(hound, vuln).check_cve(CVE)
    assert not hound_at(hound, fixed).check_cve(CVE)


def test_hound_at_retargets_only_the_copy(materializer, hound):
    tree = materializer.materialize(())
    h = hound_at(hound, tree)
    assert h.kernel == tree
    assert hound.kernel != tree
