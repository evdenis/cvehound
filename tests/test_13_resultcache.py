#!/usr/bin/env python3

import json
import os

from resultcache import ResultCache

SPATCH = 'spatch version 1.3.2 compiled with OCaml version 4.14.2'
SIG = (('include/linux/kconfig.h', 'a' * 40), ('net/core/dev.c', 'b' * 40))


def make_rule(tmp_path, content='@r@\n@@\nfoo();\n', name='CVE-0000-0000.cocci'):
    rule = tmp_path / name
    rule.write_text(content)
    return str(rule)


def test_key_depends_on_rule_bytes_and_sig(tmp_path):
    cache = ResultCache(str(tmp_path / 'c'), SPATCH)
    rule = make_rule(tmp_path)
    key = cache.key(rule, SIG)
    assert key == cache.key(rule, SIG)
    assert key != cache.key(rule, SIG[:1])
    other = make_rule(tmp_path, 'changed', name='CVE-0000-0001.cocci')
    assert key != cache.key(other, SIG)


def test_roundtrip_persists_both_verdicts(tmp_path):
    root = str(tmp_path / 'c')
    cache = ResultCache(root, SPATCH)
    rule = make_rule(tmp_path)
    hit = cache.key(rule, SIG)
    miss = cache.key(rule, SIG[:1])
    assert cache.get(hit) is None
    cache.put(hit, True)
    cache.put(miss, False)

    reloaded = ResultCache(root, SPATCH)
    assert reloaded.get(hit) is True
    assert reloaded.get(miss) is False
    assert reloaded.hits == 2


def test_workers_share_one_context(tmp_path):
    root = str(tmp_path / 'c')
    one = ResultCache(root, SPATCH, worker='gw0')
    one.put('k1', True)
    assert ResultCache(root, SPATCH, worker='gw1').get('k1') is True


def test_contexts_are_isolated(tmp_path):
    root = str(tmp_path / 'c')
    old = ResultCache(root, 'spatch version 1.2')
    old.put('k1', True)
    assert ResultCache(root, SPATCH).get('k1') is None


def test_compact_merges_and_prunes(tmp_path):
    root = str(tmp_path / 'c')
    cache = ResultCache(root, SPATCH)

    # Worker files appear after the controller instance loaded the directory.
    one = ResultCache(root, SPATCH, worker='gw0')
    one.put('keep', True)
    two = ResultCache(root, SPATCH, worker='gw1')
    two.put('fresh', False)
    stale_line = json.dumps({'k': 'stale', 'v': 0, 't': 1})
    with open(os.path.join(cache.dir, 'gw2.jsonl'), 'w') as fh:
        fh.write(stale_line + '\n')

    cache.compact()

    assert os.listdir(cache.dir) == ['merged.jsonl']
    merged = ResultCache(root, SPATCH)
    assert merged.get('keep') is True
    assert merged.get('fresh') is False
    assert merged.get('stale') is None
