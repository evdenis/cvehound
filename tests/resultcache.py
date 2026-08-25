#!/usr/bin/env python3
"""Persistent verdict cache for materialized detection runs.

The fixes..fix~ history is immutable, so a rule's verdict on a blob signature
is a pure function of (rule bytes, blobs, which spatch binary, python, harness
logic). Verdicts — both True and False — are stored as JSONL, append-only per
xdist worker (no locking needed); every process loads all files of its context
at startup. A context directory pins everything environmental, so pointing at a
different spatch, upgrading either it or python, or a HARNESS_EPOCH bump simply
starts an empty namespace.
"""

import contextlib
import hashlib
import json
import os
import shutil
import sys
import time

from filelock import FileLock

# Bump on any semantic change to how checks are invoked or keys are built.
HARNESS_EPOCH = 3

MAX_AGE = 90 * 24 * 3600


def context_id(spatch_identity):
    python = '{}.{}'.format(*sys.version_info[:2])
    raw = '\x00'.join((spatch_identity, str(HARNESS_EPOCH), python))
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


class ResultCache:
    def __init__(self, root, spatch_identity, worker='main'):
        self.root = root
        self.dir = os.path.join(root, context_id(spatch_identity))
        os.makedirs(self.dir, exist_ok=True)
        self._path = os.path.join(self.dir, worker + '.jsonl')
        self._entries = {}
        self._rule_hashes = {}
        self.hits = 0
        self.misses = 0
        self._load_dir()

    def _load_dir(self):
        for name in sorted(os.listdir(self.dir)):
            if name.endswith('.jsonl'):
                self._load(os.path.join(self.dir, name))

    def _load(self, path):
        # suppress(OSError): a concurrent session's compact() may unlink
        # files between our listdir and open.
        with contextlib.suppress(OSError), open(path) as fh:
            for line in fh:
                try:
                    rec = json.loads(line)
                    self._entries[rec['k']] = (bool(rec['v']), int(rec['t']))
                except (ValueError, KeyError, TypeError):
                    # A torn or corrupt line (including valid-JSON non-dicts
                    # like `null`) must never brick every subsequent run.
                    continue

    def key(self, rule_path, sig):
        rule_hash = self._rule_hashes.get(rule_path)
        if rule_hash is None:
            with open(rule_path, 'rb') as fh:
                rule_hash = hashlib.sha256(fh.read()).digest()
            self._rule_hashes[rule_path] = rule_hash
        h = hashlib.sha256(rule_hash)
        for relpath, oid in sig:
            h.update(f'\x00{relpath}\x01{oid}'.encode())
        return h.hexdigest()

    def get(self, key):
        entry = self._entries.get(key)
        if entry is None:
            self.misses += 1
            return None
        self.hits += 1
        return entry[0]

    def put(self, key, verdict):
        now = int(time.time())
        self._entries[key] = (verdict, now)
        with open(self._path, 'a') as fh:
            fh.write(json.dumps({'k': key, 'v': int(verdict), 't': now}) + '\n')

    def compact(self):
        """Merge every worker file of this context; drop stale entries.

        Controller-only: this session's workers must be finished. A lock
        serializes concurrent pytest invocations sharing the cache root so two
        compactions cannot unlink each other's files mid-merge; a session that
        keeps appending to a file compact() already merged loses only those
        late verdicts (a cache-warmth cost, never a wrong verdict). Other
        contexts (older spatch/python/epoch) are removed wholesale once they
        go stale.
        """
        with FileLock(os.path.join(self.root, '.compact.lock')):
            self._compact_locked()

    def _compact_locked(self):
        # Workers appended their files after this instance loaded the
        # directory: re-read everything before merging.
        self._entries = {}
        self._load_dir()
        cutoff = int(time.time()) - MAX_AGE
        merged = {k: v for k, v in self._entries.items() if v[1] >= cutoff}
        tmp = os.path.join(self.dir, '.merged.tmp')
        with open(tmp, 'w') as fh:
            for k, (v, t) in sorted(merged.items()):
                fh.write(json.dumps({'k': k, 'v': int(v), 't': t}) + '\n')
        for name in os.listdir(self.dir):
            if name.endswith('.jsonl'):
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(os.path.join(self.dir, name))
        os.replace(tmp, os.path.join(self.dir, 'merged.jsonl'))
        for name in os.listdir(self.root):
            other = os.path.join(self.root, name)
            if other == self.dir or not os.path.isdir(other):
                continue
            latest = 0
            with contextlib.suppress(FileNotFoundError):
                for entry in os.scandir(other):
                    latest = max(latest, entry.stat().st_mtime)
            if latest < cutoff:
                shutil.rmtree(other, ignore_errors=True)
