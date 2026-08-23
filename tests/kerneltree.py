#!/usr/bin/env python3
"""Materialized kernel mini-trees: run rules against any commit without a checkout.

check_cve() reads only the rule's Files: paths (plus include/linux/kconfig.h when
present) from disk, so a directory holding just those blobs is a complete substrate
for every non-all_files check. Blobs come straight from the object database through
GitPython's persistent `git cat-file` processes and are shared across trees via a
content-addressed store and hardlinks.
"""

import copy
import hashlib
import os
import shutil
import threading

from cvehound import KCONFIG_H


class BlobMaterializer:
    def __init__(self, repo, root):
        self.repo = repo
        self.blob_dir = os.path.join(root, 'blobs')
        self.tree_dir = os.path.join(root, 'trees')
        os.makedirs(self.blob_dir, exist_ok=True)
        os.makedirs(self.tree_dir, exist_ok=True)
        # GitPython's persistent cat-file streams are not thread-safe:
        # serialize request/response cycles for threaded callers.
        self._lock = threading.Lock()

    def _check_object(self, name):
        """Resolve one object name to (oid, type) or None if it doesn't exist."""
        try:
            with self._lock:
                oid, otype, _ = self.repo.git.get_object_header(name)
        except ValueError:
            return None
        return (oid.decode(), otype.decode())

    def _expand_tree(self, commit, path):
        """List every (relpath, blob oid) under a directory at a commit."""
        entries = []
        for record in self.repo.git.ls_tree('-r', '-z', commit, '--', path).split('\0'):
            if not record:
                continue
            meta, relpath = record.split('\t', 1)
            _, otype, oid = meta.split(' ')
            if otype == 'blob':
                entries.append((relpath, oid))
        return entries

    def sig(self, commit, paths):
        """Blob signature of the given paths at a commit: ((relpath, oid), ...).

        Paths missing at the commit are omitted, which reproduces check_cve()'s
        os.path.exists filter; directory paths expand to every blob below them.
        include/linux/kconfig.h is always probed so check_cve() finds it exactly
        when the commit has it.

        An unresolvable commit raises instead of yielding an empty signature:
        a typo'd --branch or a not-yet-fetched fix hash must fail loudly, not
        let every "assert not detected" test pass vacuously (and cache the
        vacuous verdict).
        """
        if self._check_object(f'{commit}:') is None:
            raise ValueError(f'unresolvable ref: {commit}')
        entries = {}
        for path in [*paths, KCONFIG_H]:
            obj = self._check_object(f'{commit}:{path}')
            if obj is None:
                continue
            oid, otype = obj
            if otype == 'blob':
                entries[path] = oid
            elif otype == 'tree':
                entries.update(self._expand_tree(commit, path))
        return tuple(sorted(entries.items()))

    def _fetch_blob(self, oid):
        dest = os.path.join(self.blob_dir, oid)
        if os.path.exists(dest):
            return dest
        with self._lock:
            data = self.repo.git.get_object_data(oid)[3]
        tmp = dest + f'.tmp{os.getpid()}-{threading.get_ident()}'
        with open(tmp, 'wb') as fh:
            fh.write(data)
        os.replace(tmp, dest)
        return dest

    def materialize(self, sig):
        """Return a directory holding the signature's blobs at their relpaths."""
        name = hashlib.sha256(repr(sig).encode()).hexdigest()[:16]
        tree = os.path.join(self.tree_dir, name)
        if os.path.isdir(tree):
            return tree
        tmp = os.path.join(self.tree_dir, f'.tmp{os.getpid()}-{threading.get_ident()}-{name}')
        os.makedirs(tmp, exist_ok=True)
        for relpath, oid in sig:
            blob = self._fetch_blob(oid)
            path = os.path.join(tmp, relpath)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            try:
                os.link(blob, path)
            except OSError:
                shutil.copyfile(blob, path)
        try:
            os.rename(tmp, tree)
        except OSError:
            # Another worker materialized the same signature first -- unless
            # the rename failed for a real reason (ENOSPC, permissions): then
            # re-raise rather than hand back a missing tree, which check_cve
            # would score as "not detected" and poison the persistent cache.
            shutil.rmtree(tmp, ignore_errors=True)
            if not os.path.isdir(tree):
                raise
        return tree


def sig_has_rule_files(sig):
    """True when the signature holds any rule file (not just the kconfig probe).

    Without one, check_cve() takes its "no hinted files exist" branch and the
    verdict is a vacuous False.
    """
    return any(path != KCONFIG_H for path, _ in sig)


def cached_check(hound, materializer, cache, sig, cve):
    """Bool verdict of check_cve() on a materialized signature, memoized.

    The verdict is a pure function of (rule bytes, signature) within one
    cache context (spatch + python + harness epoch), so hits skip both
    materialization and spatch. UnsupportedVersion propagates uncached.
    """
    key = None
    if cache is not None:
        key = cache.key(hound.get_rule(cve), sig)
        hit = cache.get(key)
        if hit is not None:
            return hit
    verdict = bool(hound_at(hound, materializer.materialize(sig)).check_cve(cve))
    if cache is not None:
        cache.put(key, verdict)
    return verdict


def hound_at(base, tree):
    """A shallow CVEhound copy pointed at a materialized tree.

    check_cve() derives include paths from self.kernel per call, so retargeting
    is just the attribute; the metadata and rule caches stay shared, sparing a
    spatch --version probe and metadata reload per tree.
    """
    hound = copy.copy(base)
    hound.kernel = os.path.abspath(tree)
    return hound
