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

# The relpath half of a whole-tree signature. It is not a path any tree holds,
# which is the point: it can never collide with a materialized mini-tree's
# signature, so both kinds of verdict share one cache namespace safely.
ALL_FILES_PATH = '<all-files>'


def object_header(repo, name):
    """Resolve one object name to (oid, type), or None when it does not exist.

    Over GitPython's persistent `cat-file --batch-check` process, so a caller
    that asks thousands of times pays ~9us each instead of a fork. The quirk
    worth having in one place: a name that resolves to nothing raises
    ValueError here, where the one-shot `git rev-parse` raised GitCommandError.
    """
    try:
        oid, otype, _ = repo.git.get_object_header(name)
    except ValueError:
        return None
    return (oid.decode(), otype.decode())


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
        """object_header() under the lock this instance's stream needs."""
        with self._lock:
            return object_header(self.repo, name)

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

    def whole_tree_sig(self, commit):
        """Signature of every file at a commit: its root tree oid names them all.

        An --all-files scan reads the tree rather than a materialized handful,
        so one entry says everything about what spatch will see -- given that
        the tree on disk is a clean checkout of this commit and not a built one,
        which is what --detach --force worktrees and _reset_worktree guarantee.

        Raises on an unresolvable ref for the reason sig() does: a vacuous
        signature would let every "assert not detected" test pass, and cache
        that.
        """
        obj = self._check_object(f'{commit}^{{tree}}')
        if obj is None:
            raise ValueError(f'unresolvable ref: {commit}')
        return ((ALL_FILES_PATH, obj[0]),)

    def _fetch_blob(self, oid):
        dest = os.path.join(self.blob_dir, oid)
        if os.path.exists(dest):
            return dest
        with self._lock:
            data = self.repo.git.get_object_data(oid)[3]
        tmp = dest + f'.tmp{os.getpid()}-{threading.get_ident()}'
        with open(tmp, 'wb') as fh:
            fh.write(data)
        # Publish write-once: os.replace() would swap the inode at dest when a
        # second worker misses on the same oid, orphaning the copy that trees
        # already hardlinked and quietly ending the sharing.
        try:
            os.link(tmp, dest)
        except FileExistsError:
            pass
        except OSError:
            # No hardlinks on this filesystem; materialize() copies here anyway.
            os.replace(tmp, dest)
            return dest
        os.unlink(tmp)
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


def _memoized(cache, rule_path, sig, run):
    """run()'s bool verdict, memoized under (rule bytes, signature).

    `run` is a thunk so that everything a hit exists to skip -- materializing a
    tree, checking a branch out, spatch itself -- stays behind the lookup. A
    None cache (--no-result-cache) runs unconditionally and stores nothing;
    anything run() raises propagates uncached, which is what keeps a timed-out
    or unsupported check from being remembered as a verdict.
    """
    if cache is None:
        return bool(run())
    key = cache.key(rule_path, sig)
    hit = cache.get(key)
    if hit is None:
        hit = bool(run())
        cache.put(key, hit)
    return hit


def cached_check(hound, materializer, cache, sig, cve):
    """Bool verdict of check_cve() on a materialized signature, memoized.

    The verdict is a pure function of (rule bytes, signature) within one
    cache context (which spatch + python + harness epoch), so hits skip both
    materialization and spatch. UnsupportedVersion propagates uncached.
    """
    return _memoized(
        cache,
        hound.get_rule(cve),
        sig,
        lambda: hound_at(hound, materializer.materialize(sig)).check_cve(cve),
    )


def cached_all_files_check(hound, at_tree, cache, sig, cve, jobs):
    """Bool verdict of an all_files check over a whole tree, memoized.

    A whole-tree verdict is as pure as a mini-tree one -- a function of (rule
    bytes, tree content) -- and whole_tree_sig() names the content, so it keys
    the same cache through the same signature shape.

    Two hounds because they cost different amounts: `hound` answers the key,
    since get_rule() is the same dict lookup whatever tree it points at, while
    `at_tree` is called only on a miss -- putting a branch's tree on disk is a
    ~95k-file checkout in the shared-tree fallback, and that is precisely what a
    hit is for.

    `jobs` is not part of the key: it is spatch's -j, which changes how the scan
    is scheduled and never what it finds.
    """
    return _memoized(
        cache,
        hound.get_rule(cve),
        sig,
        lambda: at_tree().check_cve(cve, True, jobs=jobs),
    )


def hound_at(base, tree):
    """A shallow CVEhound copy pointed at a materialized tree.

    check_cve() derives include paths from self.kernel per call, so retargeting
    is just the attribute; the metadata and rule caches stay shared, sparing a
    spatch --version probe and metadata reload per tree.
    """
    hound = copy.copy(base)
    hound.kernel = os.path.abspath(tree)
    return hound
