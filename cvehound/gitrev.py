"""Trees at a revision, and the pure logic the git modes share.

A scan reads a handful of paths per rule, so a revision does not need a
checkout: the union of every rule's Files: (plus the Makefile that names the
version and the arch/*/Makefile that resolve_arch() probes for) is materialized
once into a temp directory from the object database, and the scanner runs on
that directory as if it were a tree. `--kernel-config` adds the Kbuild files,
which is all the Kbuild parser opens.
"""

import posixpath
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from cvehound import get_rule_cves, parse_rule_header
from cvehound.exception import GitError
from cvehound.gitrepo import GitRepo
from cvehound.oracle import BlobMaterializer, Sig, ls_tree_entries, sig_has_rule_files

# The one file every tree must have: get_kernel_version() reads it, and its
# absence is how a revision that is not a kernel is told apart.
MAKEFILE = 'Makefile'

# What the Kbuild parser opens (cvehound/kbuildparse/linux.py): per-directory
# Makefile/Kbuild files and their variants (Makefile.postlink, Kbuild.platforms),
# the .mk fragments they include, and the arch/mips/*/Platform files that
# Kbuild.platforms pulls in.
KBUILD_PREFIXES = ('Makefile', 'Kbuild')
KBUILD_SUFFIXES = ('.mk',)
KBUILD_NAMES = ('Platform',)


@dataclass(frozen=True)
class RevTree:
    """A revision the user named, resolved, and put on disk."""

    rev: str
    sha: str
    describe: str | None
    path: str

    def report(self) -> dict[str, Any]:
        return {'rev': self.rev, 'commit': self.sha, 'describe': self.describe}


def all_rule_files(rules: Mapping[str, str]) -> list[str]:
    """Every path any rule reads: the union a revision tree has to hold.

    No CVE selection happens first because none is needed -- today's rules name
    ~540 files between them, which is nothing to fetch -- and because the tree
    has to exist before the hound that selects is built.
    """
    paths: set[str] = set()
    for rule in rules.values():
        paths.update(parse_rule_header(rule)['files'])
    return sorted(paths)


def arch_makefiles(repo: GitRepo, sha: str) -> list[str]:
    """arch/<arch>/Makefile for every architecture the revision has.

    resolve_arch() decides whether an architecture exists by whether its
    directory does; a directory exists in a materialized tree when a file
    under it does, and every arch has a Makefile.
    """
    return [
        posixpath.join(relpath, MAKEFILE)
        for _, otype, _, relpath in ls_tree_entries(repo, sha, '--', 'arch/')
        if otype == 'tree'
    ]


def is_kbuild_file(relpath: str) -> bool:
    name = posixpath.basename(relpath)
    return (
        name.startswith(KBUILD_PREFIXES) or name.endswith(KBUILD_SUFFIXES) or name in KBUILD_NAMES
    )


def kbuild_paths(repo: GitRepo, sha: str) -> list[str]:
    """Every Kbuild-shaped file at the revision (~3k in a current kernel)."""
    names = repo.ls_tree('-r', '--name-only', '-z', sha).split('\0')
    return [name for name in names if name and is_kbuild_file(name)]


def tree_paths(repo: GitRepo, sha: str, with_kbuild: bool = False) -> list[str]:
    """What a scan of a tree-ish reads: every rule's files, the arch Makefiles,
    and the Kbuild files when a .config is going to be evaluated."""
    (rules, _, _) = get_rule_cves()
    paths = [*all_rule_files(rules), *arch_makefiles(repo, sha)]
    if with_kbuild:
        paths.extend(kbuild_paths(repo, sha))
    return paths


def materialize_tree(
    materializer: BlobMaterializer,
    repo: GitRepo,
    label: str,
    sha: str,
    paths: Iterable[str] | None = None,
) -> RevTree:
    """Put a resolved tree-ish on disk -- tree_paths() by default -- and error
    out on a non-kernel. `sha` may be a commit or a bare tree (a --patch result)."""
    if paths is None:
        paths = tree_paths(repo, sha)
    sig = materializer.sig(sha, [MAKEFILE, *paths])
    if MAKEFILE not in dict(sig):
        raise GitError(f'{label} is not a kernel tree (no Makefile at {sha[:12]})')
    return RevTree(label, sha, repo.describe(sha), materializer.materialize(sig))


class ChangedFiles:
    """The paths a change touched, indexed for the question a rule asks: does
    any of my Files: name a changed file, or a directory one is under?"""

    def __init__(self, paths: Iterable[str]) -> None:
        self.files = set(paths)
        self.dirs: set[str] = set()
        for path in self.files:
            while path := posixpath.dirname(path):
                self.dirs.add(path)

    def touches(self, rule_files: Iterable[str]) -> bool:
        return any(f in self.files or f.rstrip('/') in self.dirs for f in rule_files)


FIXED = 'fixed'
INTRODUCED = 'introduced'
STILL_VULNERABLE = 'still-vulnerable'
UNAFFECTED = 'unaffected'


def classify(at_from: bool, at_to: bool) -> str:
    """What a change did to a rule's verdict between its two ends."""
    if at_from and not at_to:
        return FIXED
    if at_to and not at_from:
        return INTRODUCED
    if at_from:
        return STILL_VULNERABLE
    return UNAFFECTED


def first_flip(verdicts: list[bool]) -> int | None:
    """Index of the first verdict that differs from the first one, or None."""
    for i, verdict in enumerate(verdicts):
        if verdict != verdicts[0]:
            return i
    return None


def head_info(repo: GitRepo) -> dict[str, Any]:
    """What a checkout is at, for the report: commit, describe, dirty.

    Best effort and pre-sandbox only (`git status` refreshes the index): a
    repository git cannot answer for contributes nothing, and the scan itself
    is unaffected either way.
    """
    try:
        sha = repo.rev_parse('HEAD')
        return {'commit': sha, 'describe': repo.describe(sha), 'dirty': repo.is_dirty()}
    except GitError:
        return {}


def walk(repo: GitRepo, sha_from: str, sha_to: str, files: Iterable[str]) -> list[str]:
    """Both ends and every commit between them that touches the files, oldest
    first, each once: the end is listed by the log when it touches them."""
    commits = [sha_from, *repo.log_commits(sha_from, sha_to, files)]
    if commits[-1] != sha_to:
        commits.append(sha_to)
    return commits


def signed_walk(
    repo: GitRepo,
    materializer: BlobMaterializer,
    sha_from: str,
    sha_to: str,
    files: Iterable[str],
) -> list[tuple[str, Sig]]:
    """walk(), with each commit's signature of the files: what a verdict there
    is a function of."""
    files = list(files)
    return [(c, materializer.sig(c, files)) for c in walk(repo, sha_from, sha_to, files)]


def materialize_present(materializer: BlobMaterializer, sigs: Iterable[Sig]) -> dict[Sig, str]:
    """A directory per distinct signature that holds a rule file. One without
    gets none: the rule cannot run there, and a False from it would be vacuous."""
    return {
        sig: materializer.materialize(sig) for sig in dict.fromkeys(sigs) if sig_has_rule_files(sig)
    }


def collapse_steps(commits: Iterable[tuple[str, Sig]]) -> list[tuple[Sig, list[str]]]:
    """Runs of consecutive commits with the same signature, in order.

    A rule's verdict is a function of the blobs it reads, so commits that
    leave those blobs alone cannot move it: one spatch run answers for the
    whole run of them.
    """
    steps: list[tuple[Sig, list[str]]] = []
    for commit, sig in commits:
        if steps and steps[-1][0] == sig:
            steps[-1][1].append(commit)
        else:
            steps.append((sig, [commit]))
    return steps


def find_flip(steps: int, verdict: Callable[[int], bool]) -> int | None:
    """Index of the first step whose verdict differs from step 0's, found by
    bisection, or None when the two ends agree.

    Assumes one flip between the ends, as bisection must; a history that flips
    back and forth yields one of its flips, which is still a true one.
    """
    if steps < 2:
        return None
    first = verdict(0)
    if verdict(steps - 1) == first:
        return None
    lo, hi = 0, steps - 1
    while hi - lo > 1:
        mid = (lo + hi) // 2
        if verdict(mid) == first:
            lo = mid
        else:
            hi = mid
    return hi
