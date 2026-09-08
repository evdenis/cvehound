#!/usr/bin/env python3

"""The pieces the git modes are built from, on a synthetic repository.

Tree production (what --rev puts on disk), the toy rule the other git-mode
tests rely on, and the pure classification helpers.
"""

import os

import pytest
from conftest import FIXED_C, UPSTREAM_FIX, VULNERABLE_C, MiniRepo

from cvehound import CVEhound, get_rule_cves
from cvehound.cli.common import rule_touches
from cvehound.exception import GitError
from cvehound.gitevidence import (
    FIX_ABSENT,
    FIX_PRESENT,
    FIX_REVERTED,
    MAX_SHARED_ORIGIN,
    UNKNOWN,
    commit_table,
    finding_fixes,
    fix_evidence,
    prune_unintroduced,
    range_evidence,
)
from cvehound.gitrepo import GitRepo
from cvehound.gitrev import (
    ChangedFiles,
    all_rule_files,
    arch_makefiles,
    classify,
    collapse_steps,
    find_flip,
    first_flip,
    head_info,
    is_kbuild_file,
    kbuild_paths,
    materialize_present,
    materialize_tree,
    signed_walk,
    walk,
)
from cvehound.oracle import BlobMaterializer, hound_at

CVE = 'CVE-2099-0001'
FOO = 'drivers/foo/foo.c'
BAR = 'drivers/foo/bar.c'


@pytest.fixture
def repo(mini_repo):
    with GitRepo(mini_repo.path) as repo:
        yield repo


@pytest.fixture
def materializer(repo, tmp_path):
    return BlobMaterializer(repo, str(tmp_path / 'store'))


@pytest.fixture
def toy_hound(mini_repo, toy_rule):
    """A scanner rooted at the synthetic checkout, knowing only the toy rule
    on top of the shipped set."""
    hound = CVEhound(mini_repo.path)
    hound.add_rule(CVE, toy_rule)
    return hound


def test_all_rule_files_is_the_union_of_every_header():
    (rules, _, _) = get_rule_cves()
    files = all_rule_files(rules)
    assert len(files) > 400
    assert files == sorted(set(files))
    assert all(os.path.splitext(f)[1] for f in files), 'a directory in Files: would be news'


def test_arch_makefiles(repo, mini_repo):
    assert arch_makefiles(repo, mini_repo.commits[0]) == ['arch/x86/Makefile']


@pytest.mark.parametrize(
    ('path', 'expected'),
    [
        ('Makefile', True),
        ('drivers/foo/Kbuild', True),
        ('arch/mips/Kbuild.platforms', True),
        ('arch/powerpc/Makefile.postlink', True),
        ('tools/testing/selftests/lib.mk', True),
        ('arch/mips/ath79/Platform', True),
        ('drivers/foo/foo.c', False),
        ('drivers/foo/Kconfig', False),
        ('Documentation/Makefile.txt', True),
    ],
)
def test_is_kbuild_file(path, expected):
    assert is_kbuild_file(path) is expected


def test_kbuild_paths(repo, mini_repo):
    assert kbuild_paths(repo, mini_repo.commits[0]) == [
        'Kbuild',
        'Makefile',
        'arch/x86/Makefile',
        'drivers/foo/Makefile',
    ]


def test_materialize_tree_puts_the_paths_and_the_makefile_on_disk(repo, materializer, mini_repo):
    sha = mini_repo.commits[0]
    tree = materialize_tree(materializer, repo, 'v6.1', sha, [FOO, BAR, 'arch/x86/Makefile'])
    assert tree.rev == 'v6.1'
    assert tree.sha == mini_repo.commits[0]
    assert tree.describe == 'v6.1'
    assert os.path.isfile(os.path.join(tree.path, 'Makefile'))
    assert os.path.isdir(os.path.join(tree.path, 'arch', 'x86'))
    with open(os.path.join(tree.path, FOO)) as fh:
        assert fh.read() == VULNERABLE_C
    assert not os.path.exists(os.path.join(tree.path, BAR))


def test_materialize_tree_refuses_a_revision_without_a_makefile(repo, materializer, mini_repo):
    sha = mini_repo.commit({'Makefile': None}, 'not a kernel any more')
    with pytest.raises(GitError, match='not a kernel tree'):
        materialize_tree(materializer, repo, 'main', sha, [FOO])


def test_materialize_tree_defaults_to_what_a_scan_reads(repo, materializer, mini_repo):
    """No paths given: every rule's files plus the arch Makefiles, which is
    what a tree needs for the scanner to accept it as a kernel."""
    tree = materialize_tree(materializer, repo, 'v6.1', mini_repo.commits[0])
    assert os.path.isfile(os.path.join(tree.path, 'Makefile'))
    assert os.path.isdir(os.path.join(tree.path, 'arch', 'x86'))
    assert not os.path.exists(os.path.join(tree.path, FOO)), 'no shipped rule names it'


def test_changed_files_matches_files_and_the_directories_above_them():
    changed = ChangedFiles(['drivers/foo/foo.c', 'net/ipv4/tcp.c'])
    assert changed.touches(['drivers/foo/foo.c'])
    assert changed.touches(['include/x.h', 'net/ipv4/tcp.c'])
    assert changed.touches(['drivers/foo']), 'a directory in Files: covers files under it'
    assert changed.touches(['net/'])
    assert not changed.touches(['drivers/foo/foo.cc']), 'a prefix of a name is not the name'
    assert not changed.touches(['drivers/bar/bar.c'])
    assert not changed.touches([])
    assert not ChangedFiles([]).touches(['drivers/foo/foo.c'])


def test_head_info(repo, mini_repo):
    info = head_info(repo)
    assert info['commit'] == mini_repo.commits[2]
    assert info['describe'].startswith('v6.1.1-1-g')
    assert info['dirty'] is False


def test_toy_rule_fires_on_the_vulnerable_tree_only(toy_hound, materializer, mini_repo):
    """What every diff/bisect test below leans on: the toy rule tells the two
    bodies apart, through the same materialize + hound_at path the CLI uses."""
    vuln, fix, rename = mini_repo.commits
    files = toy_hound.get_rule_files(CVE)
    assert files == [FOO, BAR]
    at = {sha: materializer.materialize(materializer.sig(sha, files)) for sha in mini_repo.commits}
    assert hound_at(toy_hound, at[vuln]).check_cve(CVE)
    assert not hound_at(toy_hound, at[fix]).check_cve(CVE)
    assert not hound_at(toy_hound, at[rename]).check_cve(CVE)
    with open(os.path.join(at[rename], BAR)) as fh:
        assert fh.read() == FIXED_C


# --- the pure helpers diff and bisect classify with ----------------------------


@pytest.mark.parametrize(
    ('at_from', 'at_to', 'status'),
    [
        (True, False, 'fixed'),
        (False, True, 'introduced'),
        (True, True, 'still-vulnerable'),
        (False, False, 'unaffected'),
    ],
)
def test_classify(at_from, at_to, status):
    assert classify(at_from, at_to) == status


def test_first_flip():
    assert first_flip([True, True, False, False]) == 2
    assert first_flip([False, True]) == 1
    assert first_flip([True, True]) is None
    assert first_flip([True]) is None


def test_rule_touches_is_prefix_matching():
    assert rule_touches(['drivers/foo/foo.c'], ['drivers/foo/foo.c'])
    assert rule_touches(['drivers/foo/foo.c'], ['drivers/foo'])
    assert rule_touches(['drivers/foo/foo.c', 'include/x.h'], ['include/'])
    assert not rule_touches(['drivers/foo/foo.c'], ['drivers/bar'])
    assert not rule_touches([], ['drivers'])


# --- what commit messages say --------------------------------------------------

METADATA = {
    'CVE-2099-0001': {'fixes': UPSTREAM_FIX, 'breaks': 'a' * 40},
    'CVE-2099-0002': {'fixes': 'b' * 40, 'breaks': 'c' * 40},
    'CVE-2099-0003': {'fixes': 'd' * 40, 'breaks': 'c' * 40},
    'CVE-2099-0004': {'breaks': 'e' * 40},
}


def test_range_evidence_matches_fix_and_introducing_commits_by_sha():
    ev = range_evidence([(UPSTREAM_FIX, 'anything'), ('c' * 40, 'anything')], METADATA)
    assert ev.fixes == {'CVE-2099-0001': [UPSTREAM_FIX]}
    assert ev.introduces == {'CVE-2099-0002': ['c' * 40], 'CVE-2099-0003': ['c' * 40]}
    assert ev.backports == {} and ev.candidates == {}


def test_range_evidence_reads_upstream_citations_as_backports():
    sha = '1' * 40
    for spelling in (
        f'commit {UPSTREAM_FIX} upstream.',
        f'[ Upstream commit {UPSTREAM_FIX[:12]} ]',
        f'(cherry picked from commit {UPSTREAM_FIX})',
    ):
        ev = range_evidence([(sha, f'foo: fix\n\n{spelling}\n')], METADATA)
        assert ev.backports == {'CVE-2099-0001': [sha]}, spelling
        assert ev.fixes == {}


def test_range_evidence_reads_fixes_trailers_as_candidates_only():
    sha = '2' * 40
    ev = range_evidence([(sha, f'foo: fix\n\nFixes: {"e" * 12} ("x")\n')], METADATA)
    assert ev.candidates == {'CVE-2099-0004': [sha]}
    assert ev.backports == {} and ev.fixes == {}
    # A Fixes: trailer naming a known *fix* is not a backport of it.
    ev = range_evidence([(sha, f'foo: fix\n\nFixes: {UPSTREAM_FIX[:12]} ("x")\n')], METADATA)
    assert ev.backports == {} and ev.candidates == {}


def test_range_evidence_drops_a_candidate_the_commit_already_answers_for():
    """A fix naming the bug's origin in its own Fixes: trailer is the normal
    shape of a fix, not a second, weaker piece of evidence about it."""
    trailer = f'foo: fix\n\nFixes: {"a" * 12} ("x")\n'
    ev = range_evidence([(UPSTREAM_FIX, trailer)], METADATA)
    assert ev.fixes == {'CVE-2099-0001': [UPSTREAM_FIX]}
    assert ev.candidates == {}
    # Another commit carrying only the trailer is the case that says something.
    other = '9' * 40
    ev = range_evidence([(UPSTREAM_FIX, trailer), (other, trailer)], METADATA)
    assert ev.candidates == {'CVE-2099-0001': [other]}


def test_range_evidence_ignores_an_origin_shared_by_many_cves():
    shared = {f'CVE-2099-{i:04d}': {'breaks': 'f' * 40} for i in range(MAX_SHARED_ORIGIN + 1)}
    ev = range_evidence([('3' * 40, f'Fixes: {"f" * 12} ("initial")')], shared)
    assert ev.candidates == {}
    few = dict(list(shared.items())[:MAX_SHARED_ORIGIN])
    ev = range_evidence([('3' * 40, f'Fixes: {"f" * 12} ("initial")')], few)
    assert len(ev.candidates) == MAX_SHARED_ORIGIN


def test_range_evidence_summary_and_report():
    ev = range_evidence([(UPSTREAM_FIX, 'x')], METADATA)
    assert ev.summary() == '1 CVE fix'
    assert ev.report()['fixes'] == {'CVE-2099-0001': [UPSTREAM_FIX]}
    assert range_evidence([], METADATA).summary() == 'nothing known'


def test_range_evidence_on_the_synthetic_history(repo, mini_repo):
    """The backport in mini_repo cites UPSTREAM_FIX; its Fixes: trailer names
    the initial commit, which is the CVE's origin here."""
    vuln, fix, rename = mini_repo.commits
    metadata = {'CVE-2099-0001': {'fixes': UPSTREAM_FIX, 'breaks': vuln}}
    ev = range_evidence(repo.log_messages(f'{vuln}..{rename}'), metadata)
    assert ev.backports == {'CVE-2099-0001': [fix]}
    # The same commit, already recorded as carrying the fix: counting it again
    # as a candidate would read as two commits doing two things.
    assert ev.candidates == {}
    assert ev.fixes == {} and ev.introduces == {}


def test_commit_table_lets_the_rule_header_win(toy_hound, mini_repo):
    vuln, fix, _ = mini_repo.commits
    table = commit_table(toy_hound)
    assert table[CVE] == {'fixes': fix, 'breaks': vuln}
    # A shipped rule whose header and metadata agree is in the table once, and a
    # metadata-only CVE keeps the metadata's commits.
    assert len(table) >= len(toy_hound.metadata)
    metadata_only = next(c for c in toy_hound.metadata if c not in toy_hound.get_all_cves())
    assert table.get(metadata_only, {}).get('fixes') == toy_hound.metadata[metadata_only].get(
        'fixes'
    )


# --- where a finding's fix stands in history -----------------------------------


def test_fix_evidence_present_when_the_fix_is_an_ancestor(repo, mini_repo):
    vuln, fix, rename = mini_repo.commits
    ev = fix_evidence(repo, rename, {CVE: (fix, None)})[CVE]
    assert ev.in_history is True
    assert ev.verdict == FIX_PRESENT
    assert ev.backports == () and ev.reverted_by is None
    assert 'in history as' in ev.describe() and 'regression' in ev.describe()


def test_fix_evidence_absent_when_the_fix_is_known_but_not_reached(repo, mini_repo):
    vuln, fix, _ = mini_repo.commits
    ev = fix_evidence(repo, vuln, {CVE: (fix, None)})[CVE]
    assert ev.in_history is False
    assert ev.verdict == FIX_ABSENT
    assert ev.describe() == FIX_ABSENT


def test_fix_evidence_finds_a_backport_of_an_upstream_fix_not_in_the_repository(repo, mini_repo):
    vuln, fix, rename = mini_repo.commits
    ev = fix_evidence(repo, rename, {CVE: (UPSTREAM_FIX, None)})[CVE]
    assert ev.in_history is None, 'the upstream commit itself is not in this repository'
    assert ev.backports == (fix,)
    assert ev.verdict == FIX_PRESENT
    assert 'backported as ' + fix[:12] in ev.describe()


def test_fix_evidence_unknown_before_the_backport(repo, mini_repo):
    vuln, _, _ = mini_repo.commits
    ev = fix_evidence(repo, vuln, {CVE: (UPSTREAM_FIX, None)})[CVE]
    assert ev.verdict == UNKNOWN
    assert 'not in this repository' in ev.describe()


def test_fix_evidence_reports_a_reverted_fix(repo, mini_repo):
    vuln, fix, _ = mini_repo.commits
    revert = mini_repo.commit(
        {'drivers/foo/bar.c': VULNERABLE_C},
        f'Revert "foo: check the pointer"\n\nThis reverts commit {fix}.\n',
    )
    ev = fix_evidence(repo, revert, {CVE: (fix, None)})[CVE]
    assert ev.in_history is True
    assert ev.reverted_by == revert
    assert ev.verdict == FIX_REVERTED
    assert ev.describe() == f'{FIX_REVERTED} (by {revert[:12]})'


def test_fix_evidence_ignores_fixes_trailers(repo, mini_repo):
    """The backport's 'Fixes: <vuln>' trailer names the origin, not a fix of it."""
    vuln, _, rename = mini_repo.commits
    ev = fix_evidence(repo, rename, {'CVE-2099-0009': (vuln, None)})['CVE-2099-0009']
    assert ev.backports == ()
    assert ev.in_history is True  # vuln is an ancestor; that alone makes it present


def test_fix_evidence_bounds_the_walk_by_the_oldest_fix_date(repo, mini_repo):
    """A since bound is only applied when every finding has a date, and a
    backport cannot predate its upstream fix, so the bound never hides one."""
    vuln, fix, rename = mini_repo.commits
    # 2024-01-02T00:00:00Z is the backport's own timestamp (MiniRepo.commit).
    at_fix = 1704153600
    ev = fix_evidence(repo, rename, {CVE: (UPSTREAM_FIX, at_fix)})[CVE]
    assert ev.backports == (fix,)
    ev = fix_evidence(repo, rename, {CVE: (UPSTREAM_FIX, at_fix + 86400 * 5)})[CVE]
    assert ev.backports == (), 'a fix dated after the backport bounds it out'


def test_fix_evidence_with_nothing_to_ask(repo, mini_repo):
    assert fix_evidence(repo, mini_repo.commits[0], {}) == {}


def test_finding_fixes_reads_the_rule_header_and_the_metadata_date(toy_hound, mini_repo):
    _, fix, _ = mini_repo.commits
    findings = finding_fixes(toy_hound, [CVE, 'CVE-0000-0000'])
    assert findings == {CVE: (fix, None)}
    dated = next(c for c, i in toy_hound.metadata.items() if i.get('fixes') and i.get('fix_date'))
    assert finding_fixes(toy_hound, [dated])[dated] == (
        toy_hound.metadata[dated]['fixes'],
        int(toy_hound.metadata[dated]['fix_date']),
    )


def test_prune_unintroduced_only_on_proof(repo, toy_hound, mini_repo):
    vuln, fix, rename = mini_repo.commits
    # The toy rule's Fixes: is the first commit, an ancestor of everything: kept.
    kept, skipped = prune_unintroduced(repo, toy_hound, [CVE], rename)
    assert kept == [CVE] and skipped == {}
    # A CVE introduced by a commit that is not in this history at all: kept
    # (unknown is not proof), which is what makes the flag safe on vendor trees.
    other = next(c for c, i in toy_hound.metadata.items() if len(i.get('breaks', '')) == 40)
    kept, skipped = prune_unintroduced(repo, toy_hound, [other], rename)
    assert kept == [other]
    # Introduced by a commit that exists here but does not reach the revision: pruned.
    side = MiniRepo(mini_repo.path)  # same repository, a second handle
    side.git('checkout', '-q', '-b', 'side', vuln)
    origin = side.commit({'drivers/foo/other.c': 'int x;\n'}, 'side: introduce')
    toy_hound.metadata['CVE-2099-0002'] = {'breaks': origin, 'fixes': 'f' * 40}
    kept, skipped = prune_unintroduced(repo, toy_hound, [CVE, 'CVE-2099-0002'], rename)
    assert kept == [CVE]
    assert list(skipped) == ['CVE-2099-0002'] and origin[:12] in skipped['CVE-2099-0002']


# --- what bisect walks and how it searches ------------------------------------


def test_collapse_steps_merges_runs_of_identical_content():
    a, b = (('f', '1'),), (('f', '2'),)
    steps = collapse_steps([('c1', a), ('c2', a), ('c3', b), ('c4', a), ('c5', a)])
    assert steps == [(a, ['c1', 'c2']), (b, ['c3']), (a, ['c4', 'c5'])]
    assert collapse_steps([]) == []


def test_find_flip_bisects_to_the_first_differing_step():
    calls = []

    def verdict(seq):
        def at(i):
            calls.append(i)
            return seq[i]

        return at

    seq = [True] * 40 + [False] * 24
    assert find_flip(len(seq), verdict(seq)) == 40
    assert len(calls) <= 2 + 7, 'log2(64) plus the two ends'
    assert find_flip(2, verdict([False, True])) == 1
    assert find_flip(3, verdict([True, True, True])) is None
    assert find_flip(1, verdict([True])) is None
    assert find_flip(0, verdict([])) is None


def test_bisect_over_the_synthetic_history(repo, toy_hound, materializer, mini_repo):
    """collapse + find_flip + the materializer name the fix on mini_repo."""
    vuln, fix, rename = mini_repo.commits
    files = toy_hound.get_rule_files(CVE)
    assert walk(repo, vuln, rename, files) == [vuln, fix, rename]
    assert walk(repo, vuln, fix, files) == [vuln, fix]
    assert walk(repo, vuln, vuln, files) == [vuln]
    commits = signed_walk(repo, materializer, vuln, rename, files)
    assert [c for c, _ in commits] == [vuln, fix, rename]
    steps = collapse_steps(commits)
    trees = materialize_present(materializer, (sig for sig, _ in steps))
    assert len(trees) == 3
    assert materialize_present(materializer, [materializer.sig(vuln, ['nope.c'])]) == {}
    assert [cs for _, cs in steps] == [[vuln], [fix], [rename]]

    def verdict(i):
        return bool(hound_at(toy_hound, materializer.materialize(steps[i][0])).check_cve(CVE))

    assert steps[find_flip(len(steps), verdict)][1] == [fix]
