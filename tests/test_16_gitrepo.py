#!/usr/bin/env python3

"""GitRepo, the subprocess object reader the CLI's git modes run on.

Everything here runs on a synthetic repository, so it is independent of the
kernel checkout; the last test proves the materializer behaves over GitRepo the
way test_12 shows it does over GitPython.
"""

import os
import subprocess

import pytest
from conftest import UPSTREAM_FIX, VULNERABLE_C, MiniRepo

from cvehound import KCONFIG_H
from cvehound.exception import GitError
from cvehound.gitrepo import GitRepo
from cvehound.oracle import BlobMaterializer, object_header

FOO = 'drivers/foo/foo.c'
BAR = 'drivers/foo/bar.c'


@pytest.fixture
def repo(mini_repo):
    with GitRepo(mini_repo.path) as repo:
        yield repo


def test_rejects_a_directory_that_is_not_a_repository(tmp_path):
    with pytest.raises(GitError, match='not a git repository'):
        GitRepo(str(tmp_path))


def test_rejects_a_subdirectory_of_the_repository(mini_repo):
    """Blobs are addressed as SHA:relpath from the root; anything else would
    resolve every Files: entry against the wrong prefix."""
    with pytest.raises(GitError, match='pass the root'):
        GitRepo(os.path.join(mini_repo.path, 'drivers'))


def test_toplevel_and_git_dir_are_resolved(repo, mini_repo):
    assert repo.toplevel == os.path.realpath(mini_repo.path)
    assert repo.git_dir == os.path.realpath(os.path.join(mini_repo.path, '.git'))


def test_header_and_data_over_the_batch_pipes(repo, mini_repo):
    vuln = mini_repo.commits[0]
    oid, otype, size = repo.get_object_header(f'{vuln}:{FOO}')
    assert otype == 'blob'
    assert size == len(VULNERABLE_C.encode())
    assert repo.get_object_data(f'{vuln}:{FOO}') == (oid, 'blob', size, VULNERABLE_C.encode())
    assert repo.get_object_header(f'{vuln}:')[1] == 'tree'
    # A second question on the same pipe: the trailing LF was consumed.
    assert repo.get_object_data(f'{vuln}:Makefile')[1] == 'blob'


def test_missing_object_raises_value_error_like_gitpython(repo, mini_repo):
    vuln = mini_repo.commits[0]
    with pytest.raises(ValueError, match='missing'):
        repo.get_object_header(f'{vuln}:does/not/exist.c')
    with pytest.raises(ValueError, match='missing'):
        repo.get_object_data(f'{vuln}:does/not/exist.c')
    assert object_header(repo, f'{vuln}:does/not/exist.c') is None
    assert object_header(repo, f'{vuln}:{FOO}') is not None


def test_ls_tree(repo, mini_repo):
    out = repo.ls_tree('-r', '--name-only', mini_repo.commits[0], '--', 'drivers')
    assert out.split() == ['drivers/foo/Makefile', FOO]


def test_rev_parse(repo, mini_repo):
    assert repo.rev_parse('v6.1') == mini_repo.commits[0]
    assert repo.rev_parse('v6.1.1~') == mini_repo.commits[0]
    with pytest.raises(GitError, match='unknown revision'):
        repo.rev_parse('v9.9')


def test_describe(repo, mini_repo):
    assert repo.describe(mini_repo.commits[0]) == 'v6.1'
    assert repo.describe(mini_repo.commits[1]) == 'v6.1.1'
    assert repo.describe(mini_repo.commits[2]).startswith('v6.1.1-1-g')


def test_describe_without_a_tag_is_none(tmp_path):
    bare = MiniRepo(tmp_path / 'untagged')
    sha = bare.commit({'Makefile': ''}, 'only')
    assert GitRepo(bare.path).describe(sha) is None


def test_is_dirty(repo, mini_repo):
    assert not repo.is_dirty()
    with open(os.path.join(mini_repo.path, 'Makefile'), 'a') as fh:
        fh.write('# local\n')
    assert repo.is_dirty()


def test_diff_names_lists_both_ends_of_a_rename(repo, mini_repo):
    assert repo.diff_names(mini_repo.commits[1], mini_repo.commits[2]) == [BAR, FOO]
    assert repo.diff_names(mini_repo.commits[0], mini_repo.commits[1]) == [FOO]


def test_log_commits_touching_paths(repo, mini_repo):
    vuln, fix, rename = mini_repo.commits
    assert repo.log_commits(vuln, rename, [FOO]) == [fix, rename]
    assert repo.log_commits(vuln, rename, ['Makefile']) == []


def test_log_commits_does_not_list_a_merge_that_only_carried_the_change(repo, mini_repo):
    """A merge that took the file from one side did not change it.

    git says so by default; --ancestry-path would turn that simplification off
    and list every merge whose diff touches the path -- measured on
    net/ipv4/inet_fragment.c across a year of kernel history, 848 commits for a
    file with 13 contents.
    """
    vuln, fix, _ = mini_repo.commits
    mini_repo.git('checkout', '-q', '-b', 'side', fix)
    side = mini_repo.commit({FOO: VULNERABLE_C}, 'foo: bring the bug back on a side branch')
    mini_repo.git('checkout', '-q', '-b', 'topic', fix)
    mini_repo.commit({'drivers/foo/README': 'unrelated\n'}, 'foo: document it')
    mini_repo.git('merge', '-q', '--no-ff', '-m', 'Merge side into topic', side)
    merge = mini_repo.git('rev-parse', 'HEAD').strip()

    walked = repo.log_commits(vuln, merge, [FOO])
    assert walked == [fix, side]
    assert merge not in walked


def test_log_messages_grep_is_a_fixed_string_or(repo, mini_repo):
    found = list(repo.log_messages('main', grep=[UPSTREAM_FIX[:12], 'no-such-needle']))
    assert [sha for sha, _ in found] == [mini_repo.commits[1]]
    assert 'upstream' in found[0][1]
    assert list(repo.log_messages('main', grep=['no-such-needle'])) == []
    assert len(list(repo.log_messages('main'))) == 3


def test_log_messages_streams_and_reports_a_failing_walk(repo, mini_repo):
    """Records come out whole whatever the chunking, and a bad revision is a
    GitError at the end of the stream rather than an empty answer."""
    messages = dict(repo.log_messages('main'))
    assert set(messages) == set(mini_repo.commits)
    assert messages[mini_repo.commits[1]].startswith('foo: check the pointer\n')
    with pytest.raises(GitError):
        list(repo.log_messages('no-such-rev'))


def test_log_messages_since_bounds_the_walk(repo, mini_repo):
    # Commits are dated 2024-01-01, -02, -03 (MiniRepo.commit).
    assert len(list(repo.log_messages('main', since='2024-01-01T12:00:00+0000'))) == 2


def test_reachable_answers_for_many_prefixes_in_one_walk(repo, mini_repo):
    vuln, fix, rename = mini_repo.commits
    wanted = {vuln[:12], rename[:12], 'f' * 12}
    assert repo.reachable(fix, wanted) == {vuln[:12]}
    assert repo.reachable(rename, wanted) == {vuln[:12], rename[:12]}
    assert repo.reachable(vuln, set()) == set()


def test_has_commit(repo, mini_repo):
    assert repo.has_commit(mini_repo.commits[0])
    assert repo.has_commit('v6.1')
    assert not repo.has_commit('f' * 40)
    assert not repo.has_commit(f'{mini_repo.commits[0]}:Makefile')


def test_commit_subject(repo, mini_repo):
    assert repo.commit_subject(mini_repo.commits[1]).endswith(' foo: check the pointer')


def test_is_ancestor_three_ways(repo, mini_repo):
    vuln, fix, _ = mini_repo.commits
    assert repo.is_ancestor(vuln, fix) is True
    assert repo.is_ancestor(fix, vuln) is False
    assert repo.is_ancestor('0' * 40, fix) is None
    assert repo.is_ancestor(fix, 'f' * 40) is None


def test_patch_tree_builds_the_tree_without_touching_the_checkout(repo, mini_repo):
    vuln, fix, _ = mini_repo.commits
    patch = repo.run('diff', vuln, fix).encode()
    head_before = mini_repo.git('rev-parse', 'HEAD')
    assert repo.patch_tree(vuln, patch) == repo.run('rev-parse', f'{fix}^{{tree}}').strip()
    assert mini_repo.git('rev-parse', 'HEAD') == head_before
    assert mini_repo.git('status', '--porcelain') == ''


def test_patch_tree_reports_a_patch_that_does_not_apply(repo, mini_repo):
    vuln, fix, _ = mini_repo.commits
    patch = repo.run('diff', vuln, fix).encode()
    with pytest.raises(GitError, match='does not apply'):
        repo.patch_tree(fix, patch)


def test_alternates_names_a_borrowed_object_store(mini_repo, tmp_path):
    shared = str(tmp_path / 'shared')
    subprocess.run(
        ['git', 'clone', '-q', '--shared', mini_repo.path, shared],
        check=True,
        env=mini_repo.env,
    )
    assert GitRepo(shared).alternates() == [
        os.path.realpath(os.path.join(mini_repo.path, '.git', 'objects'))
    ]
    assert GitRepo(mini_repo.path).alternates() == []


def test_close_reaps_the_pipes_and_they_reopen_on_demand(repo, mini_repo):
    repo.get_object_header('HEAD:Makefile')
    repo.get_object_data('HEAD:Makefile')
    pipes = list(repo._pipes.values())
    assert len(pipes) == 2
    repo.close()
    assert all(proc.poll() is not None for proc in pipes)
    assert repo._pipes == {}
    assert repo.get_object_header('HEAD:Makefile')[1] == 'blob'


def test_materializer_over_gitrepo(repo, mini_repo, tmp_path):
    """The contract test_12 pins over GitPython holds over GitRepo."""
    vuln = mini_repo.commits[0]
    mat = BlobMaterializer(repo, str(tmp_path / 'store'))
    with pytest.raises(ValueError, match='unresolvable'):
        mat.sig('v9.9', [FOO])
    sig = mat.sig(vuln, [FOO, 'does/not/exist.c'])
    assert [p for p, _ in sig] == [FOO, KCONFIG_H]
    assert [p for p, _ in mat.sig(vuln, ['drivers'])] == ['drivers/foo/Makefile', FOO, KCONFIG_H]
    tree = mat.materialize(sig)
    with open(os.path.join(tree, FOO)) as fh:
        assert fh.read() == VULNERABLE_C
    assert tree == mat.materialize(sig)
