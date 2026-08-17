from pathlib import Path

import conftest
from conftest import clone_shared_repo, create_tmpfs_repo, should_use_tmpfs
from git import Repo


def test_should_use_tmpfs_at_threshold_outside_github(monkeypatch):
    monkeypatch.delenv('GITHUB_ACTIONS', raising=False)

    assert not should_use_tmpfs(['cve'] * 4)
    assert should_use_tmpfs(['cve'] * 5)
    assert should_use_tmpfs(['cve'] * 500)

    monkeypatch.setenv('GITHUB_ACTIONS', 'false')
    assert should_use_tmpfs(['cve'] * 5)


def test_should_not_use_tmpfs_on_github(monkeypatch):
    monkeypatch.setenv('GITHUB_ACTIONS', 'true')

    assert not should_use_tmpfs(['cve'] * 500)


def test_clone_shared_repo_preserves_refs_without_changing_source(tmp_path):
    source_path = tmp_path / 'source'
    source = Repo.init(source_path)
    tracked = source_path / 'tracked'
    tracked.write_text('first\n')
    source.index.add([str(tracked)])
    first = source.index.commit('first')
    source.create_tag('v1', first)
    for ref in ('origin/master', 'next/master', 'stable/linux-6.6.y'):
        source.git.update_ref('refs/remotes/' + ref, first.hexsha)

    tracked.write_text('second\n')
    source.index.add([str(tracked)])
    second = source.index.commit('second')
    source_branch = source.active_branch.name
    source_index = Path(source.index.path).read_bytes()

    target = tmp_path / 'target'
    target.mkdir()
    clone = clone_shared_repo(source, target)

    for ref in ('origin/master', 'next/master', 'stable/linux-6.6.y', 'v1'):
        assert clone.commit(ref) == first
    assert clone.commit(source_branch) == second
    assert (target / 'tracked').read_text() == 'first\n'
    assert Path(clone.git_dir, 'objects/info/alternates').read_text().strip() == str(
        Path(source.git_dir, 'objects')
    )
    assert source.head.commit == second
    assert Path(source.index.path).read_bytes() == source_index
    assert not source.is_dirty()


def test_create_tmpfs_repo_cleans_up_after_clone_failure(monkeypatch, tmp_path):
    target = tmp_path / 'mount'
    target.mkdir()
    source = object()
    unmounted = []

    def fail_clone(_source, _target):
        raise OSError

    monkeypatch.setattr(conftest.tempfile, 'mkdtemp', lambda: str(target))
    monkeypatch.setattr(
        conftest, 'mount_tmpfs', lambda path, size: (path, size) == (str(target), 3)
    )
    monkeypatch.setattr(conftest, 'clone_shared_repo', fail_clone)
    monkeypatch.setattr(conftest, 'umount', unmounted.append)

    repo, mount = create_tmpfs_repo(source)

    assert repo is source
    assert mount is None
    assert unmounted == [str(target)]
    assert not target.exists()


def test_create_tmpfs_repo_cleans_up_after_mount_failure(monkeypatch, tmp_path):
    target = tmp_path / 'mount'
    target.mkdir()
    source = object()

    monkeypatch.setattr(conftest.tempfile, 'mkdtemp', lambda: str(target))
    monkeypatch.setattr(conftest, 'mount_tmpfs', lambda _path, _size: False)

    repo, mount = create_tmpfs_repo(source)

    assert repo is source
    assert mount is None
    assert not target.exists()
