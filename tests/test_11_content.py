#!/usr/bin/env python3
"""Unit tests for the content overlay: build, install, verify, resolve.

Everything runs against tmp_path fixtures ('--from' a local directory); no
network involved.
"""

import gzip
import json
import os

import pytest

from cvehound import content
from cvehound.scripts.make_manifest import build_content
from cvehound.scripts.update import main as update_main
from cvehound.scripts.update_metadata import write_metadata
from cvehound.util import get_rule_cves, resolve_metadata_path

RULES = {
    'CVE-2020-1000.cocci': '/// Files: foo.c\nvirtual detect\n',
    'CVE-2020-1001.grep': 'pattern\n',
    'disputed/CVE-2020-1002.cocci': '/// Files: baz.c\nvirtual detect\n',
}


@pytest.fixture
def content_factory(tmp_path):
    rules = tmp_path / 'rules'
    for rel, text in RULES.items():
        path = rules / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    blob = tmp_path / 'kernel_cves.json.gz'
    with gzip.open(blob, 'wt', encoding='utf-8') as fh:
        json.dump({'CVE-2020-1000': {'fixes': 'deadbeef', 'fix_date': 1600000000}}, fh)

    def build(content_id=None):
        out = tmp_path / ('out-' + (content_id or 'default'))
        build_content(str(rules), str(blob), str(out), commit='a' * 40, content_id=content_id)
        return out

    return build


@pytest.fixture
def content_dir(content_factory):
    return content_factory()


@pytest.fixture
def overlay(tmp_path, monkeypatch):
    home = tmp_path / 'overlay'
    monkeypatch.setenv('CVEHOUND_CONTENT', str(home))
    # pytest_configure exports CVEHOUND_METADATA on checkouts without the
    # packaged blob; it outranks the overlay in resolve_metadata_path and
    # would break the resolution assertions here.
    monkeypatch.delenv('CVEHOUND_METADATA', raising=False)
    return home


def _corrupt_tarball(content_dir):
    tarball = next(content_dir.glob('cvehound-content-*.tar.gz'))
    data = bytearray(tarball.read_bytes())
    data[len(data) // 2] ^= 0xFF
    tarball.write_bytes(bytes(data))


def test_install_and_resolve(content_dir, overlay):
    cid, updated = content.install_content(str(content_dir))
    assert updated

    src = content.resolve_content()
    assert src.source == 'overlay'
    assert src.content_id == cid
    assert src.source_commit == 'a' * 40
    assert os.path.isfile(src.metadata_path)
    assert resolve_metadata_path(None) == src.metadata_path

    known, assigned, disputed = get_rule_cves()
    assert set(known) == {'CVE-2020-1000', 'CVE-2020-1001', 'CVE-2020-1002'}
    assert set(disputed) == {'CVE-2020-1002'}
    assert set(assigned) == {'CVE-2020-1000', 'CVE-2020-1001'}

    # Same content id: short-circuit, no reinstall
    assert content.install_content(str(content_dir)) == (cid, False)


def test_debris_is_not_a_rule(content_dir, overlay):
    content.install_content(str(content_dir))
    cve_dir = content.resolve_content().rules_dir
    with open(os.path.join(cve_dir, 'README.txt'), 'w') as fh:
        fh.write('junk')
    with open(os.path.join(cve_dir, 'CVE-2020-1000.cocci.orig'), 'w') as fh:
        fh.write('junk')
    known, _, _ = get_rule_cves()
    assert set(known) == {'CVE-2020-1000', 'CVE-2020-1001', 'CVE-2020-1002'}


def test_corrupt_tarball_rejected(content_dir, overlay):
    _corrupt_tarball(content_dir)
    with pytest.raises(content.ContentError):
        content.install_content(str(content_dir))
    assert content.installed_manifest() is None
    assert content.resolve_content().source == 'packaged'


def test_previous_release_survives_failed_update(content_factory, overlay):
    good = content_factory('good')
    cid, _ = content.install_content(str(good))

    bad = content_factory('bad')
    _corrupt_tarball(bad)
    with pytest.raises(content.ContentError):
        content.install_content(str(bad))

    src = content.resolve_content()
    assert src.source == 'overlay'
    assert src.content_id == cid


def test_unknown_format_version_rejected(content_dir, overlay):
    manifest_path = content_dir / 'manifest.json'
    manifest = json.loads(manifest_path.read_text())
    manifest['format_version'] = 99
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(content.ContentError):
        content.install_content(str(content_dir))


def test_invalid_overlay_falls_back(content_dir, overlay):
    content.install_content(str(content_dir))
    release = os.path.realpath(str(overlay / 'current'))
    manifest_path = os.path.join(release, 'manifest.json')
    with open(manifest_path) as fh:
        manifest = json.load(fh)
    manifest['format_version'] = 99
    with open(manifest_path, 'w') as fh:
        json.dump(manifest, fh)
    assert content.resolve_content().source == 'packaged'


def test_update_check_exit_codes(content_dir, overlay):
    assert update_main(['--check', '--from', str(content_dir)]) == 10
    assert update_main(['--from', str(content_dir)]) == 0
    assert update_main(['--check', '--from', str(content_dir)]) == 0
    # Already up to date is still a success
    assert update_main(['--from', str(content_dir)]) == 0


def test_prune_keeps_two_releases(content_factory, overlay):
    for cid in ('id-1', 'id-2', 'id-3'):
        out = content_factory(cid)
        content.install_content(str(out), force=True)
    releases = os.listdir(overlay / 'releases')
    assert len(releases) == 2
    assert 'id-3' in releases


def test_overlay_disabled(overlay, monkeypatch):
    monkeypatch.setenv('CVEHOUND_CONTENT', 'none')
    assert content.resolve_content().source == 'packaged'
    with pytest.raises(content.ContentError):
        content.install_content('/nonexistent')


def test_resolve_metadata_path_validation(tmp_path, monkeypatch):
    missing = tmp_path / 'missing.gz'
    monkeypatch.setenv('CVEHOUND_METADATA', str(missing))
    with pytest.raises(FileNotFoundError):
        resolve_metadata_path(None)

    plain = tmp_path / 'metadata.json'
    plain.write_text('{}')
    monkeypatch.setenv('CVEHOUND_METADATA', str(plain))
    with pytest.raises(ValueError):
        resolve_metadata_path(None)


def test_write_metadata_guards(tmp_path):
    target = str(tmp_path / 'kernel_cves.json.gz')

    with pytest.raises(RuntimeError):
        write_metadata({}, target)
    assert not os.path.exists(target)

    write_metadata({f'CVE-2020-{i}': {'fixes': 'x'} for i in range(100)}, target)
    with pytest.raises(RuntimeError):
        write_metadata({'CVE-2020-1': {'fixes': 'x'}}, target)

    # A <10% shrink is a normal fluctuation and goes through
    write_metadata({f'CVE-2020-{i}': {'fixes': 'y'} for i in range(95)}, target)
    assert not os.path.exists(target + '.tmp')
    with gzip.open(target, 'rt', encoding='utf-8') as fh:
        assert len(json.load(fh)) == 95
