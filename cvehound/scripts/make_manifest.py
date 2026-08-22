#!/usr/bin/env python3
"""Build a distributable content set: rules + metadata + manifest.

Maintainer/CI tool.  Packs a rules directory and a metadata blob into
cvehound-content-<id>.tar.gz and writes the standalone manifest.json that
`cvehound update` fetches first.  Both files (plus the bare metadata blob,
for consumers that only need it) are meant to be uploaded as assets of the
rolling `content-latest` GitHub release.
"""

import argparse
import hashlib
import json
import os
import shutil
import sys
import tarfile
from datetime import UTC, datetime
from typing import Any

from cvehound.content import FORMAT_VERSION, MANIFEST_NAME, METADATA_NAME, RULE_SUFFIXES
from cvehound.util import fix_date_str, get_cves_metadata, latest_fix_date


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, 'rb') as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b''):
            digest.update(chunk)
    return digest.hexdigest()


def _rule_files(rules_dir: str) -> dict[str, str]:
    """Map 'cve/<relative path>' -> sha256 for every rule under rules_dir."""
    result: dict[str, str] = {}
    for root, _dirs, file_list in os.walk(rules_dir):
        for name in file_list:
            if not name.endswith(RULE_SUFFIXES):
                continue
            path = os.path.join(root, name)
            rel = os.path.relpath(path, rules_dir)
            result['cve/' + rel.replace(os.sep, '/')] = _sha256_file(path)
    return result


def _describe_metadata(path: str) -> tuple[int, str]:
    """Entry count and latest fix date (the blob's effective generation date)."""
    data = get_cves_metadata(path)
    latest = latest_fix_date(data)
    return len(data), fix_date_str(latest) if latest else ''


def build_content(
    rules_dir: str,
    metadata_path: str,
    out_dir: str,
    commit: str | None = None,
    content_id: str | None = None,
) -> dict[str, Any]:
    """Write manifest.json, the content tarball, and the bare blob into out_dir."""
    rule_hashes = _rule_files(rules_dir)
    if not rule_hashes:
        raise RuntimeError(f'no rules found under {rules_dir}')
    entries, generated = _describe_metadata(metadata_path)
    if not entries:
        raise RuntimeError(f'metadata blob {metadata_path} is empty')

    if not content_id:
        suffix = commit[:12] if commit else 'local'
        content_id = datetime.now(tz=UTC).strftime('%Y%m%d') + '-' + suffix

    manifest: dict[str, Any] = {
        'format_version': FORMAT_VERSION,
        'content_id': content_id,
        'source_commit': commit,
        'created': datetime.now(tz=UTC).strftime('%Y-%m-%dT%H:%M:%SZ'),
        'rules': {'files': rule_hashes},
        'metadata': {
            'sha256': _sha256_file(metadata_path),
            'entries': entries,
            'generated': generated,
        },
    }

    os.makedirs(out_dir, exist_ok=True)
    tar_name = f'cvehound-content-{content_id}.tar.gz'
    tar_path = os.path.join(out_dir, tar_name)
    with tarfile.open(tar_path, 'w:gz') as tar:
        for arcname in sorted(rule_hashes):
            rel = arcname.removeprefix('cve/')
            tar.add(os.path.join(rules_dir, rel), arcname=arcname)
        tar.add(metadata_path, arcname=METADATA_NAME)

    manifest['tarball'] = {'name': tar_name, 'sha256': _sha256_file(tar_path)}
    with open(os.path.join(out_dir, MANIFEST_NAME), 'w', encoding='utf-8') as fh:
        json.dump(manifest, fh, indent=2, sort_keys=True)
        fh.write('\n')
    blob_copy = os.path.join(out_dir, os.path.basename(METADATA_NAME))
    if os.path.abspath(metadata_path) != os.path.abspath(blob_copy):
        shutil.copyfile(metadata_path, blob_copy)
    return manifest


def main(args: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog='cvehound.scripts.make_manifest',
        description='Build a cvehound content set (rules + metadata + manifest)',
    )
    parser.add_argument('--rules', required=True, metavar='DIR', help='rules directory (cve/)')
    parser.add_argument(
        '--metadata', required=True, metavar='FILE', help='kernel_cves.json.gz blob'
    )
    parser.add_argument('--out', required=True, metavar='DIR', help='output directory')
    parser.add_argument('--commit', metavar='SHA', help='source commit of the rules')
    parser.add_argument('--id', dest='content_id', metavar='ID', help='explicit content id')
    opts = parser.parse_args(args)

    try:
        manifest = build_content(
            opts.rules, opts.metadata, opts.out, commit=opts.commit, content_id=opts.content_id
        )
    except (RuntimeError, OSError, ValueError) as err:
        print(f'Error: {err}', file=sys.stderr)
        return 1
    print(
        'Built content {} ({} rules, {} CVEs in metadata) in {}'.format(
            manifest['content_id'],
            len(manifest['rules']['files']),
            manifest['metadata']['entries'],
            opts.out,
        )
    )
    return 0


if __name__ == '__main__':
    sys.exit(main())
