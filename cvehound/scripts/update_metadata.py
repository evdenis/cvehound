#!/usr/bin/env python3

import contextlib
import gzip
import json
import os
import ssl
import subprocess
import sys
from importlib.resources import files
from io import BytesIO
from urllib.request import Request, urlopen
from zipfile import ZipFile

import lxml.etree as etree


def get_exploit_status_from_fstec() -> tuple[set[str], set[str]]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = Request(
        'https://bdu.fstec.ru/files/documents/vulxml.zip', headers={'User-Agent': 'Mozilla/5.0'}
    )
    with (
        urlopen(req, context=ctx) as uh,
        ZipFile(BytesIO(uh.read())) as zh,
        zh.open('export/export.xml') as fh,
    ):
        parser = etree.XMLParser(recover=True)
        tree = etree.parse(fh, parser)

    public: set[str] = set()
    private: set[str] = set()
    for item in tree.xpath('//vul'):  # type: ignore[union-attr]
        item.xpath('identifier/text()')[0]  # type: ignore[union-attr, index]
        cve_id: str | None = None
        for vuln_id in item.xpath('identifiers/identifier'):  # type: ignore[union-attr]
            if vuln_id.get('type') == 'CVE':  # type: ignore[union-attr]
                cve_id = vuln_id.text  # type: ignore[union-attr]
                break
        is_linux = False
        for name in item.xpath('vulnerable_software/soft/name/text()'):  # type: ignore[union-attr]
            if name == 'Linux' or name == 'linux':
                is_linux = True
        if not is_linux:
            continue
        if not cve_id:
            continue

        exploit_status = item.xpath('exploit_status/text()')[0]  # type: ignore[union-attr, index]
        if 'открыт' in exploit_status:  # type: ignore[operator]  # 'открытом' == 'public'
            public.add(cve_id)
        elif 'уществует' in exploit_status:  # type: ignore[operator]  # == exists
            private.add(cve_id)

    return public, private


def get_commit_date(repo: str, commit: str) -> int:
    return int(
        subprocess.check_output(
            ['git', 'show', '-s', '--format=%ct', commit],
            cwd=repo,
            stderr=subprocess.DEVNULL,
            universal_newlines=True,
        ).strip()
    )


def main(args: list[str] | None = None) -> None:
    if args is None:
        args = sys.argv
    if len(args) < 2 or not os.path.isdir(os.path.join(args[1], '.git')):
        print(f'Usage: {args[0]} <kernel_repo_dir> [metadata_file]', file=sys.stderr)
        sys.exit(1)
    repo = args[1]

    filename = None
    if len(args) == 3:
        filename = args[2]
    else:
        filename = os.environ.get(
            'CVEHOUND_METADATA', str(files('cvehound').joinpath('data/kernel_cves.json.gz'))
        )

    public, private = get_exploit_status_from_fstec()

    with urlopen(
        'https://github.com/nluedtke/linux_kernel_cves/raw/master/data/kernel_cves.json'
    ) as fh:
        js = json.loads(fh.read().decode('utf-8'))

    # Corrupted data https://github.com/nluedtke/linux_kernel_cves/pull/379
    js = dict(filter(lambda x: x[0].startswith('CVE-'), js.items()))

    for cve, info in js.items():
        fix = info.get('fixes', '')
        if fix and repo:
            with contextlib.suppress(Exception):
                info['fix_date'] = get_commit_date(repo, fix)
        info['exploit'] = cve in public or cve in private

    with gzip.open(filename, 'wt', encoding='utf-8') as fh:
        json.dump(js, fh)


if __name__ == '__main__':
    main(sys.argv)
