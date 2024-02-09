#!/usr/bin/env python3

import os
import sys
import pkg_resources
import gzip
import json
import subprocess
import ssl
from urllib.request import urlopen, Request
from datetime import datetime
import lxml.etree as etree
from io import BytesIO
from zipfile import ZipFile

def get_exploit_status_from_fstec():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = Request('https://bdu.fstec.ru/files/documents/vulxml.zip', headers={'User-Agent': 'Mozilla/5.0'})
    with urlopen(req, context=ctx) as uh:
        with ZipFile(BytesIO(uh.read())) as zh:
            with zh.open('export/export.xml') as fh:
                parser = etree.XMLParser(recover=True)
                tree = etree.parse(fh, parser)

    public = set()
    private = set()
    for item in tree.xpath('//vul'):
        bdu_id = item.xpath('identifier/text()')[0]
        cve_id = None
        for vuln_id in item.xpath('identifiers/identifier'):
            if 'CVE' == vuln_id.get('type'):
                cve_id = vuln_id.text
                break
        is_linux = False
        for name in item.xpath('vulnerable_software/soft/name/text()'):
            if name == 'Linux' or name == 'linux':
                is_linux = True
        if not is_linux:
            continue
        if not cve_id:
            continue

        exploit_status = item.xpath('exploit_status/text()')[0]
        if 'открыт' in exploit_status: # 'открытом' == 'public'
            public.add(cve_id)
        elif 'уществует' in exploit_status: # == exists
            private.add(cve_id)

    return public, private

def get_commit_date(repo, commit):
    return int(subprocess.check_output(
            ['git', 'show', '-s', '--format=%ct', commit], cwd=repo, stderr=subprocess.DEVNULL, universal_newlines=True
    ).strip())

def main(args=sys.argv):
    if len(args) < 2 or not os.path.isdir(os.path.join(args[1], '.git')):
        print('Usage: {} <kernel_repo_dir> [metadata_file]'.format(args[0]), file=sys.stderr)
        sys.exit(1)
    repo = args[1]

    filename = None
    if len(args) == 3:
        filename = args[2]
    else:
        filename = os.environ.get('CVEHOUND_METADATA',
                                  pkg_resources.resource_filename('cvehound', 'data/kernel_cves.json.gz'))

    public, private = get_exploit_status_from_fstec()

    with urlopen('https://github.com/nluedtke/linux_kernel_cves/raw/master/data/kernel_cves.json') as fh:
        js = json.loads(fh.read().decode('utf-8'))

    # Corrupted data https://github.com/nluedtke/linux_kernel_cves/pull/379
    js = dict(filter(lambda x: x[0].startswith('CVE-'), js.items()))

    for cve, info in js.items():
        fix = info.get('fixes', '')
        if fix and repo:
            try:
                info['fix_date'] = get_commit_date(repo, fix)
            except Exception:
                pass
        info['exploit'] = cve in public or cve in private

    with gzip.open(filename, 'wt', encoding='utf-8') as fh:
        json.dump(js, fh)

if __name__ == '__main__':
    main(sys.argv)
