#!/usr/bin/env python3

import os
import sys
import pkg_resources
import gzip
import json
import subprocess
from urllib.request import urlopen, Request
from datetime import datetime
import lxml.etree as etree
from io import BytesIO
from zipfile import ZipFile

def get_exploit_status_from_fstec():
    req = Request('https://bdu.fstec.ru/files/documents/vulxml.zip', headers={'User-Agent': 'Mozilla/5.0'})
    with urlopen(req) as uh:
        with ZipFile(BytesIO(uh.read())) as zh:
            with zh.open('export/export.xml') as fh:
                tree = etree.parse(fh)

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

dates = {}
def get_commit_date(repo, commit):
    if commit not in dates:
        dates[commit] = int(subprocess.check_output(
            ['git', 'show', '-s', '--format=%ct', commit], cwd=repo, stderr=subprocess.DEVNULL, universal_newlines=True
        ).strip())
    return dates[commit]

titles = {}
def get_commit_title(repo, commit):
    if commit not in titles:
        titles[commit] = subprocess.check_output(
            ['git', 'show', '-s', '--format=%s', commit], cwd=repo, stderr=subprocess.DEVNULL, universal_newlines=True
        ).strip()
    return titles[commit]

def main(args=sys.argv):
    if len(args) < 2 or not os.path.isdir(os.path.join(args[1], '.git')):
        print('Usage: {} <kernel_repo_dir>'.format(args[0]), file=sys.stderr)
        exit(1)
    repo = args[1]
    filename = pkg_resources.resource_filename('cvehound', 'data/kernel_cves.json.gz')

    public, private = get_exploit_status_from_fstec()

    with urlopen('https://github.com/nluedtke/linux_kernel_cves/raw/master/data/kernel_cves.json') as fh:
        js = json.loads(fh.read().decode('utf-8'))

    for cve, info in js.items():
        fixes = info.get('fixes', '')
        breaks = info.get('breaks', '')
        if repo:
            if fixes:
                try:
                    info['fixes_date'] = get_commit_date(repo, fixes)
                except Exception:
                    pass
            if breaks:
                try:
                    info['breaks_date'] = get_commit_date(repo, breaks)
                    info['breaks_msg'] = get_commit_title(repo, breaks)
                except Exception:
                    pass
        info['exploit'] = cve in public or cve in private

    with gzip.open(filename, 'wt', encoding='utf-8') as fh:
        json.dump(js, fh)

if __name__ == '__main__':
    main(sys.argv)
