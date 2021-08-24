#!/usr/bin/env python3

import os
import sys
import pkg_resources
import gzip
import urllib.request
import json
import subprocess
from datetime import datetime

def get_commit_date(repo, commit):
    return int(subprocess.check_output(
            ['git', 'show', '-s', '--format=%ct', commit], cwd=repo, stderr=subprocess.DEVNULL, universal_newlines=True
    ).strip())

def main(args=sys.argv):
    if len(args) < 2 or not os.path.isdir(os.path.join(args[1], '.git')):
        print('Usage: {} <kernel_repo_dir>'.format(args[0]), file=sys.stderr)
        exit(1)
    repo = args[1]
    filename = pkg_resources.resource_filename('cvehound', 'data/kernel_cves.json.gz')

    with urllib.request.urlopen('https://github.com/nluedtke/linux_kernel_cves/raw/master/data/kernel_cves.json') as fh:
        js = json.loads(fh.read().decode('utf-8'))

    for cve, info in js.items():
        fix = info.get('fixes', '')
        if fix and args[0]:
            try:
                info['fix_date'] = get_commit_date(repo, fix)
            except Exception:
                pass

    with gzip.open(filename, 'wt', encoding='utf-8') as fh:
        json.dump(js, fh)

if __name__ == '__main__':
    main(sys.argv)
