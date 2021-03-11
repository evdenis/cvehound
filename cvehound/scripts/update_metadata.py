#!/usr/bin/env python3

import sys
import pkg_resources
import gzip
import urllib.request
import json
import subprocess
from datetime import datetime

def main(args=sys.argv[1:]):
    filename = pkg_resources.resource_filename('cvehound', 'data/kernel_cves.json.gz')

    with urllib.request.urlopen('https://github.com/nluedtke/linux_kernel_cves/raw/master/data/kernel_cves.json') as fh:
        js = json.loads(fh.read().decode('utf-8'))

    for cve, info in js.items():
        fix = info.get('fixes', '')
        if fix:
            try:
                info['fix_date'] = int(subprocess.check_output(
                    ['git', 'show', '-s', '--format=%ct', fix], cwd=args[0], stderr=subprocess.DEVNULL, universal_newlines=True
                ).strip())
            except Exception:
                pass

    with gzip.open(filename, 'wt', encoding='utf-8') as fh:
        json.dump(js, fh)

if __name__ == '__main__':
    main(sys.argv[1:])
