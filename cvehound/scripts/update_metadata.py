#!/usr/bin/env python3

import sys
import pkg_resources
import gzip
import urllib.request

def main(args=sys.argv[1:]):
    filename = pkg_resources.resource_filename('cvehound', 'data/kernel_cves.json.gz')

    with urllib.request.urlopen('https://github.com/nluedtke/linux_kernel_cves/raw/master/data/kernel_cves.json') as fh:
        json = fh.read()

    with gzip.open(filename, 'wb') as fh:
        fh.write(json)

if __name__ == '__main__':
    main(sys.argv[1:])
