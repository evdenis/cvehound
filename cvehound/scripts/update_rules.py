#!/usr/bin/env python3

import os
import sys
import pkg_resources
import shutil
from urllib.request import urlopen
from io import BytesIO
from zipfile import ZipFile

def main(args=sys.argv):
    rule_dir = pkg_resources.resource_filename('cvehound', 'cve')

    for rule in os.listdir(rule_dir):
        entry = os.path.join(rule_dir, rule)
        try:
            if os.path.isdir(entry):
                shutil.rmtree(entry)
            else:
                os.unlink(entry)
        except Exception as e:
            print('Failed to delete {}: {}'.format(entry, e))

    with urlopen('https://github.com/evdenis/cvehound/archive/refs/heads/master.zip') as uh:
        rules = []
        with ZipFile(BytesIO(uh.read())) as zh:
            rules = filter(lambda x: x.startswith('cvehound-master/cvehound/cve'), zh.namelist())
            rules = list(rules)
            zh.extractall(path=rule_dir, members=rules)
        prefix_len = len('cvehound-master/cvehound/cve') + 1
        os.chdir(rule_dir)
        for entry in rules:
            to = entry[prefix_len:].strip()
            if not to or not (os.path.isfile(entry) or os.path.isdir(entry)):
                continue
            os.rename(entry, to)
        shutil.rmtree('cvehound-master')

if __name__ == '__main__':
    main(sys.argv)
