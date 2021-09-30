#!/usr/bin/env python3

import os
import sys
import pkg_resources
from urllib.request import urlopen
from io import BytesIO
from zipfile import ZipFile

def main(args=sys.argv):
    rule_dir = pkg_resources.resource_filename('cvehound', 'cve')

    for rule in os.listdir(rule_dir):
        rule_path = os.path.join(rule_dir, rule)
        try:
            os.unlink(rule_path)
            pass
        except Exception as e:
            print('Failed to delete {}: {}'.format(rule_path, e))

    with urlopen('https://github.com/evdenis/cvehound/archive/refs/heads/master.zip') as uh:
        rules = []
        with ZipFile(BytesIO(uh.read())) as zh:
            rules = filter(lambda x: x.startswith('cvehound-master/cvehound/cve'), zh.namelist())
            rules = list(rules)
            zh.extractall(path=rule_dir, members=rules)
        prefix_len = len('cvehound-master/cvehound/cve') + 1
        os.chdir(rule_dir)
        for rule in rules:
            if not os.path.isfile(rule):
                continue
            os.rename(rule, rule[prefix_len:])
        os.rmdir('cvehound-master/cvehound/cve')
        os.rmdir('cvehound-master/cvehound')
        os.rmdir('cvehound-master')

if __name__ == '__main__':
    main(sys.argv)
