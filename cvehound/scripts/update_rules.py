#!/usr/bin/env python3

import os
import shutil
import sys
from importlib.resources import files
from io import BytesIO
from urllib.request import urlopen
from zipfile import ZipFile


def main(args: list[str] | None = None) -> None:
    if args is None:
        args = sys.argv
    rule_dir = str(files('cvehound').joinpath('cve'))

    for rule in os.listdir(rule_dir):
        entry = os.path.join(rule_dir, rule)
        try:
            if os.path.isdir(entry):
                shutil.rmtree(entry)
            else:
                os.unlink(entry)
        except Exception as e:
            print(f'Failed to delete {entry}: {e}')

    with urlopen('https://github.com/evdenis/cvehound/archive/refs/heads/master.zip') as uh:
        rules: list[str] = []
        with ZipFile(BytesIO(uh.read())) as zh:
            rules = list(
                filter(lambda x: x.startswith('cvehound-master/cvehound/cve'), zh.namelist())
            )
            zh.extractall(path=rule_dir, members=rules)
        prefix_len = len('cvehound-master/cvehound/cve') + 1
        os.chdir(rule_dir)
        for entry in rules:
            to = entry[prefix_len:].strip()
            if not to:
                continue
            # Skip directories - they're created automatically when moving files
            if os.path.isdir(entry):
                continue
            # Only process existing files
            if not os.path.isfile(entry):
                continue
            # Ensure target directory exists
            target_dir = os.path.dirname(to)
            if target_dir:
                os.makedirs(target_dir, exist_ok=True)
            os.rename(entry, to)
        shutil.rmtree('cvehound-master')


if __name__ == '__main__':
    main(sys.argv)
