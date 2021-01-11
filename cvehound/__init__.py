#!/usr/bin/env python3

import os
import sys
import argparse
import re
import subprocess
import gzip
import json
from shutil import which
from subprocess import PIPE
import pkg_resources

__VERSION__ = '0.2.1'

def dir_path(path):
    if os.path.isdir(path):
        return path
    raise NotADirectoryError(path)

def tool_exists(name):
    return which(name) is not None

cores_num = 0
def get_cores_num():
    global cores_num
    if cores_num == 0:
        cores_num = len(os.sched_getaffinity(0))
    return cores_num

def get_grep_pattern(rule):
    is_fix = False
    start = False
    patterns = []
    with open(rule, 'r') as fh:
        while True:
            line = fh.readline()
            if not line:
                break
            line = line.strip()
            if line == 'FIX':
                is_fix = True
                start = True
                continue
            elif line == 'ERROR':
                start = True
                continue
            if start and line:
                patterns.append(line)
    return (is_fix, patterns)

def read_cve_metadata():
    cves = pkg_resources.resource_filename('cvehound', 'data/kernel_cves.json.gz')
    data = None
    with gzip.open(cves, 'rt', encoding='utf-8') as fh:
        data = json.loads(fh.read())
    return data

def check_cve(kernel, cve, info=None, verbose=0, all_files=False):
    cocci = pkg_resources.resource_filename('cvehound', 'cve/' + cve + '.cocci')
    grep = pkg_resources.resource_filename('cvehound', 'cve/' + cve + '.grep')
    is_grep = False

    if os.path.isfile(cocci):
        rule = cocci
    else:
        rule = grep
        is_grep = True

    files = []
    if not all_files:
        files = get_rule_metadata(cve)['files']
        files = map(lambda f: os.path.join(kernel, f), files)
        files = filter(lambda f: os.path.exists(f), files)
        files = list(files)
    if not files:
        files = [ kernel ]

    if verbose:
        print('Checking:', cve)

    output = ''
    run = None
    try:
        if not is_grep:
            run = subprocess.run(['spatch', '--no-includes', '--include-headers',
                                  '-D', 'detect', '--no-show-diff', '-j', str(get_cores_num()),
                                  '--cocci-file', cocci, *files],
                                  stdout=PIPE, stderr=PIPE, check=True)
            output = run.stdout.decode('utf-8')
        else:
            (is_fix, patterns) = get_grep_pattern(grep)
            args = ['grep', '--include=*.[ch]', '-rPzoe', patterns[0], *files]
            patterns.pop(0)
            run = subprocess.run(args, stdout=PIPE, stderr=PIPE, check=False)
            if run.returncode == 0:
                output = run.stdout
                last = patterns.pop()
                for pattern in patterns:
                    run = subprocess.run(['grep', '-Pzoe', pattern],
                                         input=output, check=False,
                                         stdout=PIPE, stderr=PIPE)
                    if run.returncode != 0:
                        output = ''
                        break
                    output = run.stdout
                if run.returncode == 0:
                    run = subprocess.run(['grep', '-Pzoe', last],
                                         input=output, check=False,
                                         stdout=PIPE, stderr=PIPE)
                    success = run.returncode == 0
                    if is_fix == success:
                        output = ''
                    else:
                        output = 'ERROR'
    except subprocess.CalledProcessError as e:
        print('Failed to run:', ' '.join(e.cmd))
        return False

    if 'ERROR' in output:
        print('Found:', cve)
        if verbose:
            print('MSG:', info['cmt_msg'])
            if 'cwe' in info:
                print('CWE:', info['cwe'])
            if 'last_modified' in info:
                print('CVE UPDATED:', info['last_modified'])
            print('https://www.linuxkernelcves.com/cves/' + cve)
            if verbose > 1:
                print(output)
            print()
        return True
    return False

def removesuffix(string, suffix):
    if suffix and string.endswith(suffix):
        return string[:-len(suffix)]
    return string[:]

rules_metadata = {}
def get_rule_metadata(cve):
    files = []
    fix = None
    fixes = None

    if cve in rules_metadata:
        return rules_metadata[cve]

    with open(get_all_cves()[cve], 'r') as fh:
        while True:
            line = fh.readline()
            if not line:
                break
            if 'Files:' in line:
                files = line.partition('Files:')[2].split()
            elif 'Fix:' in line:
                fix = line.partition('Fix:')[2].strip()
            elif 'Fixes:' in line:
                fixes = line.partition('Fixes:')[2].strip()
                break
            elif 'Detect-To:' in line:
                fixes = line.partition('Detect-To:')[2].strip()
                break

    meta = { 'files': files }
    if fix:
        meta['fix'] = fix
    if fixes:
        meta['fixes'] = fixes
    return meta

cve_rules = {}
def get_all_cves():
    global cve_rules
    if not cve_rules:
        for cve in pkg_resources.resource_listdir('cvehound', 'cve/'):
            name = removesuffix(removesuffix(cve, '.grep'), '.cocci')
            cve_rules[name] = pkg_resources.resource_filename('cvehound', 'cve/' + cve)
    return cve_rules

def main(args=sys.argv[1:]):
    parser = argparse.ArgumentParser(
        prog='cvehound',
        description='A tool to check linux kernel sources dump for known CVEs',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('--version', action='version', version=__VERSION__)
    parser.add_argument('--all-files', action='store_true',
                        help="don't use files hint from cocci rules")
    parser.add_argument('--cve', '-c', nargs='+', default='all',
                        help='list of cve identifiers')
    parser.add_argument('--dir', '-d', type=dir_path, required=True,
                        help='linux kernel sources dir')
    parser.add_argument('-v', '--verbose', action='count', default=0,
                        help='increase output verbosity')
    cmdargs = parser.parse_args()

    if not tool_exists('spatch'):
        print('Please, install coccinelle.')
        sys.exit(1)

    known_cves = get_all_cves().keys()
    if cmdargs.cve == 'all':
        cmdargs.cve = known_cves
    else:
        cve_id = re.compile(r'^CVE-\d{4}-\d{4,7}$')
        for i, cve in enumerate(cmdargs.cve):
            if not cve.startswith('CVE-'):
                cve = 'CVE-' + cve
                cmdargs.cve[i] = cve
            if not cve_id.match(cve):
                print('Wrong CVE-ID:', cve, file=sys.stderr)
                sys.exit(1)
            if cve not in known_cves:
                print('Unknown CVE:', cve, file=sys.stderr)
                sys.exit(1)
    meta = {}
    if cmdargs.verbose:
        meta = read_cve_metadata()
    for cve in cmdargs.cve:
        check_cve(cmdargs.dir, cve, meta.get(cve, {}), cmdargs.verbose, cmdargs.all_files)

if __name__ == '__main__':
    main(sys.argv[1:])
