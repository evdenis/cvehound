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
from cvehound.cpu import CPU

__VERSION__ = '0.2.1'

class UnsupportedVersion(Exception):
    def __init__(self, spatch_version, cve, rule_version):
        self.spatch_version = '.'.join(str(spatch_version))
        self.cve = cve
        self.rule_version = '.'.join(str(rule_version))

def dir_path(path):
    if os.path.isdir(path):
        return path
    raise NotADirectoryError(path)

def tool_exists(name):
    return which(name) is not None

ver = None
def spatch_version():
    global ver
    if not ver:
        run = subprocess.run(['spatch', '--version'], stdout=PIPE, stderr=PIPE, check=True)
        output = run.stdout.decode('utf-8').split('\n')[0]
        res = re.match(r'spatch\s+version\s+([\d.]+)', output)
        ver = int(res.group(1).replace('.', ''))
    return ver

def get_grep_pattern(rule):
    is_fix = False
    start = False
    patterns = []
    with open(rule, 'r') as fh:
        for line in fh:
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

cocci_job = str(CPU().get_cocci_jobs())
def check_cve(kernel, cve, info=None, verbose=0, all_files=False):
    is_grep = False
    rule = get_all_cves()[cve]
    if rule.endswith('.grep'):
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
    if not is_grep:
        rule_ver = get_rule_metadata(cve)['version']
        if rule_ver and rule_ver > spatch_version():
            raise UnsupportedVersion(spatch_version(), cve, rule_ver)
        try:
            cocci_cmd = ['spatch', '--no-includes', '--include-headers',
                         '-D', 'detect', '--no-show-diff', '-j', cocci_job,
                         '--chunksize', '1',
                         '--cocci-file', rule, *files]

            if verbose > 2:
                print(*cocci_cmd)

            run = subprocess.run(cocci_cmd, stdout=PIPE, stderr=PIPE, check=True)
            output = run.stdout.decode('utf-8')
        except subprocess.CalledProcessError as e:
            err = e.stderr.decode('utf-8').split('\n')[-2]
            # Coccinelle 1.0.4 bug workaround
            if ('Sys_error("' + cve + ': No such file or directory")') not in err:
                raise e
    else:
        (is_fix, patterns) = get_grep_pattern(rule)
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

    if 'ERROR' in output:
        print('Found:', cve)
        if verbose:
            if 'cmt_msg' in info:
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
    version = 0

    if cve in rules_metadata:
        return rules_metadata[cve]

    with open(get_all_cves()[cve], 'rt') as fh:
        for line in fh:
            if not line.startswith('///'):
                break
            if 'Files:' in line:
                files = line.partition('Files:')[2].split()
            elif 'Fix:' in line:
                fix = line.partition('Fix:')[2].strip()
            elif 'Fixes:' in line:
                fixes = line.partition('Fixes:')[2].strip()
            elif 'Detect-To:' in line:
                fixes = line.partition('Detect-To:')[2].strip()
            elif 'Version:' in line:
                version = line.partition('Version:')[2].strip()
                version = int(version.replace('.', ''))

    meta = {
        'files': files,
        'fix': fix,
        'fixes': fixes,
        'version': version
    }
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
        try:
            check_cve(cmdargs.dir, cve, meta.get(cve, {}), cmdargs.verbose, cmdargs.all_files)
        except subprocess.CalledProcessError as e:
            print('Failed to run: ', ' '.join(e.cmd))
        except UnsupportedVersion as err:
            print('Skipping: ' + err.cve + ' requires spatch >= ' + err.rule_version)

if __name__ == '__main__':
    main(sys.argv[1:])
