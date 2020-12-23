#!/usr/bin/env python3

import pkg_resources
import os
import sys
import argparse
import re
import subprocess

def dir_path(path):
    if os.path.isdir(path):
        return path
    else:
        raise NotADirectoryError(path)

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

def get_files(rule, kernel):
    files = []
    with open(rule, 'r') as fh:
        while True:
            line = fh.readline()
            if not line:
                break
            if 'Files:' in line:
                files = line.partition('Files:')[2].split()
                break
    files = map(lambda f: os.path.join(kernel, f), files)
    files = filter(lambda f: os.path.exists(f), files)
    return files

def check_cve(kernel, cve, verbose=False, all_files=False):
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
        files = list(get_files(rule, kernel))
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
                                  capture_output=True, check=True)
            output = run.stdout.decode('utf-8')
        else:
            (is_fix, patterns) = get_grep_pattern(grep)
            args = ['grep', '--include=*.[ch]', '-rPzoe', patterns[0], *files]
            patterns.pop(0)
            run = subprocess.run(args, capture_output=True)
            if run.returncode == 0:
                output = run.stdout
                last = patterns.pop()
                for p in patterns:
                    run = subprocess.run(['grep', '-Pzoe', p],
                                         input=output, capture_output=True)
                    if run.returncode != 0:
                        output = ''
                        break
                    output = run.stdout
                if run.returncode == 0:
                    run = subprocess.run(['grep', '-Pzoe', last],
                                         input=output, capture_output=True)
                    success = run.returncode == 0
                    if is_fix == success:
                        output = ''
                    else:
                        output = 'ERROR'
    except subprocess.CalledProcessError as e:
        print('Failed to check', cve)
        if verbose:
            print('Failed to run:', ' '.join(e.cmd))
        return False

    if 'ERROR' in output:
        print('Found:', cve)
        if verbose:
            print(output)
        return True
    return False

def get_all_cves():
    return [cve.removesuffix('.cocci').removesuffix('.grep')
            for cve in pkg_resources.resource_listdir('cvehound', 'cve/')]

def main(args=sys.argv[1:]):
    parser = argparse.ArgumentParser(
        prog='cvehound',
        description='A tool to check linux kernel sources dump for known CVEs',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('--version', action='version', version='0.0.1')
    parser.add_argument('--all-files', action='store_true', help="don't use files hint from cocci rules")
    parser.add_argument('--cve', '-c', nargs='+', default='all',
                        help='list of cve identifiers')
    parser.add_argument('--dir', '-d', type=dir_path, required=True,
                        help='linux kernel sources dir')
    parser.add_argument('-v', '--verbose', help='increase output verbosity',
                        action='store_true')
    cmdargs = parser.parse_args()
    known_cves = get_all_cves()
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
    for cve in cmdargs.cve:
        check_cve(cmdargs.dir, cve, cmdargs.verbose, cmdargs.all_files)

if __name__ == '__main__':
    main(sys.argv[1:])
