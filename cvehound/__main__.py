#!/usr/bin/env python3

import os
import sys
import argparse
import re
import shutil
import subprocess
import logging
import json

import concurrent.futures

from cvehound import CVEhound
from cvehound.util import *
from cvehound.exception import UnsupportedVersion
from cvehound.cwe import CWE

def check_config(config):
    valid_config_options = {
        'kernel',
        'cve',
        'exclude',
        'exploit',
        'verbose',
        'cwe',
        'files',
        'ignore_files',
        'kernel_config'
        'check_strict',
        'report',
        'all_files',
        'metadata',
    }
    diff = set(config.keys()) - valid_config_options
    if diff:
        print("Unknown config options: " + ','.join(diff), file=sys.stderr)
        sys.exit(1)

def main(args=sys.argv[1:]):
    parser = argparse.ArgumentParser(
        prog='cvehound',
        description='A tool to check linux kernel sources dump for known CVEs',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('--config', metavar='FILE',
                        help='cvehound.ini config file (default: /etc/cvehound.ini or $HOME/.config/cvehound.ini')
    parser.add_argument('--kernel', '-k', metavar='DIR',
                        help='linux kernel sources dir')
    parser.add_argument('--list', action='store_true',
                        help="list all known CVEs and exit")
    parser.add_argument('--cve', '-c', nargs='+', default=['assigned'],
                        help='list of cve identifiers (groups: [all, assigned, disputed])')
    parser.add_argument('--exclude', '-x', nargs='+', default=[], metavar='CVE',
                        help='list of cve identifiers or a file with them to exclude CVEs from check')
    parser.add_argument('-v', '--verbose', action='count', default=0,
                        help='increase output verbosity')
    parser.add_argument('--exploit', '-e', action='store_true',
                        help='check only for CVEs with exploits')
    parser.add_argument('--cwe', nargs='+', default=[], type=int,
                        help='check only for CWE-ids')
    parser.add_argument('--files', nargs='+', default=[], metavar='PATH',
                        help='check only files (e.g. kernel drivers/block/floppy.c arch/x86)')
    parser.add_argument('--ignore-files', nargs='+', default=[], metavar='PATH',
                        help='exclude kernel files from check (e.g. kernel/bpf)')
    parser.add_argument('--kernel-config', nargs='?', const='-', metavar='.config',
                        help='check kernel config')
    parser.add_argument('--check-strict', action='store_true',
                        help='output only CVEs enabled in .config')
    parser.add_argument('--report', nargs='?', const='report.json',
                        help='output report with found CVEs')
    parser.add_argument('--all-files', action='store_true',
                        help="don't use files hint from cocci rules")
    parser.add_argument('--metadata', metavar='PATH',
                        help="Path to non-standard location of kernel_cves.json.gz")
    parser.add_argument('--version', action='version', version=get_cvehound_version())
    cmdargs = parser.parse_args()

    if cmdargs.list:
        (all_rules, _, _) = get_rule_cves()
        print("\n".join(sorted(all_rules)))
        sys.exit(0)

    config_args = {}
    try:
        if cmdargs.config:
            config_args = parse_config(cmdargs.config)
        else:
            if os.path.isfile('/etc/cvehound.ini'):
                config_args = parse_config('/etc/cvehound.ini')
            if 'HOME' in os.environ:
                home_config_path = os.path.join(os.environ['HOME'], '.config', 'cvehound.ini')
                if os.path.isfile(home_config_path):
                    config_args.update(parse_config(home_config_path))
    except Exception as err:
        print("Can't parse config file:", err, file=sys.stderr)
        sys.exit(1)
    check_config(config_args)
    args = config_args
    cmdargs = vars(cmdargs)
    for arg in cmdargs.keys():
        if cmdargs[arg] != parser.get_default(arg):
            args[arg] = cmdargs[arg]
        elif arg not in args:
            args[arg] = cmdargs[arg]

    if not args['kernel']:
        parser.print_usage()
        print("cvehound: error: the following arguments are required: --kernel/-k", file=sys.stderr)
        sys.exit(1)

    if args['metadata']:
        if not os.path.isfile(args['metadata']):
            print("Can't find metadata file", args['metadata'], file=sys.stderr)
            sys.exit(1)
        if not args['metadata'].endswith('.gz'):
            print("Metadata file", args['metadata'], "is not the gz archive", file=sys.stderr)
            sys.exit(1)

    if not all(os.path.isfile(os.path.join(args['kernel'], f)) for f in
               ['Makefile']):
        print(args['kernel'], "isn't a kernel directory", file=sys.stderr)
        sys.exit(1)

    if args['kernel_config'] == '-':
        config = os.path.normpath(os.path.join(args['kernel'], '.config'))
        if os.path.isfile(config):
            args['kernel_config'] = config
    else:
        if args['kernel_config'] and not os.path.isfile(args['kernel_config']):
            print("Can't find config file", args['kernel_config'], file=sys.stderr)
            sys.exit(1)

    if args['kernel_config'] and args['verbose'] == 0:
        args['verbose'] = 1

    if args['check_strict']:
        if not args['kernel_config']:
            print('Please, use --check-strict with --kernel-config', file=sys.stderr)
            sys.exit(1)

    if not shutil.which('spatch'):
        print("coccinelle is not installed", file=sys.stderr)
        sys.exit(1)

    loglevel = logging.WARNING
    if args['verbose'] > 1:
        loglevel = logging.DEBUG
    elif args['verbose'] > 0:
        loglevel = logging.INFO
    logging.basicConfig(level=loglevel, format='%(message)s')

    config_info = {}
    if args['kernel_config'] and args['kernel_config'] != '-':
        config_info = get_config_data(args['kernel_config'])

    hound = CVEhound(args['kernel'], args['metadata'], args['kernel_config'],
                     args['check_strict'], config_info.get('arch', 'x86'))

    cve_id = re.compile(r'^CVE-\d{4}-\d{4,7}$')
    if args['cve'] == ['all']:
        args['cve'] = hound.get_all_cves()
    elif args['cve'] == ['assigned']:
        args['cve'] = hound.get_assigned_cves()
    elif args['cve'] == ['disputed']:
        args['cve'] = hound.get_disputed_cves()
    else:
        known_cves = hound.get_all_cves()
        for i, cve in enumerate(args['cve']):
            if not cve.startswith('CVE-'):
                cve = 'CVE-' + cve
                args['cve'][i] = cve
            if not cve_id.match(cve):
                print('Wrong CVE-ID:', cve, file=sys.stderr)
                sys.exit(1)
            if cve not in known_cves:
                print('Unknown CVE:', cve, file=sys.stderr)
                sys.exit(1)

    for file in args['exclude']:
        if os.path.exists(file):
            args['exclude'].remove(file)
            with open(file, 'rt', encoding='utf-8') as fh:
                for line in fh:
                    line = line.strip()
                    if line == '' or line.startswith('#'):
                        continue
                    if not line.startswith('CVE-'):
                        line = 'CVE-' + line
                    if not cve_id.match(line):
                        print('Wrong CVE-ID:', line, 'in file', file, file=sys.stderr)
                        sys.exit(1)
                    args['exclude'].append(line)

    for i, cve in enumerate(args['exclude']):
        if not cve.startswith('CVE-'):
            cve = 'CVE-' + cve
            args['exclude'][i] = cve
        if not cve_id.match(cve):
            print('Wrong CVE-ID:', cve, file=sys.stderr)
            sys.exit(1)

    if args['all_files'] and args['files']:
        print('--files filter and --all-files are not compatible', file=sys.stderr)
        sys.exit(1)
    if args['all_files'] and args['ignore_files']:
        print('--ignore-files filter and --all-files are not compatible', file=sys.stderr)
        sys.exit(1)
    for f in [*args['files'], *args['ignore_files']]:
        path = re.compile(r'^[_a-zA-Z-./0-9]+$')
        if not path.match(f):
            print('Wrong file filter:', f, file=sys.stderr)
            sys.exit(1)

    filter_cwes = frozenset(args['cwe'])
    cves = []
    for cve in args['cve']:
        if cve in args['exclude']:
            continue
        if args['exploit'] and not hound.get_cve_exploit(cve):
            continue
        if args['cwe']:
            rule_cwe_desc = hound.get_cve_cwe(cve)
            if not rule_cwe_desc:
                continue
            rule_cwes = frozenset(CWE[rule_cwe_desc])
            if not (rule_cwes & filter_cwes):
                continue
        if args['files']:
            add = False
            for rulefile in hound.get_rule_files(cve):
                if any(map(lambda x: rulefile.startswith(x), args['files'])):
                    add = True
                    break
            if not add:
                continue
        if args['ignore_files']:
            ignore = True
            for rulefile in hound.get_rule_files(cve):
                if all(map(lambda x: not rulefile.startswith(x) and not rulefile.endswith('.h'), args['ignore_files'])):
                    ignore = False
                    break
            if ignore:
                continue
        cves.append(cve)

    args['files'].sort()
    args['ignore_files'].sort()
    args['cwe'].sort()
    args['cve'] = sorted(cves)

    report = { 'args': {}, 'kernel': {}, 'config': {}, 'tools': {}, 'results': {}}
    report['args']['cve'] = args['cve']
    report['args']['kernel'] = args['kernel']
    report['args']['config'] = args['kernel_config']
    report['args']['only_cwe'] = args['cwe']
    report['args']['only_files'] = args['files']
    report['args']['all_files'] = args['all_files']
    report['args']['check_strict'] = args['check_strict']
    report['kernel'] = get_kernel_version(args['kernel'])
    if args['kernel_config'] != '-':
        report['config'] = config_info
    report['tools']['cvehound'] = get_cvehound_version()
    report['tools']['spatch'] = '.'.join(list(str(get_spatch_version())))

    with concurrent.futures.ProcessPoolExecutor(max_workers=os.cpu_count()) as executor:
        future_to_cve = { executor.submit(hound.check_cve, cve, args['all_files']): cve
                          for cve in args['cve'] }

        for future in concurrent.futures.as_completed(future_to_cve):
            cve = future_to_cve[future]
            try:
                result = future.result()
                if result:
                    report['results'][cve] = result
            except subprocess.CalledProcessError as e:
                logging.error('Failed to run: ' + ' '.join(e.cmd) + '\nError: ' + e.stderr)
            except UnsupportedVersion as err:
                logging.error('Skipping: ' + err.cve + ' requires spatch >= ' + err.rule_version)

    if args['report']:
        with open(args['report'], 'wt', encoding='utf-8') as fh:
            json.dump(report, fh, indent=4, sort_keys=True)
        print('Report saved to:', args['report'])

if __name__ == '__main__':
    main(sys.argv[1:])
