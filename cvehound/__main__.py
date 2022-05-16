#!/usr/bin/env python3

import os
import sys
import argparse
import re
import subprocess
import logging
import json

from cvehound import CVEhound
from cvehound.util import *
from cvehound.exception import UnsupportedVersion
from cvehound.cwe import CWE

def main(args=sys.argv[1:]):
    parser = argparse.ArgumentParser(
        prog='cvehound',
        description='A tool to check linux kernel sources dump for known CVEs',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('--kernel', '-k', metavar='DIR',
                        help='linux kernel sources dir')
    parser.add_argument('--list', action='store_true',
                        help="list all known CVEs and exit")
    parser.add_argument('--cve', '-c', nargs='+', default=['assigned'],
                        help='list of cve identifiers (groups: [all, assigned, disputed])')
    parser.add_argument('--exclude', '-x', nargs='+', default=[], metavar='CVE',
                        help='list of cve identifiers to exclude from check')
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
    parser.add_argument('--config', nargs='?', const='-', metavar='.config',
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

    if not cmdargs.kernel:
        parser.print_usage()
        print("cvehound: error: the following arguments are required: --kernel/-k", file=sys.stderr)
        sys.exit(1)

    if cmdargs.metadata:
        if not os.path.isfile(cmdargs.metadata):
            print("Can't find metadata file", cmdargs.metadata, file=sys.stderr)
            sys.exit(1)
        if not cmdargs.metadata.endswith('.gz'):
            print("Metadata file", cmdargs.metadata, "is not the gz archive", file=sys.stderr)
            sys.exit(1)

    if not all(os.path.isfile(os.path.join(cmdargs.kernel, f)) for f in
               ['Makefile']):
        print(cmdargs.kernel, "isn't a kernel directory", file=sys.stderr)
        sys.exit(1)

    if cmdargs.config == '-':
        config = os.path.normpath(os.path.join(cmdargs.kernel, '.config'))
        if os.path.isfile(config):
            cmdargs.config = config
    else:
        if cmdargs.config and not os.path.isfile(cmdargs.config):
            print("Can't find config file", cmdargs.config, file=sys.stderr)
            sys.exit(1)

    if cmdargs.config and cmdargs.verbose == 0:
        cmdargs.verbose = 1

    if cmdargs.check_strict:
        if not cmdargs.config:
            print('Please, use --check-strict with --config', file=sys.stderr)
            sys.exit(1)

    loglevel = logging.WARNING
    if cmdargs.verbose > 1:
        loglevel = logging.DEBUG
    elif cmdargs.verbose > 0:
        loglevel = logging.INFO
    logging.basicConfig(level=loglevel, format='%(message)s')

    config_info = {}
    if cmdargs.config and cmdargs.config != '-':
        config_info = get_config_data(cmdargs.config)

    hound = CVEhound(cmdargs.kernel, cmdargs.metadata, cmdargs.config,
                     cmdargs.check_strict, config_info.get('arch', 'x86'))

    cve_id = re.compile(r'^CVE-\d{4}-\d{4,7}$')
    if cmdargs.cve == ['all']:
        cmdargs.cve = hound.get_all_cves()
    elif cmdargs.cve == ['assigned']:
        cmdargs.cve = hound.get_assigned_cves()
    elif cmdargs.cve == ['disputed']:
        cmdargs.cve = hound.get_disputed_cves()
    else:
        known_cves = hound.get_all_cves()
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

    for i, cve in enumerate(cmdargs.exclude):
        if not cve.startswith('CVE-'):
            cve = 'CVE-' + cve
            cmdargs.exclude[i] = cve
        if not cve_id.match(cve):
            print('Wrong CVE-ID:', cve, file=sys.stderr)
            sys.exit(1)

    if cmdargs.all_files and cmdargs.files:
        print('--files filter and --all-files are not compatible', file=sys.stderr)
        sys.exit(1)
    if cmdargs.all_files and cmdargs.ignore_files:
        print('--ignore-files filter and --all-files are not compatible', file=sys.stderr)
        sys.exit(1)
    for f in [*cmdargs.files, *cmdargs.ignore_files]:
        path = re.compile(r'^[_a-zA-Z-./0-9]+$')
        if not path.match(f):
            print('Wrong file filter:', f, file=sys.stderr)
            sys.exit(1)

    filter_cwes = frozenset(cmdargs.cwe)
    cves = []
    for cve in cmdargs.cve:
        if cve in cmdargs.exclude:
            continue
        if cmdargs.exploit and not hound.get_cve_exploit(cve):
            continue
        if cmdargs.cwe:
            rule_cwe_desc = hound.get_cve_cwe(cve)
            if not rule_cwe_desc:
                continue
            rule_cwes = frozenset(CWE[rule_cwe_desc])
            if not (rule_cwes & filter_cwes):
                continue
        if cmdargs.files:
            add = False
            for rulefile in hound.get_rule_files(cve):
                if any(map(lambda x: rulefile.startswith(x), cmdargs.files)):
                    add = True
                    break
            if not add:
                continue
        if cmdargs.ignore_files:
            ignore = True
            for rulefile in hound.get_rule_files(cve):
                if all(map(lambda x: not rulefile.startswith(x) and not rulefile.endswith('.h'), cmdargs.ignore_files)):
                    ignore = False
                    break
            if ignore:
                continue
        cves.append(cve)
    cmdargs.cve = cves

    report = { 'args': {}, 'kernel': {}, 'config': {}, 'tools': {}, 'results': {}}
    report['args']['cve'] = cmdargs.cve
    report['args']['kernel'] = cmdargs.kernel
    report['args']['config'] = cmdargs.config
    report['args']['only_cwe'] = cmdargs.cwe
    report['args']['only_files'] = cmdargs.files
    report['args']['all_files'] = cmdargs.all_files
    report['args']['check_strict'] = cmdargs.check_strict
    report['kernel'] = get_kernel_version(cmdargs.kernel)
    if cmdargs.config != '-':
        report['config'] = config_info
    report['tools']['cvehound'] = get_cvehound_version()
    report['tools']['spatch'] = '.'.join(list(str(get_spatch_version())))
    for cve in cmdargs.cve:
        try:
            result = hound.check_cve(cve, cmdargs.all_files)
            if result:
                report['results'][cve] = result
        except subprocess.CalledProcessError as e:
            logging.error('Failed to run: ' + ' '.join(e.cmd))
        except UnsupportedVersion as err:
            logging.error('Skipping: ' + err.cve + ' requires spatch >= ' + err.rule_version)

    if cmdargs.report:
        with open(cmdargs.report, 'wt', encoding='utf-8') as fh:
            json.dump(report, fh, indent=4, sort_keys=True)
        print('Report saved to:', cmdargs.report)

if __name__ == '__main__':
    main(sys.argv[1:])
