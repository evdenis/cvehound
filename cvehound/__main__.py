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
    parser.add_argument('--version', action='version', version=get_cvehound_version())
    parser.add_argument('--all-files', action='store_true',
                        help="don't use files hint from cocci rules")
    parser.add_argument('--cve', '-c', nargs='+', default='all',
                        help='list of cve identifiers')
    parser.add_argument('--exploit', '-e', action='store_true',
                        help='check only for CVEs with exploits')
    parser.add_argument('--cwe', nargs='+', default=[], type=int,
                        help='check only for CWE-ids')
    parser.add_argument('--files', nargs='+', default=[],
                        help='check only files (e.g. drivers/block/floppy.c arch/x86)')
    parser.add_argument('--kernel', '-k', required=True,
                        help='linux kernel sources dir')
    parser.add_argument('--config', nargs='?', const='-',
                        help='check kernel config')
    parser.add_argument('--report', nargs='?', const='report.json',
                        help='output report with found CVEs')
    parser.add_argument('--report-strict', action='store_true',
                        help='include in report only CVEs included in .config')
    parser.add_argument('-v', '--verbose', action='count', default=0,
                        help='increase output verbosity')
    cmdargs = parser.parse_args()

    if not all(os.path.isfile(os.path.join(cmdargs.kernel, f)) for f in
               ['Makefile', 'MAINTAINERS']):
        print(cmdargs.kernel, "isn't a kernel directory", file=sys.stderr)
        sys.exit(1)

    if cmdargs.config == '-':
        config = os.path.join(cmdargs.kernel, '.config')
        if os.path.isfile(config):
            cmdargs.config = config
    else:
        if cmdargs.config and not os.path.isfile(cmdargs.config):
            print("Can't find config file", cmdargs.config, file=sys.stderr)
            sys.exit(1)

    if cmdargs.config and cmdargs.verbose == 0:
        cmdargs.verbose = 1

    if cmdargs.report_strict:
        if not cmdargs.report:
            cmdargs.report = 'report.json'
        if not cmdargs.config:
            print('Please, use --config with --report-strict')
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

    hound = CVEhound(cmdargs.kernel, cmdargs.config, config_info.get('arch', 'x86'))

    known_cves = hound.get_known_cves()
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

    if cmdargs.all_files and cmdargs.files:
        print('--files filter and --all-files are not compatible', file=sys.stderr)
        sys.exit(1)
    for f in cmdargs.files:
        path = re.compile(r'^[a-zA-Z-./0-9]+$')
        if not path.match(f):
            print('Wrong file filter:', f, file=sys.stderr)
            sys.exit(1)

    filter_cwes = frozenset(cmdargs.cwe)
    cves = []
    for cve in cmdargs.cve:
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
            found = False
            for rulefile in hound.get_rule_files(cve):
                for filterdir in cmdargs.files:
                    if rulefile.startswith(filterdir):
                        found = True
            if not found:
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
    report['kernel'] = get_kernel_version(cmdargs.kernel)
    if cmdargs.config != '-':
        report['config'] = config_info
    report['tools']['cvehound'] = get_cvehound_version()
    report['tools']['spatch'] = '.'.join(list(str(get_spatch_version())))
    for cve in cmdargs.cve:
        try:
            result = hound.check_cve(cve, cmdargs.all_files)
            if result and (not cmdargs.report_strict or result['config']['affected']):
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
