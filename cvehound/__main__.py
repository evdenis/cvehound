#!/usr/bin/env python3

import sys
import argparse
import re
import subprocess
import logging

from cvehound import CVEhound
from cvehound.util import get_cvehound_version, dir_path, tool_exists
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
    parser.add_argument('--cwe', nargs='+', default=[], type=int,
                        help='check only for CWE-ids')
    parser.add_argument('--files', nargs='+', default=[],
                        help='check only files (e.g. drivers/block/floppy.c arch/x86)')
    parser.add_argument('--kernel', '-k', type=dir_path, required=True,
                        help='linux kernel sources dir')
    parser.add_argument('-v', '--verbose', action='count', default=0,
                        help='increase output verbosity')
    cmdargs = parser.parse_args()

    if not tool_exists('spatch'):
        print('Please, install coccinelle.')
        sys.exit(1)

    hound = CVEhound(cmdargs.kernel)

    known_cves = hound.get_cves()
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

    filter_cwes = frozenset(cmdargs.cwe)

    if cmdargs.all_files and not cmdargs.files:
        print('--files filter and --all-files are not compatible', file=sys.stderr)
        sys.exit(1)
    for f in cmdargs.files:
        path = re.compile(r'^[a-zA-Z-./0-9]+$')
        if not path.match(f):
            print('Wrong file filter:', f, file=sys.stderr)
            sys.exit(1)

    loglevel = logging.WARNING
    if cmdargs.verbose > 1:
        loglevel = logging.DEBUG
    elif cmdargs.verbose > 0:
        loglevel = logging.INFO
    logging.basicConfig(level=loglevel, format='%(message)s')

    for cve in cmdargs.cve:
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
        try:
            hound.check_cve(cve, cmdargs.all_files)
        except subprocess.CalledProcessError as e:
            logging.error('Failed to run: ', ' '.join(e.cmd))
        except UnsupportedVersion as err:
            logging.error('Skipping: ' + err.cve + ' requires spatch >= ' + err.rule_version)

if __name__ == '__main__':
    main(sys.argv[1:])
