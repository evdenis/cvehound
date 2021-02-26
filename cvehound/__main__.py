#!/usr/bin/env python3

import sys
import argparse
import re
import subprocess

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
    parser.add_argument('--cwe', nargs='+', default=[],
                        help='check only for CWE-ids')
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
    filter_cwes = set()
    for cwe in cmdargs.cwe:
        try:
            filter_cwes.add(int(cwe))
        except Exception:
            print('Unknown CWE-id:', cwe, file=sys.stderr)
            sys.exit(1)
    for cve in cmdargs.cve:
        if cmdargs.cwe:
            rule_cwe_desc = hound.get_cve_cwe(cve)
            if not rule_cwe_desc:
                continue
            rule_cwes = frozenset(CWE[rule_cwe_desc])
            if not (rule_cwes & filter_cwes):
                continue
        try:
            hound.check_cve(cve, cmdargs.verbose, cmdargs.all_files)
        except subprocess.CalledProcessError as e:
            print('Failed to run: ', ' '.join(e.cmd))
        except UnsupportedVersion as err:
            print('Skipping: ' + err.cve + ' requires spatch >= ' + err.rule_version)

if __name__ == '__main__':
    main(sys.argv[1:])
