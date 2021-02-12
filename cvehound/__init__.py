#!/usr/bin/env python3

import os
import sys
import argparse
import re
import subprocess
from subprocess import PIPE
import pkg_resources
from cvehound.cpu import CPU
from cvehound.kbuild import Makefile
from cvehound.exception import UnsupportedVersion
from cvehound.util import get_spatch_version, get_all_cves, get_cves_metadata, removeprefix

__VERSION__ = '0.2.1'


class CVEhound:

    def __init__(self, kernel):
        self.kernel = kernel
        self.metadata = get_cves_metadata()
        self.cocci_job = str(CPU().get_cocci_jobs())
        self.spatch_version = get_spatch_version()
        self.rules_metadata = {}
        self.cve_rules = get_all_cves()

        ipaths = [
            'arch/x86/include',
            'arch/x86/include/generated',
            'arch/x86/include/uapi',
            'arch/x86/include/generated/uapi',
            'include',
            'include/uapi',
            'include/generated/uapi'
        ]
        ipaths = map(lambda f: os.path.join(kernel, f), ipaths)
        includes = []
        for i in ipaths:
            includes.append('-I')
            includes.append(i)
        self.includes = includes

        mk = Makefile(kernel)
        mk.scan()
        mk.process()
        self.mk = mk

    def get_grep_pattern(self, rule):
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

    def check_cve(self, cve, verbose=0, all_files=False):
        is_grep = False
        rule = self.cve_rules[cve]
        if rule.endswith('.grep'):
            is_grep = True

        files = []
        if not all_files:
            files = self.get_rule_files(cve)
            files = map(lambda f: os.path.join(self.kernel, f), files)
            files = filter(lambda f: os.path.exists(f), files)
            files = list(files)
        if not files:
            files = [ self.kernel ]

        includes = self.includes.copy()
        kconfig = os.path.join(self.kernel, 'include/linux/kconfig.h')
        if os.path.exists(kconfig):
            includes.append('--include')
            includes.append(kconfig)

        if verbose:
            print('Checking:', cve)

        output = ''
        run = None
        if not is_grep:
            rule_ver = self.get_rule_version(cve)
            if rule_ver and rule_ver > self.spatch_version:
                raise UnsupportedVersion(self.spatch_version, cve, rule_ver)
            try:
                cocci_cmd = ['spatch', '--no-includes', '--include-headers',
                             '-D', 'detect', '--no-show-diff', '-j', self.cocci_job,
                             *includes,
                             '--chunksize', '1',
                             '--cocci-file', rule, *files]

                if verbose > 2:
                    print(*cocci_cmd)

                run = subprocess.run(cocci_cmd, stdout=PIPE, stderr=PIPE, check=True)
                output = run.stdout.decode('utf-8').strip()
            except subprocess.CalledProcessError as e:
                err = e.stderr.decode('utf-8').split('\n')[-2]
                # Coccinelle 1.0.4 bug workaround
                if ('Sys_error("' + cve + ': No such file or directory")') not in err:
                    raise e
        else:
            (is_fix, patterns) = self.get_grep_pattern(rule)
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
                    output = run.stdout.strip()
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

            configs = { 'enabled': [], 'disabled': [] }
            for line in output.split('\n'):
                if not line:
                    continue
                path = line.split(':')[0].strip()
                conf = self.mk.file_config.get(path, None)
                if conf:
                    configs['enabled'].extend(conf['enabled'])
                    configs['disabled'].extend(conf['disabled'])

            if verbose:
                info = self.metadata[cve]
                if 'cmt_msg' in info:
                    print('MSG:', info['cmt_msg'])
                if 'cwe' in info:
                    print('CWE:', info['cwe'])
                if 'last_modified' in info:
                    print('CVE UPDATED:', info['last_modified'])
                print('https://www.linuxkernelcves.com/cves/' + cve)

                if configs['enabled']:
                    print('Depends on enabled configs:', ' || '.join(set(configs['enabled'])))
                if configs['disabled']:
                    print('Depends on disabled configs:', ' && '.join(set(configs['disabled'])))
                if verbose > 1:
                    print(output)
                print()

            return True
        return False

    def get_rule_metadata(self, cve):
        files = []
        fix = None
        fixes = None
        version = 0

        if cve in self.rules_metadata:
            return self.rules_metadata[cve]

        with open(self.cve_rules[cve], 'rt') as fh:
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
        self.rules_metadata[cve] = meta
        return meta

    def get_cve_metadata(self, cve):
        return self.metadata.get(cve, None)

    def get_cve_cwe(self, cve):
        return self.metadata[cve].get('cwe', None)

    def get_cves(self):
        return self.cve_rules.keys()

    def get_rule(self, cve):
        return self.cve_rules[cve]

    def get_rule_fix(self, cve):
        return self.get_rule_metadata(cve)['fix']

    def get_rule_fixes(self, cve):
        return self.get_rule_metadata(cve)['fixes']

    def get_rule_files(self, cve):
        return self.get_rule_metadata(cve)['files']

    def get_rule_version(self, cve):
        return self.get_rule_metadata(cve)['version']
