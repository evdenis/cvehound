#!/usr/bin/env python3

import os
import sys
import subprocess
import logging
from subprocess import PIPE
import collections
from datetime import datetime
from sympy.logic import simplify_logic
from cvehound.exception import UnsupportedVersion
from cvehound.util import get_spatch_version, get_rule_cves, get_cves_metadata, parse_coccinelle_output
from cvehound.kbuild import KbuildParser
from cvehound.config import Config

__VERSION__ = '1.2.1'


class CVEhound:

    def __init__(self, kernel, metadata=None, config=None, check_strict=False, arch='x86'):
        kernel = os.path.abspath(kernel)
        self.kernel = kernel
        self.metadata = get_cves_metadata(metadata)
        self.spatch_version = get_spatch_version()
        self.check_strict = check_strict
        self.rules_metadata = {}
        (self.cve_all_rules, self.cve_assigned_rules, self.cve_disputed_rules) = get_rule_cves()

        ipaths = [
            os.path.join('arch', arch, 'include'),
            os.path.join('arch', arch, 'include/generated'),
            os.path.join('arch', arch, 'include/uapi'),
            os.path.join('arch', arch, 'include/generated/uapi'),
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

        if config:
            parser = KbuildParser(None, arch)
            dirs_to_process = collections.OrderedDict()
            parser.init_class.process(parser, dirs_to_process, kernel)

            for item in dirs_to_process:
                descend = parser.init_class.get_file_for_subdirectory(item)
                parser.process_kbuild_or_makefile(descend, dirs_to_process[item])

            self.config_map = parser.get_config()
            if config != '-':
                self.config_file = config
                self.config = Config(config)
            else:
                self.config_file = None
                self.config = None
        else:
            self.config_file = None
            self.config_map = None
            self.config = None

        if self.spatch_version <= 104:
            logging.warning('spatch (coccinelle) version is too old.\n'
                            'Please, consider updating to >= 1.0.7 version.')

    def get_grep_pattern(self, rule):
        patterns = []
        with open(rule, 'rt') as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                if line.startswith('//'):
                    continue
                if line:
                    patterns.append(line)
        return patterns

    def _print_found_cve(self, cve):
        logging.warning('Found: ' + cve)
        if cve in self.metadata:
            info = self.metadata[cve]
            if 'cmt_msg' in info:
                logging.info('MSG: ' + info['cmt_msg'])
            if 'cwe' in info:
                logging.info('CWE: ' + info['cwe'])
            if 'cvss2' in info and 'score' in info['cvss2']:
                logging.info('CVSS2: ' + str(info['cvss2']['score']))
            if 'cvss3' in info and 'score' in info['cvss3']:
                logging.info('CVSS3: ' + str(info['cvss3']['score']))
            if 'fix_date' in info:
                logging.info('FIX DATE: ' + str(datetime.utcfromtimestamp(info['fix_date']).strftime('%Y-%m-%d')))
        logging.info('https://www.linuxkernelcves.com/cves/' + cve)

    def _print_affected_files(self, config):
        if 'files' in config and config['files']:
            logging.info('Affected Files:')
            for file in config['files']:
                logic = config['files'][file]['logic']
                if self.config:
                    affected = 'affected' if config['files'][file]['config'] else 'not affected'
                    logging.info(' - ' + file + ': ' + logic + '\n   ' + self.config_file + ': ' + affected)
                else:
                    logging.info(' - ' + file + ': ' + logic)

        if 'affected' not in config or config['affected'] == None:
            return
        config_affected = 'affected' if config['affected'] else 'not affected'
        if self.config:
            logging.info('Config: ' + self.config_file + ' ' + config_affected)
        else:
            logging.info('Config: any ' + config_affected)

    def check_cve(self, cve, all_files=False):
        result = {}
        is_grep = False
        rule = self.cve_all_rules[cve]
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

        logging.debug('Checking: ' + cve)

        output = ''
        run = None
        if not is_grep:
            rule_ver = self.get_rule_version(cve)
            if rule_ver and rule_ver > self.spatch_version:
                raise UnsupportedVersion(self.spatch_version, cve, rule_ver)
            try:
                cocci_cmd = ['spatch', '--no-includes', '--include-headers',
                             '-D', 'detect', '--chunksize', '1', '-j', '1',
                             '--no-show-diff', '--very-quiet',
                             *includes]
                if self.spatch_version > 104: # Not suppored on coccinelle 1.0.4
                    cocci_cmd.extend(['--python', os.path.realpath(sys.executable)])
                cocci_cmd.extend(['--cocci-file', rule, *files])

                logging.debug(' '.join(cocci_cmd))

                run = subprocess.run(cocci_cmd, stdout=PIPE, stderr=PIPE, check=True, universal_newlines=True)
                output = run.stdout.strip()
            except subprocess.CalledProcessError as e:
                err = e.stderr.split('\n')[-2]
                # Coccinelle 1.0.4 bug workaround
                if ('Sys_error("' + cve + ': No such file or directory")') not in err:
                    raise e
        else:
            for pattern in self.get_grep_pattern(rule):
                args = ['grep', '-rPzle', pattern, *files]
                run = subprocess.run(args, stdout=PIPE, stderr=PIPE, check=False, universal_newlines=True)
                if run.returncode != 0:
                    break
                output += run.stdout.strip()
            else:
                # Found all patterns
                output += '\nERROR'

        if 'ERROR' not in output:
            return False

        config_result = {}
        if self.config_map:
            kernel_files = {}
            for line in output.split('\n'):
                file = []
                if not is_grep:
                    file = [ line.split(':')[0] ]
                else:
                    while True:
                        try:
                            rindex = line.rindex(self.kernel)
                        except ValueError:
                            break
                        file.append(line[rindex:])
                        line = line[:rindex]
                for f in filter(lambda f: os.path.isfile(f), file):
                    kernel_files[f] = self.config_map.get(f, '')
            if kernel_files:
                config_affected = None
                if 'files' not in config_result:
                    config_result['files'] = {}
                for file, config in kernel_files.items():
                    rel_file = file[len(self.kernel)+1:]
                    result_file = {}
                    if config:
                        config = simplify_logic(config)
                        result_file['logic'] = str(config)
                        if self.config:
                            affected = config.subs(self.config.get_mapping())
                            if affected == True:
                                result_file['config'] = True
                                config_affected = True
                            else:
                                result_file['config'] = False
                                if config_affected == None:
                                    config_affected = False
                    elif not file.endswith('.h'):
                        result_file['logic'] = str(True)
                        result_file['config'] = True
                        config_affected = True
                    elif file.endswith('.h'): # FIXME: only .h file?
                        result_file['logic'] = str(True)
                        result_file['config'] = True
                        config_affected = True
                    config_result['files'][rel_file] = result_file
            if config_affected != None:
                config_result['affected'] = config_affected

        if self.check_strict and 'affected' in config_result and config_result['affected'] or not self.check_strict:
            if cve in self.metadata:
                result = self.metadata[cve]
            result['config'] = config_result
            result['spatch_output'] = output
            if not is_grep:
                result['files'] = parse_coccinelle_output(output)
            else:
                result['files'] = list(map(lambda x: { "file": x } , files))
            self._print_found_cve(cve)
            self._print_affected_files(config_result)
            logging.debug(output)
            logging.info('')
        else:
            return False

        return result

    def get_rule_metadata(self, cve):
        files = []
        fix = None
        fixes = None
        version = 0

        if cve in self.rules_metadata:
            return self.rules_metadata[cve]

        with open(self.cve_all_rules[cve], 'rt') as fh:
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
        return self.metadata.get(cve, {})

    def get_cve_cwe(self, cve):
        return self.get_cve_metadata(cve).get('cwe', None)

    def get_cve_exploit(self, cve):
        return self.get_cve_metadata(cve).get('exploit', False)

    def get_all_cves(self):
        return set(self.cve_all_rules.keys())

    def get_assigned_cves(self):
        return set(self.cve_assigned_rules.keys())

    def get_disputed_cves(self):
        return set(self.cve_disputed_rules.keys())

    def get_rule(self, cve):
        return self.cve_all_rules[cve]

    def get_rule_fix(self, cve):
        return self.get_rule_metadata(cve)['fix']

    def get_rule_fixes(self, cve):
        return self.get_rule_metadata(cve)['fixes']

    def get_rule_files(self, cve):
        return self.get_rule_metadata(cve)['files']

    def get_rule_version(self, cve):
        return self.get_rule_metadata(cve)['version']
