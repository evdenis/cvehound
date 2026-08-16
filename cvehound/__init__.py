#!/usr/bin/env python3

import collections
import logging
import os
import subprocess
import sys
from datetime import UTC, datetime
from typing import Any

from sympy.logic import simplify_logic

from cvehound.config import Config
from cvehound.exception import UnsupportedVersion
from cvehound.kbuild import KbuildParser
from cvehound.util import (
    get_cves_metadata,
    get_rule_cves,
    get_spatch_version,
    parse_coccinelle_output,
)

__VERSION__ = '1.2.1'

RuleMetadata = dict[str, Any]


class CVEhound:
    def __init__(
        self,
        kernel: str,
        metadata: str | None = None,
        config: str | None = None,
        check_strict: bool = False,
        arch: str = 'x86',
    ) -> None:
        kernel = os.path.abspath(kernel)
        self.kernel = kernel
        self.metadata: dict[str, Any] = get_cves_metadata(metadata)
        self.spatch_version = get_spatch_version()
        self.check_strict = check_strict
        self.rules_metadata: dict[str, RuleMetadata] = {}
        (self.cve_all_rules, self.cve_assigned_rules, self.cve_disputed_rules) = get_rule_cves()

        ipaths = [
            os.path.join('arch', arch, 'include'),
            os.path.join('arch', arch, 'include/generated'),
            os.path.join('arch', arch, 'include/uapi'),
            os.path.join('arch', arch, 'include/generated/uapi'),
            'include',
            'include/uapi',
            'include/generated/uapi',
        ]
        includes: list[str] = []
        for ipath in ipaths:
            includes.append('-I')
            includes.append(os.path.join(kernel, ipath))
        self.includes = includes

        self.config_file: str | None = None
        self.config_map: dict[str, str] | None = None
        self.config: Config | None = None

        if config:
            kbuild_parser = KbuildParser(None, arch)
            dirs_to_process: dict[str, Any] = collections.OrderedDict()
            kbuild_parser.init_class.process(kbuild_parser, dirs_to_process, kernel)

            for item in dirs_to_process:
                descend = kbuild_parser.init_class.get_file_for_subdirectory(item)
                kbuild_parser.process_kbuild_or_makefile(descend, dirs_to_process[item])

            self.config_map = kbuild_parser.get_config()
            if config != '-':
                self.config_file = config
                self.config = Config(config)

        if self.spatch_version <= 104:
            logging.warning(
                'spatch (coccinelle) version is too old.\n'
                'Please, consider updating to >= 1.0.7 version.'
            )

    def get_grep_pattern(self, rule: str) -> list[str]:
        patterns: list[str] = []
        with open(rule) as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                if line.startswith('//'):
                    continue
                patterns.append(line)
        return patterns

    def _print_found_cve(self, cve: str) -> None:
        logging.warning('Found: ' + cve)
        if cve in self.metadata:
            info = self.metadata[cve]
            if 'cmt_msg' in info:
                logging.info('MSG: ' + info['cmt_msg'])
            if 'fix_date' in info:
                logging.info(
                    'FIX DATE: '
                    + datetime.fromtimestamp(info['fix_date'], tz=UTC).strftime('%Y-%m-%d')
                )
        logging.info('https://www.cve.org/CVERecord?id=' + cve)

    def _print_affected_files(self, config: dict[str, Any]) -> None:
        if 'files' in config and config['files']:
            logging.info('Affected Files:')
            for file in config['files']:
                logic = config['files'][file]['logic']
                if self.config:
                    affected = 'affected' if config['files'][file]['config'] else 'not affected'
                    logging.info(
                        ' - ' + file + ': ' + logic + '\n   ' + self.config_file + ': ' + affected
                    )
                else:
                    logging.info(' - ' + file + ': ' + logic)

        if 'affected' not in config or config['affected'] is None:
            return
        config_affected = 'affected' if config['affected'] else 'not affected'
        if self.config and self.config_file:
            logging.info('Config: ' + self.config_file + ' ' + config_affected)
        else:
            logging.info('Config: any ' + config_affected)

    def check_cve(self, cve: str, all_files: bool = False) -> dict[str, Any] | bool:
        result: dict[str, Any] = {}
        is_grep = False
        rule = self.cve_all_rules[cve]
        if rule.endswith('.grep'):
            is_grep = True

        files: list[str] = []
        if not all_files:
            rule_files = self.get_rule_files(cve)
            files = [
                os.path.join(self.kernel, f)
                for f in rule_files
                if os.path.exists(os.path.join(self.kernel, f))
            ]
        if not files:
            files = [self.kernel]

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
                cocci_cmd = [
                    'spatch',
                    '--no-includes',
                    '--include-headers',
                    '-D',
                    'detect',
                    '--chunksize',
                    '1',
                    '-j',
                    '1',
                    '--no-show-diff',
                    '--very-quiet',
                    *includes,
                ]
                if self.spatch_version > 104:  # Not supported on coccinelle 1.0.4
                    cocci_cmd.extend(['--python', os.path.realpath(sys.executable)])
                cocci_cmd.extend(['--cocci-file', rule, *files])

                logging.debug(' '.join(cocci_cmd))

                run = subprocess.run(cocci_cmd, capture_output=True, check=True, text=True)
                output = run.stdout.strip()
            except subprocess.CalledProcessError as e:
                err = e.stderr.split('\n')[-2]
                # Coccinelle 1.0.4 bug workaround
                if ('Sys_error("' + cve + ': No such file or directory")') not in err:
                    raise e
        else:
            for pattern in self.get_grep_pattern(rule):
                args = ['grep', '-rPzle', pattern, *files]
                run = subprocess.run(args, capture_output=True, check=False, text=True)
                if run.returncode != 0:
                    break
                output += run.stdout.strip()
            else:
                # Found all patterns
                output += '\nERROR'

        if 'ERROR' not in output:
            return False

        config_result: dict[str, Any] = {}
        if self.config_map:
            kernel_files: dict[str, str] = {}
            for line in output.split('\n'):
                file_list: list[str] = []
                if not is_grep:
                    file_list = [line.split(':')[0]]
                else:
                    while True:
                        try:
                            rindex = line.rindex(self.kernel)
                        except ValueError:
                            break
                        file_list.append(line[rindex:])
                        line = line[:rindex]
                for f in file_list:
                    if os.path.isfile(f):
                        kernel_files[f] = self.config_map.get(f, '')
            if kernel_files:
                config_affected: bool | None = None
                if 'files' not in config_result:
                    config_result['files'] = {}
                for kfile, kconfig in kernel_files.items():
                    rel_file = kfile[len(self.kernel) + 1 :]
                    result_file: dict[str, Any] = {}
                    if kconfig:
                        simplified = simplify_logic(kconfig)
                        result_file['logic'] = str(simplified)
                        if self.config:
                            affected = simplified.subs(self.config.get_mapping())
                            if affected:
                                result_file['config'] = True
                                config_affected = True
                            else:
                                result_file['config'] = False
                                if config_affected is None:
                                    config_affected = False
                    else:
                        # No config constraint for this file
                        result_file['logic'] = str(True)
                        result_file['config'] = True
                        config_affected = True
                    config_result['files'][rel_file] = result_file
                if config_affected is not None:
                    config_result['affected'] = config_affected

        if (
            self.check_strict and 'affected' in config_result and config_result['affected']
        ) or not self.check_strict:
            if cve in self.metadata:
                result = self.metadata[cve]
            result['config'] = config_result
            result['spatch_output'] = output
            if not is_grep:
                result['files'] = parse_coccinelle_output(output)
            else:
                result['files'] = [{'file': x} for x in files]
            self._print_found_cve(cve)
            self._print_affected_files(config_result)
            logging.debug(output)
            logging.info('')
        else:
            return False

        return result

    def get_rule_metadata(self, cve: str) -> RuleMetadata:
        files: list[str] = []
        fix: str | None = None
        fixes: str | None = None
        version: int | str = 0

        if cve in self.rules_metadata:
            return self.rules_metadata[cve]

        with open(self.cve_all_rules[cve]) as fh:
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

        meta = {'files': files, 'fix': fix, 'fixes': fixes, 'version': version}
        self.rules_metadata[cve] = meta
        return meta

    def get_cve_metadata(self, cve: str) -> dict[str, Any]:
        result: dict[str, Any] = self.metadata.get(cve, {})
        return result

    def get_cve_exploit(self, cve: str) -> bool:
        exploit: bool = self.get_cve_metadata(cve).get('exploit', False)
        return exploit

    def get_all_cves(self) -> set[str]:
        return set(self.cve_all_rules.keys())

    def get_assigned_cves(self) -> set[str]:
        return set(self.cve_assigned_rules.keys())

    def get_disputed_cves(self) -> set[str]:
        return set(self.cve_disputed_rules.keys())

    def get_rule(self, cve: str) -> str:
        return self.cve_all_rules[cve]

    def get_rule_fix(self, cve: str) -> str | None:
        fix: str | None = self.get_rule_metadata(cve)['fix']
        return fix

    def get_rule_fixes(self, cve: str) -> str | None:
        fixes: str | None = self.get_rule_metadata(cve)['fixes']
        return fixes

    def get_rule_files(self, cve: str) -> list[str]:
        files: list[str] = self.get_rule_metadata(cve)['files']
        return files

    def get_rule_version(self, cve: str) -> int:
        version: int = self.get_rule_metadata(cve)['version']
        return version
