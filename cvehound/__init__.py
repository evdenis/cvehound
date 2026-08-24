#!/usr/bin/env python3

import functools
import logging
import os
import subprocess
import sys
from typing import Any

from sympy.logic import simplify_logic

from cvehound.config import Config
from cvehound.exception import SpatchError, UnsupportedVersion
from cvehound.kbuild import KbuildParser
from cvehound.util import (
    fix_date_str,
    get_cves_metadata,
    get_rule_cves,
    get_spatch_version,
    get_srcarch,
    parse_coccinelle_output,
)

__VERSION__ = '1.3.0'

RuleMetadata = dict[str, Any]

# Sources that become object files, i.e. the ones the Kbuild map can describe.
COMPILED_SUFFIXES = ('.c', '.S', '.s', '.rs')

# Force-included into every spatch run when the tree has it; the test harness
# mirrors this probe when it materializes mini-trees (tests/kerneltree.py).
KCONFIG_H = 'include/linux/kconfig.h'


@functools.cache
def _simplify_condition(logic: str) -> Any:
    """Cache sympy's (expensive) minimization: the same few hot-file
    conditions are evaluated for many CVEs in every worker."""
    return simplify_logic(logic)


def evaluate_file_condition(
    logic: str | None, relpath: str, srcarch: str, config: Config | None
) -> tuple[str, bool | None]:
    """Evaluate one file's Kbuild CONFIG condition against a .config.

    @logic is the raw condition from the Kbuild map: None when the file is
    unknown to the parser, '' when the file is built unconditionally.
    Returns the printable condition and the affected verdict; the verdict
    is None when there is no .config to evaluate against.
    """
    if relpath.startswith('arch/') and not relpath.startswith('arch/' + srcarch + '/'):
        # Sources of another architecture are never built into this kernel.
        text, affected = 'False', False
    elif logic is None:
        # Unknown to the parser: assume built (prefer a false positive).
        text, affected = 'unknown', True
    elif logic == '':
        text, affected = 'True', True
    else:
        simplified = _simplify_condition(logic)
        if config is None:
            return (str(simplified), None)
        # Kconfig is closed-world: a symbol absent from the .config is
        # disabled, so substitute every free symbol; Config lookups
        # default to False.
        subs = {sym: config[str(sym)] for sym in simplified.free_symbols}
        return (str(simplified), bool(simplified.subs(subs)))

    return (text, affected if config is not None else None)


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
        self.arch = arch
        self.srcarch = get_srcarch(arch)
        self.rules_metadata: dict[str, RuleMetadata] = {}
        (self.cve_all_rules, self.cve_assigned_rules, self.cve_disputed_rules) = get_rule_cves()

        self.ipaths = [
            os.path.join('arch', self.srcarch, 'include'),
            os.path.join('arch', self.srcarch, 'include/generated'),
            os.path.join('arch', self.srcarch, 'include/uapi'),
            os.path.join('arch', self.srcarch, 'include/generated/uapi'),
            'include',
            'include/uapi',
            'include/generated/uapi',
        ]

        self.config_file: str | None = None
        self.config_map: dict[str, str] | None = None
        self.config: Config | None = None

        if config:
            self.config_map = KbuildParser(None, arch, kernel).parse_tree()
            if not self.config_map:
                logging.warning(
                    "Couldn't map any kernel file to CONFIG_ options: "
                    'every finding will be reported as affected'
                )
            if config != '-':
                self.config_file = config
                self.config = Config(config)

        if self.spatch_version < 110:
            logging.warning(
                'spatch (coccinelle) versions older than 1.1.0 are not supported.\n'
                'Please, update to coccinelle >= 1.1.0.'
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
                logging.info('FIX DATE: ' + fix_date_str(info['fix_date']))
        logging.info('https://www.cve.org/CVERecord?id=' + cve)

    def _print_affected_files(self, config: dict[str, Any]) -> None:
        if 'files' in config and config['files']:
            logging.info('Affected Files:')
            for file in config['files']:
                entry = config['files'][file]
                logic = entry['logic']
                verdict = entry.get('config')
                if verdict is not None and self.config_file:
                    affected = 'affected' if verdict else 'not affected'
                    logging.info(
                        ' - ' + file + ': ' + logic + '\n   ' + self.config_file + ': ' + affected
                    )
                else:
                    logging.info(' - ' + file + ': ' + logic)

        if 'affected' not in config or config['affected'] is None:
            return
        config_affected = 'affected' if config['affected'] else 'not affected'
        if self.config is not None and self.config_file:
            logging.info('Config: ' + self.config_file + ' ' + config_affected)
        else:
            logging.info('Config: any ' + config_affected)

    def check_cve(self, cve: str, all_files: bool = False, jobs: int = 1) -> dict[str, Any] | bool:
        result: dict[str, Any] = {}
        is_grep = False
        rule = self.cve_all_rules[cve]
        if rule.endswith('.grep'):
            is_grep = True

        if all_files:
            files = [self.kernel]
        else:
            rule_files = self.get_rule_files(cve)
            files = [
                os.path.join(self.kernel, f)
                for f in rule_files
                if os.path.exists(os.path.join(self.kernel, f))
            ]
            if not files:
                logging.debug('Skipping %s: none of the hinted files exist', cve)
                return False

        # Built from self.kernel per call so a shallow copy pointed at another
        # tree (tests/kerneltree.py hound_at) needs no include rewriting.
        includes: list[str] = []
        for ipath in self.ipaths:
            includes.append('-I')
            includes.append(os.path.join(self.kernel, ipath))
        kconfig = os.path.join(self.kernel, KCONFIG_H)
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
            cocci_cmd = [
                'spatch',
                '--no-includes',
                '--include-headers',
                '-D',
                'detect',
                '--chunksize',
                '1',
                '-j',
                str(jobs),
                '--no-show-diff',
                '--very-quiet',
                *includes,
                '--python',
                os.path.realpath(sys.executable),
                '--cocci-file',
                rule,
                *files,
            ]

            logging.debug(' '.join(cocci_cmd))

            run = subprocess.run(cocci_cmd, capture_output=True, check=False, text=True)
            if run.returncode != 0:
                raise SpatchError(cve, self.kernel, run.returncode, run.stderr)
            output = run.stdout.strip()
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
        if self.config_map is not None:
            kernel_files: dict[str, str | None] = {}
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
                        kernel_files[f] = self.config_map.get(f)
            if kernel_files:
                verdicts: list[bool] = []
                config_result['files'] = {}
                for kfile, kconfig in kernel_files.items():
                    rel_file = kfile[len(self.kernel) + 1 :]
                    logic, affected = evaluate_file_condition(
                        kconfig, rel_file, self.srcarch, self.config
                    )
                    result_file: dict[str, Any] = {
                        'logic': logic,
                        'mapped': kconfig is not None,
                    }
                    if logic == 'unknown':
                        # Only compilation units are expected in the map;
                        # headers and the like are never built on their own.
                        report = (
                            logging.warning
                            if rel_file.endswith(COMPILED_SUFFIXES)
                            else logging.debug
                        )
                        report('No Kbuild mapping for ' + rel_file + ': assuming the file is built')
                    if affected is not None:
                        result_file['config'] = affected
                        verdicts.append(affected)
                    config_result['files'][rel_file] = result_file
                if verdicts:
                    config_result['affected'] = any(verdicts)

        # Drop a hit under --check-strict only when the .config evaluation
        # explicitly ruled every affected file out; an undetermined verdict
        # (no .config, unmapped files) must not silence a finding.
        if self.check_strict and config_result.get('affected') is False:
            return False

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
                    try:
                        version = int(version.replace('.', ''))
                    except ValueError:
                        # An unparsable requirement must degrade to "run the
                        # rule" (prefer a false positive), not abort the scan.
                        logging.warning(
                            '%s: cannot parse Version: %r; ignoring the spatch requirement',
                            cve,
                            version,
                        )
                        version = 0

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
