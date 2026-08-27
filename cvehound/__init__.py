#!/usr/bin/env python3

import contextlib
import functools
import logging
import os
import shutil
import signal
import subprocess
import tempfile
from typing import Any

from sympy.logic import simplify_logic

from cvehound.config import Config
from cvehound.exception import SpatchError, SpatchNotFound, SpatchTimeout, UnsupportedVersion
from cvehound.kbuild import KbuildParser
from cvehound.util import (
    find_spatch,
    fix_date_str,
    get_cves_metadata,
    get_rule_cves,
    get_spatch_version,
    get_srcarch,
    parse_coccinelle_output,
    parse_spatch_timeout,
)

__VERSION__ = '1.5.0'

RuleMetadata = dict[str, Any]

# Sources that become object files, i.e. the ones the Kbuild map can describe.
COMPILED_SUFFIXES = ('.c', '.S', '.s', '.rs')

# Force-included into every spatch run when the tree has it; the test harness
# mirrors this probe when it materializes mini-trees (tests/kerneltree.py).
KCONFIG_H = 'include/linux/kconfig.h'

# CPU-seconds inside the matching engine, per work unit -- and each of those
# three words matters. CPU, because coccinelle arms ITIMER_VIRTUAL, so an
# oversubscribed machine does not trip it. Matching engine, because the timer
# wraps Cocci.full_engine only: the ~3s of iso loading and rule parsing, and any
# wait on I/O, are outside it. Work unit, because given a file list spatch
# treats the whole list as one, and only a directory (--all-files) splits per
# file.
#
# 60 against a worst measured file of 0.5 CPU-seconds is margin for the two
# things that move billed CPU -- machine load and core speed -- not for
# expensive rules. docs/WRITING_RULES.md -> "The rule exceeds its time budget"
# carries the numbers.
SPATCH_TIMEOUT = 60

# The outer bound, and the only one that sees what a CPU budget structurally
# cannot: a stalled read, a deadlocked parmap child, a rule parse that never
# returns. It is also the coarser statement of the same standard -- no single
# spatch run has any business taking five minutes, whole-tree scan included, and
# one that does is a rule to rewrite rather than a budget to raise. The slowest
# --all-files scan of the whole rule set measures 43s wall / 37s CPU, so this
# leaves ~7x for slower hardware. 0 disables it, as it does for spatch.
SPATCH_WALL_TIMEOUT = 300

# spatch is OCaml, and its cost on a rule's own files is dominated by allocating
# and collecting the parsed AST. space_overhead is how much garbage the major
# collector tolerates before it works, so raising it buys wall-clock with memory
# -- and the memory it spends is small at this shape: peak RSS per spatch stays
# ~40-46MB whatever the setting, because a rule sees a handful of files. Measured
# against the bundled cvehound-spatch build (1.3.2 on OCaml 5.3) on the fast
# suite (idle 32-thread box, --no-result-cache, paired runs): 56.0s
# default, 49.4s at o=800, 47.9s at o=1600, 47.2s at o=3200 -- so 1600 sits where
# the curve flattens. Do not raise the minor heap (s=) with it: every variant
# tried was slower, and a large one triples system time under 32-way concurrency.
#
# Whole-tree scans (--all-files) barely move: handed a directory spatch spends
# its time on the token prefilter, scanning every file in the tree for the
# rule's literals, and parses almost nothing. There is no AST there to collect.
SPATCH_OCAMLRUNPARAM = 'o=1600'


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


def _spatch_env() -> dict[str, str]:
    """The environment for a spatch child: ours, plus our GC defaults.

    A caller who has already said something about the OCaml runtime keeps it
    untouched -- the tuning is a default, not a policy. CAMLRUNPARAM counts as
    saying something: the runtime reads OCAMLRUNPARAM first and only falls back
    to it, so setting ours unconditionally would silently void theirs.
    """
    env = dict(os.environ)
    if 'OCAMLRUNPARAM' not in env and 'CAMLRUNPARAM' not in env:
        env['OCAMLRUNPARAM'] = SPATCH_OCAMLRUNPARAM
    return env


def _run_spatch(cve: str, kernel: str, cmd: list[str], wall_timeout: int) -> str:
    """Run spatch under both budgets and hand back its stdout, or raise.

    Both halves of "did this run finish" live here so they cannot be used apart:
    a caller that got the wall watchdog but skipped the engine verdict would
    read a rule that gave up as a rule that found nothing.

    The wall half needs its own process group. subprocess.run(timeout=) kills
    only spatch, leaving the parmap workers it forks under -j>1 orphaned and
    still burning cores; start_new_session lets one signal reach all of them.
    That also costs spatch its SIGINT, so the same kill runs for any exception.
    """
    with subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
        env=_spatch_env(),
    ) as proc:
        try:
            # 0 disables the watchdog, matching what spatch reads --timeout 0 as.
            stdout, stderr = proc.communicate(timeout=wall_timeout or None)
        except subprocess.TimeoutExpired as err:
            _killpg(proc)
            # Whatever spatch said before the kill is the only clue to where it
            # wedged, and communicate() leaves it out of the exception.
            raise SpatchTimeout(
                cve, kernel, -signal.SIGKILL, proc.communicate()[1], wall_timeout, wall=True
            ) from err
        except BaseException:
            _killpg(proc)
            proc.communicate()
            raise

    # The engine half is a question about stderr, not the exit code: handed a
    # directory spatch drops the file it gave up on and still exits 0, so the
    # exit code alone would report a runaway rule as "not vulnerable".
    timed_out = parse_spatch_timeout(stderr)
    if timed_out is not None:
        raise SpatchTimeout(
            cve,
            kernel,
            proc.returncode,
            stderr,
            SPATCH_TIMEOUT,
            [os.path.relpath(f, kernel) for f in timed_out],
        )
    if proc.returncode != 0:
        raise SpatchError(cve, kernel, proc.returncode, stderr)
    return stdout


def _killpg(proc: subprocess.Popen[str]) -> None:
    with contextlib.suppress(ProcessLookupError):
        os.killpg(proc.pid, signal.SIGKILL)


class CVEhound:
    def __init__(
        self,
        kernel: str,
        metadata: str | None = None,
        config: str | None = None,
        check_strict: bool = False,
        arch: str = 'x86',
        spatch: str | None = None,
    ) -> None:
        kernel = os.path.abspath(kernel)
        self.kernel = kernel
        self.metadata: dict[str, Any] = get_cves_metadata(metadata)
        self.spatch: str = spatch or find_spatch()
        self.spatch_version = get_spatch_version(self.spatch)
        # spatch renders its context-mode output by shelling out to diff(1),
        # and without it prints an internal error and still exits 0 -- so an
        # unnoticed missing diffutils turns every rule into a silent miss.
        if shutil.which('diff') is None:
            raise SpatchNotFound('diff not found: spatch needs diffutils to report what it matched')
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
        hits: list[dict[str, str | int]] = []
        if not is_grep:
            rule_ver = self.get_rule_version(cve)
            if rule_ver and rule_ver > self.spatch_version:
                raise UnsupportedVersion(self.spatch_version, cve, rule_ver)
            # spatch stages each parmap worker's output in a directory built from
            # --tmp-dir and removes it as it exits (enter.ml, par_fold) -- which
            # the watchdog's SIGKILL denies it. A private directory keeps the
            # strand ours to remove, and keeps the staging out of a world-writable
            # /tmp, where a predictable name is at least a denial of service
            # (spatch refuses to start when the path exists) and, under a
            # permissive umask, lets a planted stdout* file be replayed as hits.
            with tempfile.TemporaryDirectory(
                prefix='cvehound-spatch-', ignore_cleanup_errors=True
            ) as tmpdir:
                cocci_cmd = [
                    self.spatch,
                    '--no-includes',
                    '--include-headers',
                    '-D',
                    'detect',
                    '--chunksize',
                    '1',
                    '-j',
                    str(jobs),
                    '--timeout',
                    str(SPATCH_TIMEOUT),
                    '--tmp-dir',
                    os.path.join(tmpdir, 'par'),
                    '--very-quiet',
                    *includes,
                    '--cocci-file',
                    rule,
                    *files,
                ]

                logging.debug(' '.join(cocci_cmd))

                output = _run_spatch(cve, self.kernel, cocci_cmd, SPATCH_WALL_TIMEOUT).strip()
            # Rules report by starring lines: a match is a unified diff of the
            # starred lines on stdout, silence means not vulnerable. The parsed
            # hits are the verdict, so "detected" and the reported locations can
            # never disagree.
            hits = parse_coccinelle_output(output)
            if not hits:
                return False
        else:
            for pattern in self.get_grep_pattern(rule):
                args = ['grep', '-rPzle', pattern, *files]
                run = subprocess.run(args, capture_output=True, check=False, text=True)
                if run.returncode != 0:
                    # A grep rule needs every pattern to match somewhere.
                    return False
                output += run.stdout.strip()

        config_result: dict[str, Any] = {}
        if self.config_map is not None:
            kernel_files: dict[str, str | None] = {}
            file_list: list[str] = []
            if not is_grep:
                file_list = sorted({str(hit['file']) for hit in hits})
            else:
                for line in output.split('\n'):
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
            result['files'] = hits
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
