#!/usr/bin/env python3

import argparse
import concurrent.futures
import json
import logging
import multiprocessing
import os
import re
import sys
import zlib
from datetime import UTC, datetime
from typing import Any

from cvehound import SPATCH_TIMEOUT, SPATCH_WALL_TIMEOUT, CVEhound
from cvehound.content import resolve_content
from cvehound.exception import SpatchError, SpatchNotFound, SpatchTimeout, UnsupportedVersion
from cvehound.util import (
    find_spatch,
    fix_date_str,
    get_config_data,
    get_cvehound_version,
    get_cves_metadata,
    get_kernel_version,
    get_rule_cves,
    get_srcarch,
    latest_fix_date,
    parse_config,
    resolve_metadata_path,
)
from cvehound.worker import _worker_check_cve, _worker_init, setup_logging

# Metadata older than this gets a warning; --exploit is stricter because the
# CISA KEV catalog it filters on changes much faster than the fix data.
METADATA_STALE_DAYS = 90
METADATA_STALE_DAYS_EXPLOIT = 30


def format_version_info() -> str:
    """Tool version plus the identity of the content it would scan with."""
    lines = ['cvehound ' + get_cvehound_version()]
    content = resolve_content()
    (all_rules, _, _) = get_rule_cves()
    origin = content.source
    if content.content_id:
        origin += ' ' + content.content_id
    if content.source_commit:
        origin += ', commit ' + content.source_commit[:12]
    lines.append(f'rules: {len(all_rules)} ({origin})')
    try:
        path = resolve_metadata_path(None)
    except (FileNotFoundError, ValueError) as err:
        lines.append(f'metadata: error: {err}')
        return '\n'.join(lines)
    if path is None:
        lines.append("metadata: none (run 'cvehound update')")
    elif path == content.metadata_path and content.metadata_generated:
        # The verified manifest already carries the blob's generation date:
        # no need to gunzip and parse the whole blob just for --version.
        lines.append(f'metadata: updated {content.metadata_generated} ({path})')
    else:
        try:
            metadata = get_cves_metadata(path)
        except (OSError, EOFError, ValueError, zlib.error) as err:
            # A corrupt or truncated blob must not crash the very command
            # users run to diagnose their install.
            lines.append(f'metadata: error: {path}: {err}')
            return '\n'.join(lines)
        latest = latest_fix_date(metadata)
        if latest:
            lines.append(f'metadata: updated {fix_date_str(latest)} ({path})')
        else:
            lines.append(f'metadata: {path}')
    return '\n'.join(lines)


class _VersionAction(argparse.Action):
    def __init__(self, option_strings: list[str], dest: str, **kwargs: Any) -> None:
        super().__init__(option_strings, dest, nargs=0, **kwargs)

    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: Any,
        option_string: str | None = None,
    ) -> None:
        print(format_version_info())
        parser.exit()


def check_metadata_freshness(metadata: dict[str, Any], exploit: bool) -> None:
    if not metadata:
        if exploit:
            print(
                '--exploit needs CVE metadata, but none was found; '
                "run 'cvehound update' to fetch it",
                file=sys.stderr,
            )
            sys.exit(1)
        print(
            'Warning: no CVE metadata found, findings will lack commit details; '
            "run 'cvehound update' to fetch it",
            file=sys.stderr,
        )
        return
    latest = latest_fix_date(metadata)
    if not latest:
        return
    age_days = int((datetime.now(tz=UTC).timestamp() - latest) // 86400)
    limit = METADATA_STALE_DAYS_EXPLOIT if exploit else METADATA_STALE_DAYS
    if age_days > limit:
        hint = ' (--exploit may miss recently catalogued exploits)' if exploit else ''
        print(
            f'Warning: the CVE metadata is ~{age_days} days old{hint}; '
            "run 'cvehound update' to refresh it",
            file=sys.stderr,
        )


def ensure_rules(all_rules: dict[str, str]) -> None:
    """An empty rule set means a broken install (e.g. an interrupted run of the
    legacy in-place updater); scanning would silently report nothing."""
    if all_rules:
        return
    content = resolve_content()
    if content.source == 'overlay':
        remedy = "run 'cvehound update --force' to reinstall the content overlay"
    else:
        remedy = 'reinstall the package: pip install --force-reinstall cvehound'
    print('No detection rules found in', content.rules_dir + ';', remedy, file=sys.stderr)
    sys.exit(1)


def resolve_arch(args_cfg: dict[str, Any], config_info: dict[str, str]) -> str:
    """Determine the kernel architecture: --arch, else the .config banner,
    else a warned-about x86 guess."""
    arch = args_cfg.get('arch')
    config_arch = config_info.get('arch')

    if arch and config_arch and get_srcarch(arch) != get_srcarch(config_arch):
        print(
            '--arch',
            arch,
            'conflicts with',
            args_cfg['kernel_config'],
            'generated for',
            config_arch,
            file=sys.stderr,
        )
        sys.exit(1)

    arch = arch or config_arch
    if arch:
        if not os.path.isdir(os.path.join(args_cfg['kernel'], 'arch', get_srcarch(arch))):
            print('Unknown kernel architecture:', arch, file=sys.stderr)
            sys.exit(1)
        return arch

    if args_cfg['check_strict']:
        # A guessed architecture would silently drop every arch/<real>/ CVE
        # as "not affected"; refuse to guess when dropping is enabled.
        print(
            "--check-strict can't infer the kernel architecture from",
            args_cfg['kernel_config'],
            '(no config banner); pass --arch',
            file=sys.stderr,
        )
        sys.exit(1)
    if args_cfg['kernel_config']:
        print('Assuming x86 kernel architecture; pass --arch to override', file=sys.stderr)
    if not os.path.isdir(os.path.join(args_cfg['kernel'], 'arch', 'x86')):
        # Only a guess: without it the scan still works, it merely loses the
        # arch-specific include paths.
        print(
            'No arch/x86 directory in',
            args_cfg['kernel'] + '; continuing without arch-specific include paths',
            file=sys.stderr,
        )
    return 'x86'


def check_config(config: dict[str, Any]) -> None:
    valid_config_options = {
        'kernel',
        'cve',
        'exclude',
        'exploit',
        'verbose',
        'files',
        'ignore_files',
        'kernel_config',
        'check_strict',
        'report',
        'all_files',
        'metadata',
        'arch',
        'spatch',
    }
    diff = set(config.keys()) - valid_config_options
    if diff:
        print('Unknown config options: ' + ','.join(diff), file=sys.stderr)
        sys.exit(1)


def main(args: list[str] | None = None) -> None:
    if args is None:
        args = sys.argv[1:]
    if args and args[0] == 'update':
        from cvehound.scripts.update import main as update_main

        sys.exit(update_main(args[1:]))
    parser = argparse.ArgumentParser(
        prog='cvehound',
        description='A tool to check linux kernel sources dump for known CVEs',
        epilog="subcommands: 'cvehound update' refreshes the detection rules and "
        "CVE metadata (see 'cvehound update --help')",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        '--config',
        metavar='FILE',
        help='cvehound.ini config file (default: /etc/cvehound.ini or $HOME/.config/cvehound.ini',
    )
    parser.add_argument('--kernel', '-k', metavar='DIR', help='linux kernel sources dir')
    parser.add_argument('--list', action='store_true', help='list all known CVEs and exit')
    parser.add_argument(
        '--cve',
        '-c',
        nargs='+',
        default=['assigned'],
        help='list of cve identifiers (groups: [all, assigned, disputed])',
    )
    parser.add_argument(
        '--exclude',
        '-x',
        nargs='+',
        default=[],
        metavar='CVE',
        help='list of cve identifiers or a file with them to exclude CVEs from check',
    )
    parser.add_argument(
        '-v', '--verbose', action='count', default=0, help='increase output verbosity'
    )
    parser.add_argument(
        '--exploit', '-e', action='store_true', help='check only for CVEs with exploits'
    )
    parser.add_argument(
        '--files',
        nargs='+',
        default=[],
        metavar='PATH',
        help='check only files (e.g. kernel drivers/block/floppy.c arch/x86)',
    )
    parser.add_argument(
        '--ignore-files',
        nargs='+',
        default=[],
        metavar='PATH',
        help='exclude kernel files from check (e.g. kernel/bpf)',
    )
    parser.add_argument(
        '--kernel-config', nargs='?', const='-', metavar='.config', help='check kernel config'
    )
    parser.add_argument(
        '--arch',
        metavar='ARCH',
        help='kernel architecture (default: from the .config banner, else x86)',
    )
    parser.add_argument(
        '--check-strict', action='store_true', help='output only CVEs enabled in .config'
    )
    parser.add_argument(
        '--report', nargs='?', const='report.json', help='output report with found CVEs'
    )
    parser.add_argument(
        '--all-files', action='store_true', help="don't use files hint from cocci rules"
    )
    parser.add_argument(
        '--metadata', metavar='PATH', help='Path to non-standard location of kernel_cves.json.gz'
    )
    parser.add_argument(
        '--spatch',
        metavar='PATH',
        help='spatch binary to use (default: $CVEHOUND_SPATCH, the bundled'
        ' cvehound-spatch package, then PATH)',
    )
    parser.add_argument(
        '--version',
        action=_VersionAction,
        default=argparse.SUPPRESS,
        help='show the tool, rules, and metadata versions and exit',
    )
    cmdargs = parser.parse_args(args)

    if cmdargs.list:
        (all_rules, _, _) = get_rule_cves()
        ensure_rules(all_rules)
        print('\n'.join(sorted(all_rules)))
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
    merged_args: dict[str, Any] = config_args
    cmdargs_dict = vars(cmdargs)
    for arg in cmdargs_dict:
        if cmdargs_dict[arg] != parser.get_default(arg) or arg not in merged_args:
            merged_args[arg] = cmdargs_dict[arg]
    args_cfg = merged_args

    if not args_cfg['kernel']:
        parser.print_usage()
        print('cvehound: error: the following arguments are required: --kernel/-k', file=sys.stderr)
        sys.exit(1)

    try:
        # Also validates $CVEHOUND_METADATA, which --metadata's checks never saw.
        metadata_path = resolve_metadata_path(args_cfg['metadata'])
    except (FileNotFoundError, ValueError) as err:
        print(err, file=sys.stderr)
        sys.exit(1)

    if not all(os.path.isfile(os.path.join(args_cfg['kernel'], f)) for f in ['Makefile']):
        print(args_cfg['kernel'], "isn't a kernel directory", file=sys.stderr)
        sys.exit(1)

    if args_cfg['kernel_config'] == '-':
        config = os.path.normpath(os.path.join(args_cfg['kernel'], '.config'))
        if os.path.isfile(config):
            args_cfg['kernel_config'] = config
        elif args_cfg['check_strict']:
            print(
                '--check-strict needs a kernel .config, but', config, 'not found', file=sys.stderr
            )
            sys.exit(1)
        else:
            print(
                'No',
                config,
                'found: inferring CONFIG_ options without a .config check',
                file=sys.stderr,
            )
    else:
        if args_cfg['kernel_config'] and not os.path.isfile(args_cfg['kernel_config']):
            print("Can't find config file", args_cfg['kernel_config'], file=sys.stderr)
            sys.exit(1)

    if args_cfg['kernel_config'] and args_cfg['verbose'] == 0:
        args_cfg['verbose'] = 1

    if args_cfg['check_strict'] and not args_cfg['kernel_config']:
        print('Please, use --check-strict with --kernel-config', file=sys.stderr)
        sys.exit(1)

    try:
        spatch = find_spatch(args_cfg.get('spatch'))
    except SpatchNotFound as err:
        print(err, file=sys.stderr)
        sys.exit(1)

    loglevel = logging.WARNING
    if args_cfg['verbose'] > 1:
        loglevel = logging.DEBUG
    elif args_cfg['verbose'] > 0:
        loglevel = logging.INFO
    setup_logging(loglevel)

    config_info: dict[str, str] = {}
    if args_cfg['kernel_config'] and args_cfg['kernel_config'] != '-':
        config_info = get_config_data(args_cfg['kernel_config'])

    args_cfg['arch'] = resolve_arch(args_cfg, config_info)

    hound = CVEhound(
        args_cfg['kernel'],
        metadata_path,
        args_cfg['kernel_config'],
        args_cfg['check_strict'],
        args_cfg['arch'],
        spatch=spatch,
    )
    ensure_rules(hound.cve_all_rules)
    check_metadata_freshness(hound.metadata, args_cfg['exploit'])

    cve_id = re.compile(r'^CVE-\d{4}-\d{4,7}$')
    cve_set: set[str]
    if args_cfg['cve'] == ['all']:
        cve_set = hound.get_all_cves()
    elif args_cfg['cve'] == ['assigned']:
        cve_set = hound.get_assigned_cves()
    elif args_cfg['cve'] == ['disputed']:
        cve_set = hound.get_disputed_cves()
    else:
        cve_set = set(args_cfg['cve'])
        known_cves = hound.get_all_cves()
        for i, cve in enumerate(args_cfg['cve']):
            if not cve.startswith('CVE-'):
                cve = 'CVE-' + cve
                args_cfg['cve'][i] = cve
            if not cve_id.match(cve):
                print('Wrong CVE-ID:', cve, file=sys.stderr)
                sys.exit(1)
            if cve not in known_cves:
                print('Unknown CVE:', cve, file=sys.stderr)
                sys.exit(1)
        cve_set = set(args_cfg['cve'])

    for file in args_cfg['exclude'][:]:
        if os.path.exists(file):
            args_cfg['exclude'].remove(file)
            with open(file, encoding='utf-8') as fh:
                for line in fh:
                    line = line.strip()
                    if line == '' or line.startswith('#'):
                        continue
                    if not line.startswith('CVE-'):
                        line = 'CVE-' + line
                    if not cve_id.match(line):
                        print('Wrong CVE-ID:', line, 'in file', file, file=sys.stderr)
                        sys.exit(1)
                    args_cfg['exclude'].append(line)

    for i, cve in enumerate(args_cfg['exclude']):
        if not cve.startswith('CVE-'):
            cve = 'CVE-' + cve
            args_cfg['exclude'][i] = cve
        if not cve_id.match(cve):
            print('Wrong CVE-ID:', cve, file=sys.stderr)
            sys.exit(1)

    if args_cfg['all_files'] and args_cfg['files']:
        print('--files filter and --all-files are not compatible', file=sys.stderr)
        sys.exit(1)
    if args_cfg['all_files'] and args_cfg['ignore_files']:
        print('--ignore-files filter and --all-files are not compatible', file=sys.stderr)
        sys.exit(1)
    path_pattern = re.compile(r'^[_a-zA-Z-./0-9]+$')
    for f in [*args_cfg['files'], *args_cfg['ignore_files']]:
        if not path_pattern.match(f):
            print('Wrong file filter:', f, file=sys.stderr)
            sys.exit(1)

    cves: list[str] = []
    for cve in cve_set:
        if cve in args_cfg['exclude']:
            continue
        if args_cfg['exploit'] and not hound.get_cve_exploit(cve):
            continue
        if args_cfg['files']:
            add = False
            for rulefile in hound.get_rule_files(cve):
                if any(rulefile.startswith(x) for x in args_cfg['files']):
                    add = True
                    break
            if not add:
                continue
        if args_cfg['ignore_files']:
            should_check = False
            for rulefile in hound.get_rule_files(cve):
                # Header files don't affect the ignore decision
                if rulefile.endswith('.h'):
                    continue
                # If this file doesn't match any ignore pattern, we should check this CVE
                if not any(rulefile.startswith(x) for x in args_cfg['ignore_files']):
                    should_check = True
                    break
            if not should_check:
                continue
        cves.append(cve)

    args_cfg['files'].sort()
    args_cfg['ignore_files'].sort()
    cves_sorted = sorted(cves)

    # 'errors' is part of the schema whether or not anything failed: a consumer
    # that has to tell "no CVE fired" from "the rule never ran" needs the key to
    # be there unconditionally.
    report: dict[str, Any] = {
        'args': {},
        'kernel': {},
        'config': {},
        'tools': {},
        'results': {},
        'errors': {},
    }
    report['args']['cve'] = cves_sorted
    report['args']['kernel'] = args_cfg['kernel']
    report['args']['config'] = args_cfg['kernel_config']
    report['args']['only_files'] = args_cfg['files']
    report['args']['ignore_files'] = args_cfg['ignore_files']
    report['args']['all_files'] = args_cfg['all_files']
    report['args']['check_strict'] = args_cfg['check_strict']
    report['args']['arch'] = args_cfg['arch']
    report['args']['exclude'] = sorted(args_cfg['exclude'])
    report['args']['exploit'] = args_cfg['exploit']
    report['args']['metadata'] = metadata_path
    report['kernel'] = get_kernel_version(args_cfg['kernel'])
    if args_cfg['kernel_config'] and args_cfg['kernel_config'] != '-':
        report['config'] = config_info
    report['tools']['cvehound'] = get_cvehound_version()
    report['tools']['spatch'] = '.'.join(list(str(hound.spatch_version)))
    report['tools']['spatch_path'] = hound.spatch
    # The budgets that produced these findings: a rule that timed out here may
    # well have fired on a machine that gave it more room, so a report is not
    # comparable to another one without them.
    report['tools']['spatch_timeout'] = SPATCH_TIMEOUT
    report['tools']['spatch_wall_timeout'] = SPATCH_WALL_TIMEOUT
    # Rules and metadata update out-of-band, so the tool version alone does not
    # identify what produced the findings; pin the content identity too.
    content = resolve_content()
    rules_info: dict[str, Any] = {'source': content.source, 'count': len(hound.cve_all_rules)}
    if content.content_id:
        rules_info['content_id'] = content.content_id
    if content.source_commit:
        rules_info['commit'] = content.source_commit
    report['tools']['rules'] = rules_info
    latest_fix = latest_fix_date(hound.metadata)
    report['tools']['metadata'] = {
        'path': metadata_path,
        'entries': len(hound.metadata),
        'latest_fix_date': fix_date_str(latest_fix) if latest_fix else None,
    }

    # Under forkserver (the Linux default since Python 3.14) workers would
    # otherwise each re-import cvehound (and sympy) when the CLI runs as
    # `python -m cvehound`; preloading amortizes that once. No-op for fork/spawn.
    multiprocessing.set_forkserver_preload(['cvehound.worker'])
    with concurrent.futures.ProcessPoolExecutor(
        max_workers=os.cpu_count(), initializer=_worker_init, initargs=(hound, loglevel)
    ) as executor:
        future_to_cve = {
            executor.submit(_worker_check_cve, cve, args_cfg['all_files']): cve
            for cve in cves_sorted
        }

        for future in concurrent.futures.as_completed(future_to_cve):
            cve = future_to_cve[future]
            try:
                result = future.result()
                if result:
                    report['results'][cve] = result
            except SpatchTimeout as err:
                logging.error(str(err))
                report['errors'][cve] = {
                    'error': 'timeout',
                    'returncode': err.returncode,
                    'timeout': err.timeout,
                    'wall': err.wall,
                    'files': err.files,
                    'stderr': err.stderr_tail,
                }
            except SpatchError as err:
                logging.error(str(err))
                report['errors'][cve] = {
                    'error': 'spatch',
                    'returncode': err.returncode,
                    'stderr': err.stderr_tail,
                }
            except UnsupportedVersion as err:
                logging.error('Skipping: ' + err.cve + ' requires spatch >= ' + err.rule_version)
                report['errors'][cve] = {
                    'error': 'unsupported_version',
                    'requires': err.rule_version,
                }

    if args_cfg['report']:
        with open(args_cfg['report'], 'w', encoding='utf-8') as fh:
            json.dump(report, fh, indent=4, sort_keys=True)
        print('Report saved to:', args_cfg['report'])


if __name__ == '__main__':
    main(sys.argv[1:])
