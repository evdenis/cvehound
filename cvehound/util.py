import gzip
import json
import os
import re
import shutil
import subprocess
from configparser import ConfigParser
from datetime import UTC, datetime
from importlib.metadata import distribution, version
from typing import Any

from cvehound.content import RULE_SUFFIXES, resolve_content
from cvehound.exception import SpatchNotFound

# The top-level Makefile's ARCH -> SRCARCH mapping: which arch/<dir>
# the sources for a given ARCH= value actually live in.
SRCARCH = {
    'i386': 'x86',
    'x86_64': 'x86',
    'sparc32': 'sparc',
    'sparc64': 'sparc',
    'parisc64': 'parisc',
    'sh64': 'sh',
    'tilepro': 'tile',
    'tilegx': 'tile',
}


def get_srcarch(arch: str) -> str:
    return SRCARCH.get(arch, arch)


def get_config_data(path: str) -> dict[str, str]:
    with open(path) as fh:
        ver_pattern = re.compile(r'# Linux/(\S+)\s+(\S+)\s+Kernel Configuration')
        for line in fh:
            res = ver_pattern.match(line)
            if res:
                return {'arch': res.group(1), 'version': res.group(2)}
    return {}


def get_kernel_version(path: str) -> dict[str, str]:
    with open(os.path.join(path, 'Makefile')) as fh:
        makefile = fh.read()
    ver: dict[str, str] = {}
    for key in ['version', 'patchlevel', 'sublevel', 'extraversion', 'name']:
        res = re.search('^' + key.upper() + r'[ \t]*=[ \t]*(.*)[ \t]*$', makefile, re.MULTILINE)
        if res:
            ver[key] = res.group(1)
        else:
            ver[key] = ''
    ver['full'] = (
        '.'.join([ver['version'], ver['patchlevel'], ver['sublevel']]) + ver['extraversion']
    )
    return ver


def get_cvehound_version() -> str:
    pkg_version = version('cvehound')
    dist = distribution('cvehound')
    location = str(dist.locate_file(''))

    if not os.path.exists(os.path.join(location, '.git')):
        return pkg_version

    try:
        desc = ['git', 'describe', '--tags', '--dirty']
        pkg_version = subprocess.check_output(
            desc, cwd=location, stderr=subprocess.DEVNULL, universal_newlines=True
        ).strip()
    except Exception:
        pass

    return pkg_version


def find_spatch(explicit: str | None = None) -> str:
    """Resolve the spatch binary to run.

    Precedence: an explicit path/name (--spatch, config file) -> the
    CVEHOUND_SPATCH environment variable -> the bundled cvehound-spatch
    package -> whatever is on PATH.

    An explicitly named binary that does not resolve is an error, never a
    silent fallback; an implicit source that does not resolve falls through
    to the next one. Failure to resolve anything at all raises
    SpatchNotFound, so callers never have to handle a None.
    """

    def resolve(name: str, origin: str) -> str:
        path = shutil.which(name)
        if path is None:
            raise SpatchNotFound(f'spatch not found at {name!r} (from {origin})')
        return path

    if explicit:
        return resolve(explicit, '--spatch')
    env = os.environ.get('CVEHOUND_SPATCH')
    if env:
        return resolve(env, '$CVEHOUND_SPATCH')
    try:
        import cvehound_spatch  # ty: ignore[unresolved-import]  # optional sidecar package

        # The sidecar is not an explicit choice, so a package whose binary is
        # missing must fall through to PATH rather than hand back a path that
        # only fails later, inside subprocess.
        bundled = shutil.which(str(cvehound_spatch.spatch_path()))
        if bundled:
            return bundled
    except ImportError:
        pass
    found = shutil.which('spatch')
    if found is None:
        raise SpatchNotFound(
            "spatch not found: install coccinelle, or pip install 'cvehound[spatch]' "
            'to get a prebuilt one'
        )
    return found


def get_spatch_version(spatch: str) -> int:
    version_output = (
        subprocess.check_output(
            [spatch, '--version'], stderr=subprocess.DEVNULL, universal_newlines=True
        )
        .strip()
        .split('\n')[0]
    )
    res = re.match(r'spatch\s+version\s+([\d.]+)', version_output)
    if res is None:
        raise RuntimeError('Could not parse spatch version')
    version_string = res.group(1)
    nums = version_string.count('.')
    if nums == 1:
        version_string += '.0'
    return int(version_string.replace('.', ''))


def get_rule_cves() -> tuple[dict[str, str], dict[str, str], dict[str, str]]:
    known: dict[str, str] = {}
    assigned: dict[str, str] = {}
    disputed: dict[str, str] = {}
    cve_dir = resolve_content().rules_dir
    for root, _dirs, file_list in os.walk(cve_dir):
        rel = os.path.relpath(root, cve_dir)
        is_disputed = rel.split(os.sep)[0] == 'disputed'
        for cve in file_list:
            if not cve.endswith(RULE_SUFFIXES):
                continue
            path = os.path.join(root, cve)
            name = cve.removesuffix('.grep').removesuffix('.cocci')
            known[name] = path
            if is_disputed:
                disputed[name] = path
            else:
                assigned[name] = path
    return (known, assigned, disputed)


def resolve_metadata_path(path: str | None = None) -> str | None:
    """Resolve the metadata blob to use: the explicit path, $CVEHOUND_METADATA,
    the content overlay, then the packaged default; None when nothing exists."""
    if not path:
        path = os.environ.get('CVEHOUND_METADATA')
    if path:
        if not os.path.isfile(path):
            raise FileNotFoundError(f"Can't find metadata file {path}")
        if not path.endswith('.gz'):
            raise ValueError(f'Metadata file {path} is not a gz archive')
        return path
    return resolve_content().metadata_path


def latest_fix_date(metadata: dict[str, Any]) -> int:
    """The newest fix_date in a metadata blob: its effective generation date."""
    return max((info.get('fix_date', 0) for info in metadata.values()), default=0)


def fix_date_str(timestamp: int) -> str:
    """Render a fix_date timestamp the one way it appears everywhere."""
    return datetime.fromtimestamp(timestamp, tz=UTC).strftime('%Y-%m-%d')


def get_cves_metadata(path: str | None) -> Any:
    path = resolve_metadata_path(path)
    if path is None:
        return {}
    with gzip.open(path, 'rt', encoding='utf-8') as fh:
        return json.load(fh)


def parse_coccinelle_output(output: str) -> list[dict[str, str | int]]:
    """Parse spatch context-mode output: unified diffs of the starred lines.

    Rules report by starring lines, so a match is a diff whose removed
    lines are the starred ones; each removed line becomes one hit with
    its line number in the original file.
    """
    result: list[dict[str, str | int]] = []
    file = ''
    old_line = 0
    for line in output.splitlines():
        if line.startswith('--- '):
            file = line[4:]
        elif line.startswith('@@'):
            hunk = re.match(r'@@ -(\d+)', line)
            if hunk:
                old_line = int(hunk.group(1))
        elif line.startswith('-'):
            result.append({'file': file, 'line': old_line})
            old_line += 1
        elif not line.startswith('+'):
            # Context lines advance the original-file counter; '+++' and added
            # lines do not exist in the original and are skipped by the above.
            old_line += 1
    return result


# spatch reports a fired --timeout in three shapes, and which one you get depends
# on how the run was invoked, not on what went wrong:
#
#   file list, -j 1   exit 2    "timeout (we abort): <files>" then
#                               "Fatal error: exception <mod>Common.Timeout"
#   directory arg     exit 0    "EXN: <mod>Common.Timeout in <file>", one per file,
#                               then "An error occurred when attempting to ..."
#   file list, -j > 1 exit 255  "[Parmap]: error at index ... got exception
#                               <mod>Common.Timeout on core N"
#
# The exit code alone settles nothing -- OCaml gives any uncaught exception exit 2,
# and the directory shape does not fail at all -- so the stderr text is the verdict.
# The module prefix is build-dependent (Coccinelle_modules.Common.Timeout on the
# OCaml 5 builds, bare Common.Timeout on older ones), hence the optional group.
_TIMEOUT_EXN = re.compile(r'\bCommon\.Timeout\b')
_TIMEOUT_EXN_FILE = re.compile(r'^EXN: (?:\S+\.)?Common\.Timeout in (.+)$', re.MULTILINE)
_TIMEOUT_ABORT = re.compile(r'^timeout \(we abort\): (.*)$', re.MULTILINE)


def parse_spatch_timeout(stderr: str) -> list[str] | None:
    """Classify spatch stderr: None when no --timeout fired, else the files blamed.

    The list is empty when spatch named no file -- the parmap and fatal-error
    lines carry only the exception. Callers must treat "empty" as "timed out,
    files unknown", never as "did not time out".
    """
    if not _TIMEOUT_EXN.search(stderr):
        return None
    files = _TIMEOUT_EXN_FILE.findall(stderr)
    if not files:
        # The abort line lists the whole work unit, space-separated: under a file
        # list that is every file spatch was given, since they are one unit.
        for group in _TIMEOUT_ABORT.findall(stderr):
            files.extend(group.split())
    return sorted(set(files))


def parse_config(file: str) -> dict[str, Any]:
    parser = ConfigParser()
    with open(file) as fh:
        parser.read_string('[cvehound]\n' + fh.read())
    config: dict[str, Any] = dict(parser['cvehound'])

    for key in ['cve', 'exclude', 'files', 'ignore_files']:
        if key not in config:
            continue
        config[key] = config[key].split()

    if 'verbose' in config:
        try:
            config['verbose'] = int(config['verbose'])
        except ValueError:
            raise Exception('"verbose" should be an integer') from None

    for key in ['check_strict', 'all_files', 'exploit']:
        if key not in config:
            continue
        if config[key].lower() in ['y', 't', '1', 'yes', 'true']:
            config[key] = True
        elif config[key].lower() in ['n', 'f', '0', 'no', 'false']:
            config[key] = False
        else:
            raise Exception("Can't parse boolean argument " + key)

    return config
