import os
import re
import subprocess
from configparser import ConfigParser
from importlib.metadata import distribution, version
from importlib.resources import files
from typing import Any


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


def get_spatch_version() -> int:
    version_output = (
        subprocess.check_output(
            ['spatch', '--version'], stderr=subprocess.DEVNULL, universal_newlines=True
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
    cve_dir = str(files('cvehound').joinpath('cve'))
    for root, _dirs, file_list in os.walk(cve_dir):
        for cve in file_list:
            path = os.path.join(root, cve)
            name = cve.removesuffix('.grep').removesuffix('.cocci')
            known[name] = path
            if 'disputed' in root:
                disputed[name] = path
            else:
                assigned[name] = path
    return (known, assigned, disputed)


def parse_coccinelle_output(output: str) -> list[dict[str, str | int]]:
    result: list[dict[str, str | int]] = []
    for line in output.splitlines():
        file, hline, _ = line.split(':', 2)
        result.append(
            {
                'file': file,
                'line': int(hline),
            }
        )
    return result


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

    for key in ['check_strict', 'all_files']:
        if key not in config:
            continue
        if config[key].lower() in ['y', 't', '1', 'yes', 'true']:
            config[key] = True
        elif config[key].lower() in ['n', 'f', '0', 'no', 'false']:
            config[key] = False
        else:
            raise Exception("Can't parse boolean argument " + key)

    return config
