import os
import re
import subprocess
import pkg_resources
import json
import gzip
from shutil import which
from configparser import ConfigParser

def tool_exists(name):
    return which(name) is not None

def removesuffix(string, suffix):
    if suffix and string.endswith(suffix):
        return string[:-len(suffix)]
    return string[:]

def get_config_data(path):
    with open(path, 'rt') as fh:
        ver_pattern = re.compile(r'# Linux/(\S+)\s+(\S+)\s+Kernel Configuration')
        for line in fh:
            res = ver_pattern.match(line)
            if res:
                return {'arch': res.group(1), 'version': res.group(2)}
    return {}

def get_kernel_version(path):
    with open(os.path.join(path, 'Makefile'), 'rt') as fh:
        makefile = fh.read()
    version = {}
    for key in ['version', 'patchlevel', 'sublevel', 'extraversion', 'name']:
        res = re.search('^' + key.upper() + r'[ \t]*=[ \t]*(.*)[ \t]*$', makefile, re.MULTILINE)
        if res:
            version[key] = res.group(1)
        else:
            version[key] = ''
    version['full'] = '.'.join([version['version'], version['patchlevel'], version['sublevel']]) + version['extraversion']
    return version

def get_cvehound_version():
    version = pkg_resources.get_distribution('cvehound').version
    location = pkg_resources.get_distribution('cvehound').location

    if not os.path.exists(os.path.join(location, '.git')):
        return version

    try:
        desc = ['git', 'describe', '--tags', '--dirty']
        version = subprocess.check_output(
            desc, cwd=location, stderr=subprocess.DEVNULL, universal_newlines=True
        ).strip()
    finally:
        return version

def get_spatch_version():
    version = subprocess.check_output(
            ['spatch', '--version'],
            stderr=subprocess.DEVNULL, universal_newlines=True
    ).strip().split('\n')[0]
    res = re.match(r'spatch\s+version\s+([\d.]+)', version)
    version_string = res.group(1)
    nums = version_string.count('.')
    if nums == 1:
        version_string += '.0'
    return int(version_string.replace('.', ''))

def get_rule_cves():
    known = {}
    assigned = {}
    disputed = {}
    for root, dirs, files in os.walk(pkg_resources.resource_filename('cvehound', 'cve/')):
        for cve in files:
            path = os.path.join(root, cve)
            name = removesuffix(removesuffix(cve, '.grep'), '.cocci')
            known[name] = path
            if 'disputed' in root:
                disputed[name] = path
            else:
                assigned[name] = path
    return (known, assigned, disputed)

def get_cves_metadata(path):
    if not path:
        path = os.environ.get('CVEHOUND_METADATA',
               pkg_resources.resource_filename('cvehound', 'data/kernel_cves.json.gz'))
    data = None
    with gzip.open(path, 'rt', encoding='utf-8') as fh:
        data = json.load(fh)
    return data

def parse_coccinelle_output(output):
    files = []
    for line in output.splitlines():
        file, hline, _ = line.split(':', 2)
        files.append({
            'file': file,
            'line': int(hline),
        })
    return files

def parse_config(file):
    parser = ConfigParser()
    with open(file, 'rt') as fh:
        parser.read_string("[cvehound]\n" + fh.read())
    config = dict(parser['cvehound'])

    for key in ['cve', 'exclude', 'cwe', 'files', 'ignore_files']:
        if key not in config:
            continue
        config[key] = config[key].split()

    if 'verbose' in config:
        try:
            config['verbose'] = int(config['verbose'])
        except ValueError:
            raise Exception('"verbose" should be an integer')

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
