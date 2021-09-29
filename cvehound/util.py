import os
import re
import subprocess
import pkg_resources
import json
import gzip
from shutil import which

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
    version = {}
    with open(os.path.join(path, 'Makefile'), 'rt') as fh:
        def getparam():
            line = fh.readline()
            if line.startswith('#'):
                line = fh.readline()
            return line.split('=')[1].strip()
        version['version'] = getparam()
        version['patchlevel'] = getparam()
        version['sublevel'] = getparam()
        version['extraversion'] = getparam()
        version['name'] = getparam()
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
    return int(res.group(1).replace('.', ''))

def get_rule_cves():
    cves = {}
    for cve in pkg_resources.resource_listdir('cvehound', 'cve/'):
        if cve.endswith('.grep') or cve.endswith('.cocci'):
            name = removesuffix(removesuffix(cve, '.grep'), '.cocci')
            cves[name] = pkg_resources.resource_filename('cvehound', 'cve/' + cve)
    return cves

def get_cves_metadata():
    cves = pkg_resources.resource_filename('cvehound', 'data/kernel_cves.json.gz')
    data = None
    with gzip.open(cves, 'rt', encoding='utf-8') as fh:
        data = json.load(fh)
    return data
