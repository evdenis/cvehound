import os
import re
import subprocess
import pkg_resources
from shutil import which

def dir_path(path):
    if os.path.isdir(path):
        return path
    raise NotADirectoryError(path)

def tool_exists(name):
    return which(name) is not None

def removesuffix(string, suffix):
    if suffix and string.endswith(suffix):
        return string[:-len(suffix)]
    return string[:]

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

