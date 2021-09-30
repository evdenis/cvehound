#!/usr/bin/env python3

import os
import re
from setuptools import setup

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

def find_version(source):
    version_file = read(source)
    version_match = re.search(r"^__VERSION__ = ['\"]([^'\"]*)['\"]", version_file, re.M)
    if version_match:
        return version_match.group(1)
    raise RuntimeError("Unable to find version string.")

test_deps = [
    'pytest',
    'gitpython',
    'psutil'
]
extras = {
    'tests': test_deps,
}

setup(
    name='cvehound',
    version=find_version('cvehound/__init__.py'),
    author='Denis Efremov',
    author_email='efremov@linux.com',
    url='http://github.com/evdenis/cvehound',
    description='A tool to check linux kernel source dump for known CVEs',
    long_description=read('README.md'),
    long_description_content_type='text/markdown',
    python_requires='>=3.6',
    install_requires=['sympy'],
    tests_require=test_deps,
    extras_require=extras,
    classifiers=[
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9'
    ],
    packages=[
        'cvehound',
        'cvehound.kbuildparse'
    ],
    license='GPLv3',
    keywords=['cve', 'linux', 'kernel', 'spatch', 'cve-scanning', 'coccinelle'],
    entry_points={
        'console_scripts': [
            'cvehound=cvehound.__main__:main',
            'cvehound_update_metadata=cvehound.scripts.update_metadata:main',
            'cvehound_update_rules=cvehound.scripts.update_rules:main'
        ]
    },
    include_package_data=True
)
