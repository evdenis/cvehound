#!/usr/bin/env python3

from setuptools import setup

setup(
    name='cvehound',
    version='0.1.1',
    author='Denis Efremov',
    author_email='efremov@linux.com',
    url='http://github.com/evdenis/cvehound',
    description='A tool to check linux kernel source dump for known CVEs',
    long_description=open('README.md', encoding='utf8').read(),
    long_description_content_type='text/markdown',
    python_requires='>=3.6',
    classifiers=[
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9'
    ],
    packages=['cvehound'],
    license='GPLv3',
    keywords=['cve', 'linux', 'kernel', 'spatch', 'cve-scanning', 'coccinelle'],
    entry_points={
        'console_scripts': [
            'cvehound=cvehound.__init__:main'
        ]
    },
    include_package_data=True
)
