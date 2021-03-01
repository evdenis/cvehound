[![GitHub Actions status](https://github.com/evdenis/cvehound/workflows/test/badge.svg)](https://github.com/evdenis/cvehound/actions?query=workflow%3Atest)
[![Supported Versions of Python](https://img.shields.io/pypi/pyversions/cvehound.svg)](https://pypi.org/project/cvehound)
[![PyPI package version](https://img.shields.io/pypi/v/cvehound.svg)](https://pypi.org/project/cvehound)

# CVEhound

CVEhound is a tool for checking linux sources for known CVEs.
The tool is based on [coccinelle](https://coccinelle.gitlabpages.inria.fr/website/)
rules and grep patterns. The tool checks sources for vulnerable
code patterns of known CVEs and missing fixes for them.

- **What:** The tool tries to find "unfixed" code of known CVEs;
- **How:** The tool uses [coccinelle/grep](cvehound/cve) rules with patterns that helps to detect known CVE bugs or their fixes. Thus, sources are checked either for a presence of "unfixed" code pieces (e.g. [CVE-2020-12912](cvehound/cve/CVE-2020-12912.cocci)), or for an absence of a fix (e.g. [CVE-2020-27068](cvehound/cve/CVE-2020-27068.grep));
- **Why:** If you have a git log then it's easier to check what CVEs are fixed based on a git history. However, many vendors (samsung, huawei, various iot, routers manufacturers) publish kernel sources as archives without git history. In most cases their kernels are based on LTS kernels, but versions are far from upstream. Linux version string from Makefile will only give you an information about what CVEs were fixed by kernel developers upto this version. It will not help you to understand what fixes were backported by a vendor itself. In this case it's possible to apply the tool and check "missing" CVE fixes.

## Prerequisites

- Python 3 (>=3.5)
- pip (Python package manager)
- grep with pcre support (-P flag)
- coccinelle (>= 1.0.4)

Install prerequisites:
``` shell
# Ubuntu, coccinelle uses libpython2.7 internally
# Seems like some ppas mark libpython dependency as optional
$ sudo apt install python3-pip coccinelle libpython2.7

# Fedora
$ sudo dnf install python3-pip coccinelle
```

## Installation

To install the latest stable version just run the following command:

``` shell
$ python3 -m pip install --user cvehound
```

For development purposes you may install cvehound in "editable" mode
directly from the repository (clone it on your computer beforehand):

``` shell
$ pip install -e .
```

## How to use

The simplest way to start using CVEhound is to run the following command:

``` shell
$ cvehound --kernel ~/workspace/linux
Found: CVE-2020-27830
Found: CVE-2020-27152
Found: CVE-2020-29371
Found: CVE-2020-26088
```

where *dir* should point to linux kernel sources. CVEhound will check the
sources for all cve patterns that you can find in [cve dir](/cvehound/cve/).
To check the sources for particular CVEs one can use:

``` shell
$ cvehound --kernel ~/workspace/linux --verbose --cve CVE-2020-27194 CVE-2020-29371
Checking: CVE-2020-27194
Found: CVE-2020-27194
MSG: bpf: Fix scalar32_min_max_or bounds tracking
CWE: Improper Restriction of Operations within the Bounds of a Memory Buffer
DATE: 2020-11-03

Checking: CVE-2020-29371
Found: CVE-2020-29371
MSG: romfs: fix uninitialized memory leak in romfs_dev_read()
CWE: Use of Uninitialized Resource
DATE: 2020-12-08
```

