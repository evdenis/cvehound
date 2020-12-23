# CVEhound

CVEhound is a tool for checking linux sources for known CVEs.
The tool is based on [coccinelle](https://coccinelle.gitlabpages.inria.fr/website/)
rules and grep patterns. The tool checks sources for vulnerable
code patterns of known CVEs and missing fixes for them.

## Prerequisites

- Python 3 (>=3.6)
- pip (Python package manager)
- grep with pcre support (-P flag)
- coccinelle (>= 1.0.8)

On Fedora:
``` shell
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
$ cvehound --dir ~/workspace/linux --verbose
```

where *dir* should point to linux kernel sources. CVEhound will check the
sources for all cve patterns that you can find in [cve dir](/cvehound/cve/).
To check the sources for particular CVEs one can use:

``` shell
$ cvehound --dir ~/workspace/linux --cve CVE-2020-27194 CVE-2020-29371
```

