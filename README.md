[![GitHub Actions status](https://github.com/evdenis/cvehound/workflows/test/badge.svg)](https://github.com/evdenis/cvehound/actions?query=workflow%3Atest)
[![Supported Versions of Python](https://img.shields.io/pypi/pyversions/cvehound.svg)](https://pypi.org/project/cvehound)
[![PyPI package version](https://img.shields.io/pypi/v/cvehound.svg)](https://pypi.org/project/cvehound)

# CVEhound

CVEhound is a tool for checking linux sources for known CVEs.
The tool is based on [coccinelle](https://coccinelle.gitlabpages.inria.fr/website/)
rules and grep patterns. The tool checks sources for vulnerable
code patterns of known CVEs and missing fixes for them.

- **What:** The tool tries to find "unfixed" code of known CVEs;
- **How:** The tool uses [coccinelle/grep](cvehound/cve) rules with patterns that helps to detect known CVE bugs or their fixes. Thus, sources are checked either for a presence of "unfixed" code pieces (e.g. [CVE-2020-12912](cvehound/cve/CVE-2020-12912.cocci)), or for an absence of a fix (e.g. [CVE-2020-26088](cvehound/cve/CVE-2020-26088.cocci));
- **Why:** If you have a git log then it's easier to check what CVEs are fixed based on a git history. However, many vendors (samsung, huawei, various iot, routers manufacturers) publish kernel sources as archives without a development log. In most cases their kernels are based on LTS kernels, but versions are far from upstream. Linux version string from Makefile will only give you an information about what CVEs were fixed by kernel developers upto this version. It will not help you to understand what fixes were backported by a vendor itself. In this case it's possible to apply the tool and check "missing" CVE fixes.

### CVEHound: Audit Kernel Sources for Missing CVE Fixes

[Linux Security Summit 2021 Presentation (EN)](docs/LSS2021_CVEhound_en.pdf)

<p align="center">
  <a href="https://www.youtube.com/watch?v=jIDnVeZNUA8">
    <img src="https://img.youtube.com/vi/jIDnVeZNUA8/0.jpg" alt="Linux Security Summit 2021 Presentation"/>
  </a>
</p>

[ZeroNights 2021 Presentation (RU)](docs/ZN2021_CVEhound_ru.pdf)

<p align="center">
  <a href="https://www.youtube.com/watch?v=GG-YHLn5E1Q">
    <img src="https://img.youtube.com/vi/GG-YHLn5E1Q/0.jpg" alt="ZeroNights 2021 Presentation"/>
  </a>
</p>

### Found issues in stable trees

 - CVE-2020-27825 fix [missing backports](https://lkml.org/lkml/2021/1/21/1278) for [5.4, 4.19, 4.14, 4.9, 4.4 kernels](https://www.spinics.net/lists/stable/msg440412.html)
 - CVE-2021-4149 fix [missing backports](https://lore.kernel.org/stable/d1a3f31f-2205-6dce-0f33-6611972e48cd@gmx.com/T/#t) to [4.19, 4.14, 4.9 kernels](https://lore.kernel.org/stable/20220309064748.160978-1-denis.e.efremov@oracle.com/)
 - CVE-2022-26490 fix [missing backports](https://lore.kernel.org/all/20220321174006.47972-1-denis.e.efremov@oracle.com/)
 - See [tests exceptions](https://github.com/evdenis/cvehound/blob/master/tests/test_01_on_branch.py#L7) for more examples

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
$ cvehound --kernel ~/linux
Found: CVE-2020-27830
Found: CVE-2020-27152
Found: CVE-2020-29371
Found: CVE-2020-26088
```

where *dir* should point to linux kernel sources. CVEhound will check the
sources for all cve patterns that you can find in [cve dir](/cvehound/cve/).
To check the sources for particular CVEs one can use:

``` shell
$ cvehound --kernel ./linux --config --cve CVE-2020-27194 CVE-2020-29371
Checking: CVE-2020-27194
Found: CVE-2020-27194
MSG: bpf: Fix scalar32_min_max_or bounds tracking
CWE: Improper Restriction of Operations within the Bounds of a Memory Buffer
FIX DATE: 2020-10-08 09:02:53
https://www.linuxkernelcves.com/cves/CVE-2020-27194
Affected Files:
 - linux/kernel/bpf/verifier.c: CONFIG_BPF & CONFIG_BPF_SYSCALL
   linux/.config: affected
Config: ./linux/.config affected

Checking: CVE-2020-29371
Found: CVE-2020-29371
MSG: romfs: fix uninitialized memory leak in romfs_dev_read()
CWE: Use of Uninitialized Resource
FIX DATE: 2020-08-21 16:52:53
https://www.linuxkernelcves.com/cves/CVE-2020-29371
Affected Files:
 - linux/fs/romfs/storage.c: CONFIG_ROMFS_FS
   linux/.config: not affected
Config: ./linux/.config not affected
```

Other args:
 - `--report` - will produce json file with found CVEs
   Most of metainformation in generated report is taken from linuxkernelcves.com
 - `--config` or `--config <file>` - will infer the kernel configuration required to
   build the affected code (based on Kbuild/Makefiles, ifdefs are not checked) and
   check kernel .config file if there is one
 - `--files`, `--cwe` - will limit the scope of checked cves to the kernel files of
   interest or specific CWE classes
 - `--exploit` - check only for CVEs that are known to be exploitable (according to
   the FSTEC BDU database)

## LICENSE

Python code is licensed under GPLv3. All rules in cvehound/cve folder are licensed under GPLv2.

## Acknowledgements

I would like to thank the following projects and people behind them:
 - [coccinelle](https://coccinelle.gitlabpages.inria.fr/website/) for the program matching engine
 - [linuxkernelcves.com](https://linuxkernelcves.com/) for information about Linux CVEs
 - [undertaker](https://vamos.informatik.uni-erlangen.de/trac/undertaker) for mapping kernel configs to .c files
 - [sympy](https://www.sympy.org/) for the symbolic logic solver
