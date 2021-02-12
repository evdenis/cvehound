#!/usr/bin/python
#
#  Copyright (c) 2000,2001,2007-2019  Giacomo A. Catenazzi <cate@cateee.net>
#  This is free software, see GNU General Public License v2 (or later) for details

import fnmatch
import logging
import os
import os.path
import re


logger = logging.getLogger(__name__)


# We can get configurations on building tools (what condition make
# a file to be compiled), and from configuration system (what
# precondition is needed to be able to see and select an option)
#
# But we have two varieties each: old and new:
# building: new kbuild and old "kmake"
# configuration: new Kconfig and old config.in


# parse kbuild files (Makefiles) and extract the file dependencies

# comment are removed; line ending with `\` are merged
kbuild_normalize = re.compile(
    r"(#.*$|\\\n)", re.MULTILINE)
kbuild_includes = re.compile(
    r"^-?include\s+\$[({]srctree[)}]/(.*)$", re.MULTILINE|re.ASCII)
kbuild_rules = re.compile(
    r"^([-A-Za-z0-9_]+)-([^-+=: \t\n]+)\s*[:+]?=[ \t]*(.*)$", re.MULTILINE|re.ASCII)

ignore_rules_set = frozenset(
    ("clean", "ccflags", "cflags", "aflags", "asflags", "mflags", "cpuflags", "subdir-ccflags", "extra"))


class Makefiles():
    def __init__(self, kerneldir, dirs):
        self.kerneldir = kerneldir
        self.dirs = dirs
        # dictionary of CONFIG_ dependencies for each file
        # dependencies: filename.c: {CONFIG_FOO, CONFIG_BAR, ...}
        self.dependencies = {}
        # dir_dep: dir: {CONFIG_FOO, ...}
        self.dir_dep = {}
        # dep_aliases: filename.c: (virtual-filename-objs.c, ...)
        self.dep_aliases = {}
        # modules: the inverse; format CONFIG_FOO: name  (used for module, so single name)
        self.modules = {}
        # pre parsed data
        # rules: filename: [[rule, dep, files] ...]  # rule-$(dep): files
        self.rules = {}
        # direct includes: filename -> [included file]
        self.includes = {}
        # variables: filename: [[variable_name, expansion],...]

    def scan(self):
        orig_cwd = os.getcwd()
        try:
            os.chdir(self.kerneldir)
            logger.info("=== Makefiles")
            for subdir in self.dirs:
                for root, dirs, files in os.walk(subdir):
                    dirs.sort()
                    if root.startswith('arch/') and subdir.count("/") == 1:
                        self.kbuild_parse_dir(root, 1)
                    else:
                        self.kbuild_parse_dir(root, 0)
        finally:
            os.chdir(orig_cwd)

    def kbuild_parse_dir(self, subdir, mode):
        # mode = 0: normal case -> path relatives; merge Kbuild and Makefile
        # mode = 1: arch/xxx/Makefile -> path from root
        # mode = 2: arch/xxx/Kbuild -> path relative, don't parse Makefile
        mk1 = os.path.normpath(os.path.join(subdir, "Makefile"))
        mk2 = os.path.normpath(os.path.join(subdir, "Kbuild"))
        mk1_exist = os.path.exists(mk1)
        mk2_exist = os.path.exists(mk2)
        if not mk1_exist and not mk2_exist:
            logger.warning("parse_kbuild: Makefile/Kbuild not found for dir %s" % subdir)
            return
        logger.debug("Reading Makefile/KBuild of " + subdir)
        if mode != 1 and mk2_exist:
            with open(mk2, encoding='utf8', errors='replace') as fh:
                src = kbuild_normalize.sub(" ", fh.read())
        else:
            src = ""
        if mode != 2 and mk1_exist:
            with open(mk1, encoding='utf8', errors='replace') as fh:
                src += '\n' + kbuild_normalize.sub(" ", fh.read())
        if not src:
            logger.warning("No Makefile/Kbuild in %s [mode=%s]" % (subdir, mode))
            return

        # includes
        while True:
            m = kbuild_includes.search(src)
            if not m:
                break
            mk2 = m.group(1)
            if not os.path.isfile(mk2):
                logger.warning("parse_kbuild: could not find included file (from %s): %s" %
                               (subdir, mk2))
                src = src[:m.start()] + "\n" + src[m.end():]
                continue
            with open(mk2, encoding='utf8', errors='replace') as fh:
                src2 = kbuild_normalize.sub(" ", fh.read())
            src = src[:m.start()] + "\n" + src2 + "\n" + src[m.end():]

        if mode == 1:
            # arch/*/Makefile is included from root Makefile
            # so paths are relative to root
            self.kbuild_parse_lines('', src)
            if mk2_exist:
                # we are in arch/*/Makefile and we should parse Kbuild but with
                # different context (subdir)
                self.kbuild_parse_dir(subdir, 2)
        else:
            self.kbuild_parse_lines(subdir, src)

    def kbuild_parse_alias(self, subdir, rule, prerequisites):
        if rule in {'obj', 'libs', 'init', 'drivers', 'net', 'core', 'virt', 'usr'}:
            return
        target = os.path.normpath(os.path.join(subdir, rule + '.c'))
        for this_pre_f in prerequisites.split():
            if this_pre_f.endswith('.o'):
                this_pre_fn = os.path.normpath(os.path.join(subdir, this_pre_f))
                this_pre_fc = this_pre_fn[:-2] + '.c'
                self.dep_aliases.setdefault(this_pre_fc, []).append(target)

    def kbuild_parse_lines(self, subdir, src):
        subdir = os.path.normpath(subdir)
        path_comp = os.path.normpath(subdir).split('/')
        dir_deps = set()
        for i in range(len(path_comp)):
            parent_dir = '/'.join(path_comp[:i+1])
            dir_deps.update(self.dir_dep.get(parent_dir, set()))
        for (rule, dep, files) in kbuild_rules.findall(src):
            # rule-$(dep): file1 file2 dir1/ ...
            if not files or files.startswith('-'):  # compiler options
                continue
            if rule in ignore_rules_set:
                continue
            new_deps = dir_deps.copy()
            if dep in ('y', 'm'):
                pass
            elif (dep.startswith('$(CONFIG_') and dep[-1] == ')') or \
                 (dep.startswith('${CONFIG_') and dep[-1] == '}'):
                # obj-$(CONFIG_FOO_BAR) += file1.o file2.o subdir1/ ...
                i = dep.find(')', 10, -1)
                if i > 0:
                    if dep[i + 1:i + 10] == '$(CONFIG_':
                        # few cases with modname-$(CONFIG_A)$(CONFIG_B) += abc.o
                        new_deps.add(dep[2:i])
                        self.modules[dep[2:i]] = files
                        new_deps.add(dep[i + 3:-1])
                        self.modules[dep[i + 3:-1]] = files
                else:
                    new_deps.add(dep[2:-1])
                    if rule == 'fw-shipped':
                        # obsolete rule, not used since 4.14
                        # should we handle also dep=y case?
                        for f in files.split():
                            if f.find('$') > -1:
                                logger.warning("this firmware include indirect firmwares '%s': '%s'" %
                                               (dep[2:-1], os.path.join(subdir, f)))
                            else:
                                self.firmware_table.add_row((dep[2:-1], os.path.join(subdir, f)))
                        continue
                    else:
                        self.modules[dep[2:-1]] = files
            elif dep == 'objs':
                # this merge several files into a module, named {rule}
                self.kbuild_parse_alias(subdir, rule, files)
                continue
            elif dep == 'userldlibs':
                continue
            else:
                logger.warning("parse_kbuild: unknown dep in %s: '%s'" % (subdir, dep))
                continue

            for f in files.split():
                if f.endswith('.o'):
                    fn = os.path.normpath(os.path.join(subdir, f))
                    fc = fn[:-2] + '.c'
                    self.dependencies.setdefault(fc, set()).update(new_deps)
                elif f.endswith('/'):
                    new_dir = os.path.normpath(os.path.join(subdir, f))
                    if subdir:
                        self.dir_dep.setdefault(new_dir, set()).update(new_deps)
                    pass
                else:
                    logger.info("parse_kbuild: unknown target in '%s': '%s, was %s'" %
                                (subdir, f, (rule, dep, files)))

            self.kbuild_parse_alias(subdir, rule, files)

    def _list_dep_rec(self, fn, dep, passed):
        deps = self.dependencies.get(fn, None)
        if deps is not None:
            dep.update(deps)
        aliases = self.dep_aliases.get(fn, None)
        if aliases is not None:
            for alias in aliases:
                if alias in passed:
                    continue
                else:
                    passed.add(alias)
                dep.update(self._list_dep_rec(alias, dep, passed))
        return dep

    def list_dep(self, fn):
        dep = set()
        passed = {fn}
        self._list_dep_rec(fn, dep, passed)
        return dep

from pprint import pprint

mk = Makefiles('.', ['kernel', 'drivers'])
mk.scan()
#pprint(mk.dependencies)
pprint(mk.list_dep('kernel/trace/trace_printk.c'))
pprint(mk.list_dep('kernel/workqueue.c'))
