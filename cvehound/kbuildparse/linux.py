""" Implementation of kbuildparse base classes for Linux."""

# Copyright (C) 2014-2015 Andreas Ruprecht <andreas.ruprecht@fau.de>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

import collections
import logging
import os
import re

import cvehound.kbuildparse.base_classes as BaseClasses
import cvehound.kbuildparse.data_structures as DataStructures
import cvehound.kbuildparse.helper as Helper

# Helper functions in module
CONFIG_FORMAT = r"CONFIG_([A-Za-z0-9_-]+)"
REGEX_CONFIG = re.compile(CONFIG_FORMAT)
REGEX_IFNEQ = re.compile(r"\s*(ifneq|ifeq)\s+(.*)")
REGEX_IFNEQ_CONF = re.compile(r"\(\$\(" + CONFIG_FORMAT +
                              r"\),\s*(y|m|n|\s*)\s*\)")
REGEX_IFNDEF = re.compile(r"\s*(ifdef|ifndef)\s+(.*)")
REGEX_ENDIF = re.compile(r"\s*endif\s*")
REGEX_ELSE = re.compile(r"\s*else\s*")

def regex_ifneq_match(line, ifdef_condition, global_vars, model):
    """ Check if @line resembles a line describing a condition
    with if(n)eq. If so, update the condition in @ifdef_condition and
    return True, otherwise return False."""
    regex_match = REGEX_IFNEQ.match(line)
    if not regex_match:
        return False

    if global_vars["no_config_nesting"] > 0:
        global_vars.increment_variable("no_config_nesting")
    else:
        positive_keyword = (regex_match.group(1) != "ifneq")
        possible_conf = regex_match.group(2)
        conf_results = REGEX_IFNEQ_CONF.match(possible_conf)
        if conf_results:
            positive_comp = (conf_results.group(2) == "y" or
                             conf_results.group(2) == "m")
            config = conf_results.group(1)

            conf = Helper.get_config_string(config, model)
            if positive_keyword == positive_comp:
                ifdef_condition.add_condition(conf)
            else:
                ifdef_condition.add_condition("~" + conf)
        else:
            global_vars.increment_variable("no_config_nesting")
    return True

def regex_ifndef_match(line, ifdef_condition, global_vars, model):
    """ Check if @line resembles a line describing a condition
    with if(n)def. If so, update the condition in @ifdef_condition and
    return True, otherwise return False."""
    regex_match = REGEX_IFNDEF.match(line)
    if not regex_match:
        return False

    if global_vars["no_config_nesting"] > 0:
        global_vars.increment_variable("no_config_nesting")
    else:
        keyword = regex_match.group(1)
        rhs = regex_match.group(2)

        conf_results = REGEX_CONFIG.match(rhs)
        if conf_results:
            conf = Helper.get_config_string(conf_results.group(1),\
                                           model)
            if keyword == "ifdef":
                ifdef_condition.add_condition(conf)
            else:
                ifdef_condition.add_condition("~" + conf)
        else:   # Not parseable -> nesting level
            global_vars.increment_variable("no_config_nesting")
    return True

def regex_endif_match(line, ifdef_condition, global_vars):
    """ Check if @line resembles a line describing the end of a conditional
    block (endif). If so, update the condition in @ifdef_condition and
    return True, otherwise return False."""
    regex_match = REGEX_ENDIF.match(line)
    if not regex_match:
        return False

    if global_vars["no_config_nesting"] > 0:
        global_vars.decrement_variable("no_config_nesting")
    else:
        ifdef_condition.pop()
    return True

def regex_else_match(line, ifdef_condition, global_vars):
    """ Check if @line resembles a line describing an else.
    If so, update the condition in ifdef_condition and
    return True, otherwise return False."""
    regex_match = REGEX_ELSE.match(line)
    # Note that this regex can only match single "else" statements in one line,
    # constructs like "else ifeq $(...)" are not supported (at the time of
    # writing, this is not used at any relevant place in the Linux kernel).
    if not regex_match:
        return False

    if global_vars["no_config_nesting"] > 0:
        pass
    else:
        last = ifdef_condition.pop()
        if last.startswith("~"):
            ifdef_condition.add_condition(last[1:])
        else:
            ifdef_condition.add_condition("~" + last)
    return True

def update_if_condition(line, ifdef_condition, global_vars, local_vars, model):
    """ Update the @ifdef_condition with information from @line.
    If updating succeeded, return True. Otherwise signal skipping
    of the line by returning True if we're inside an unparseable block and
    False if the other logic should try to process it. """
    if regex_ifneq_match(line, ifdef_condition, global_vars, model) or \
            regex_ifndef_match(line, ifdef_condition, global_vars, model) or \
            regex_else_match(line, ifdef_condition, global_vars) or \
            regex_endif_match(line, ifdef_condition, global_vars):
        return True
    ret = global_vars["no_config_nesting"] > 0
    return ret


class LinuxInit(BaseClasses.InitClass):
    """ Init class for Linux."""

    # Arch specific regexes
    arch_spec_line = r"\s*(core|init|drivers|net|libs)-(y|\$\(" + \
                     CONFIG_FORMAT + r"\))\s*(=|\+=|:=)\s*(.*)"
    regex_arch_spec = re.compile(arch_spec_line)
    arm_line = r"\s*(machine|plat)-(y|\$\(" + CONFIG_FORMAT + \
               r"\))\s*(=|\+=|:=)\s*(.*)"
    regex_arm = re.compile(arm_line)
    include_line = r"include\s+(.*)"
    regex_include = re.compile(include_line)
    mips_platforms_line = r"platforms\s*\+=\s*(.*)"
    regex_mips_platforms = re.compile(mips_platforms_line)
    mips_plat_line = r"platform-\$\(" + CONFIG_FORMAT + r"\)\s*\+=\s*(.*)"
    regex_mips_plat = re.compile(mips_plat_line)

    def __init__(self, model, arch):
        """ Constructor for InitLinux, takes model and arch parameters."""
        super(LinuxInit, self).__init__(model, arch)

    def parse_architecture_regular(self, line, local_arch_dirs):
        """ Parse an architecture Makefile. This looks for any additional
        lists (core|init|drivers|net|libs) and saves the corresponding
        conditions for those directories."""
        regex_match = self.regex_arch_spec.match(line)
        if not regex_match:
            return False

        current_precondition = DataStructures.Precondition()
        config_item = regex_match.group(2)
        if config_item != "y":
            config_item = regex_match.group(3)
            condition = Helper.get_config_string(config_item, self.model)
            current_precondition.add_condition(condition)

        rhs = regex_match.group(5)

        matches = [x for x in re.split("\t| ", rhs) if x]

        for match in matches:
            if not os.path.isdir(match):
                continue

            if match[-1] != '/':
                match += '/'
            logging.debug("adding match " + match + " with " + \
                          config_item)
            local_arch_dirs[match].append(current_precondition[:])
        return True

    def parse_arm_architecture(self, line, local_arch_dirs):
        """ Parse the Makefile at arch/arm/ and look for
        machine-$() and plat-$() lists describing the subdirectories."""

        if self.arch != "arm":
            return False

        regex_match = self.regex_arm.match(line)
        if not regex_match:
            return False

        current_precondition = DataStructures.Precondition()
        lst = regex_match.group(1)
        config_item = regex_match.group(2)
        if config_item != "y":
            config_item = regex_match.group(3)
            condition = Helper.get_config_string(config_item, self.model)
            current_precondition.add_condition(condition)

        rhs = regex_match.group(5)

        matches = [x for x in re.split("\t| ", rhs) if x]

        for match in matches:
            fullpath = ""
            if lst == "machine":
                fullpath = "arch/arm/mach-" + match
            else:
                fullpath = "arch/arm/plat-" + match
            if not os.path.isdir(fullpath):
                continue

            if fullpath[-1] != '/':
                fullpath += '/'
            logging.debug("adding ARM match " + match + " with " + \
                          config_item)
            local_arch_dirs[fullpath].append(current_precondition[:])
        return True

    def parse_blackfin_architecture(self, line, local_arch_dirs):
        """ Parse the Makefile at arch/blackfin/ and look for any
        lines describing machine-$(CONFIG_XY) lists."""

        if self.arch != "blackfin":
            return False

        regex_match = self.regex_arm.match(line)
        if not regex_match:
            return False

        current_precondition = DataStructures.Precondition()
        lst = regex_match.group(1)
        config_item = regex_match.group(2)
        if config_item != "y":
            config_item = regex_match.group(3)
            condition = Helper.get_config_string(config_item, self.model)
            current_precondition.add_condition(condition)

        rhs = regex_match.group(5)

        matches = [x for x in re.split("\t| ", rhs) if x]

        for match in matches:
            if lst != "machine":    # Should never happen in blackfin
                logging.error("plat- list should not be present in blackfin")
                continue

            fullpath = "arch/blackfin/mach-" + match
            if os.path.isdir(fullpath):
                if fullpath[-1] != '/':
                    fullpath += '/'
                local_arch_dirs[fullpath].append(current_precondition[:])

            fullpath = "arch/blackfin/mach-" + match + "/boards/"
            if os.path.isdir(fullpath):
                if fullpath[-1] != '/':
                    fullpath += '/'
                local_arch_dirs[fullpath].append(current_precondition[:])
        return True

    def parse_mips_platform(self, path, local_arch_dirs):
        """ Parse a arch/mips/*/Platform file. Mips describes the dependencies
        there, which is why we need to parse this as well."""

        with open(path, "r") as infile:
            while True:
                (good, line) = Helper.get_multiline_from_file(infile)
                if not good:
                    break

                regex_match = self.regex_mips_plat.match(line)
                if not regex_match:
                    continue

                config = "CONFIG_" + regex_match.group(1)
                rhs = regex_match.group(2)
                fulldir = "arch/mips/" + rhs
                if os.path.isdir(fulldir):
                    current_precondition = DataStructures.Precondition()
                    current_precondition.add_condition(config)
                    local_arch_dirs[fulldir].append(current_precondition)

    def parse_mips_architecture(self, line, local_arch_dirs):
        """ Parses the main mips Makefile. Calls parse_mips_platform for
        any found Platform file in a subdirectory."""

        if self.arch != "mips":
            return False
        regex_match = self.regex_include.match(line)
        if not regex_match:
            return False

        with open(regex_match.group(1), "r") as included_file:
            for line in included_file:
                platform_match = self.regex_mips_platforms.match(line)
                if platform_match:
                    subpath = "arch/mips/" + platform_match.group(1) + \
                              "/Platform"
                    self.parse_mips_platform(subpath, local_arch_dirs)
        return True

    def parse_architecture_path(self, path, dirs_to_process):
        """ Gather additional information from an architecture
        directory. The arch-Makefiles behave a little bit differently
        depending on the architecture, which is why other helper
        routines are called for processing them."""

        if not os.path.isfile(path):
            logging.debug("arch/ parsing: no such file: " + path)
            return

        # Through the use of a defaultdict, we can directly call
        # local_arch_dirs[dir].append(..) without explicitely creating the
        # corresponding dict.
        local_arch_dirs = collections.defaultdict(list)
        basepath = os.path.dirname(path)

        logging.debug("Parsing architecture path " + basepath)

        with open(path, "r") as infile:
            while True:
                (good, line) = Helper.get_multiline_from_file(infile)
                if not good:
                    break

                line = line.replace(r"$(ARCH)", self.arch)
                line = line.replace(r"$(srctree)", ".")
                logging.debug("read line: " + line)
                if self.parse_architecture_regular(line, local_arch_dirs):
                    continue
                elif self.parse_arm_architecture(line, local_arch_dirs):
                    continue
                elif self.parse_blackfin_architecture(line, local_arch_dirs):
                    continue
                elif self.parse_mips_architecture(line, local_arch_dirs):
                    continue

        for item in local_arch_dirs:
            dirs_to_process[item] = \
                Helper.build_precondition(local_arch_dirs[item])

    def get_file_for_subdirectory(self, directory):
        """ Select the correct Kbuild makefile in directory."""
        if not directory.endswith('/'):
            directory += '/'
        descend = directory + "Kbuild"
        if not os.path.isfile(descend):
            descend = directory + "Makefile"
        return descend

    def process(self, parser, dirs_to_process, kernel_dir='.'):
        """ Here we can read the command line arguments, create global
        variables and insert items into a list of directories which will
        be processed. """

        parser.global_vars.create_variable("no_config_nesting", 0)

        # Default directories have no precondition
        for subdir in ["init/", "drivers/", "sound/", "firmware/", "net/",
                       "lib/", "usr/", "kernel/", "mm/", "fs/", "ipc/",
                       "security/", "crypto/", "block/", "certs/", "virt/"]:
            dirs_to_process[os.path.join(kernel_dir, subdir)] = DataStructures.Precondition()

        # Parse architecture specific path
        self.parse_architecture_path(os.path.join(kernel_dir, "arch", self.arch, "Makefile"),
                                     dirs_to_process)



class LinuxBefore(BaseClasses.BeforePass):
    """ Initialization of per-file variables for Linux."""

    def __init__(self, model, arch):
        """ Constructor for BeforeLinux, takes model and arch parameters"""
        super(LinuxBefore, self).__init__(model, arch)

    def process(self, parser, basepath):
        """ Initialize data structures before main processing loop."""
        # Composite object handling
        parser.local_vars.create_variable("composite_map",
            collections.defaultdict(DataStructures.Alternatives))

        # Main data structure
        parser.local_vars.create_variable("file_features",
            collections.defaultdict(DataStructures.Alternatives))

        # directory preconditions
        parser.local_vars.create_variable("dir_cond_collection",
            collections.defaultdict(DataStructures.Alternatives))

        # Updated with #if(n)def/#if(n)eq conditions
        parser.local_vars.create_variable("ifdef_condition",
            DataStructures.Precondition())

        # Local variable definitions
        parser.local_vars.create_variable("definitions", {})


class _00_LinuxDefinitions(BaseClasses.DuringPass):

    regex_subst_match = re.compile(r".*-\$\(subst m,y,\$\(" + CONFIG_FORMAT + "\)\)\s*[\+|:|]=.*")
    regex_subst_sub = re.compile(r"(.*)-\$\(subst m,y,\$\(" + CONFIG_FORMAT + "\)\)\s*(\+=|=|:=)(.*)")
    regex_my_match = re.compile(r".*-\$\(" + CONFIG_FORMAT + ":m=y\)\s*[\+|:|]=.*")
    regex_my_sub = re.compile(r"(.*)-\$\(" + CONFIG_FORMAT + ":m=y\)\s*(\+=|=|:=)(.*)")
    regex_def = re.compile(r"\s*([A-Z_-]+)\s*[\?:]?=\s*(.*)")

    def __init__(self, model, arch):
        super(_00_LinuxDefinitions, self).__init__(model, arch)

    def do_line_replacements(self, parser, line):
        """ Replace occurences of known patterns and definitions in line and
        return them. """

        # "obj-$(subst m,y,$(CONFIG_XY)) ?? obj.o" becomes "obj-$(CONFIG_XY) ?? obj.o"
        if self.regex_subst_match.match(line):
            line = self.regex_subst_sub.sub(r"\1-$(CONFIG_\2) \3 \4", line)
        # "obj-$(CONFIG_XY:m=y) ?? obj.o" becomes "obj-$(CONFIG_XY) ?? obj.o"
        if self.regex_my_match.match(line):
            line = self.regex_my_sub.sub(r"\1-$(CONFIG_\2) \3 \4", line)

        # Replacement of defined macros
        for definition in parser.local_vars["definitions"]:
            if r"$(" + definition + r")" in line:
                line = re.sub(r"\$\(" + definition + r"\)",
                              parser.local_vars["definitions"][definition],
                              line)

        return line

    def process(self, parser, line, basepath):
        _line = line.raw_line
        # Assumes definitions are UPPERCASE and done with :=
        definition = self.regex_def.match(_line)
        if definition:
            # Recursive definitions are ugly for now, so ignore them.
            if definition.group(1) in definition.group(2):
                return False

            parser.local_vars["definitions"][definition.group(1)] = \
                definition.group(2)
            return True
        else:
            line.processed_line = self.do_line_replacements(parser, _line)
            return False


class _01_LinuxIf(BaseClasses.DuringPass):
    """ Evaluation of ifdef/ifeq conditions in Linux."""

    def __init__(self, model, arch):
        super(_01_LinuxIf, self).__init__(model, arch)

    def process(self, parser, line, basepath):
        """ Process lines starting with if{n}{eq,def}. If the condition could
        not be properly parsed, the line and all following lines until the
        corresponding endif are marked as invalid - update_if_condition will
        return False in that case, as the nesting level has been incremented to
        a value > 0. """
        _line = line.processed_line
        retval = update_if_condition(_line, parser.local_vars["ifdef_condition"],
                                     parser.global_vars, parser.local_vars,
                                     self.model)
        line.condition = parser.local_vars["ifdef_condition"][:]
        line.invalid = retval
        return retval


class _02_LinuxObjects(BaseClasses.DuringPass):
    """ Evaluation of lines describing object files in Linux."""

    obj_line = r"\s*(obj|lib)-(y|m|\$[\(\{]" + CONFIG_FORMAT + \
               r"[\)\}])\s*(:=|\+=|=)\s*(([A-Za-z0-9.,_\$\(\)/-]+\s*)+)"
    regex_obj = re.compile(obj_line)
    subdir_line = r"\s*subdir-(y|\$\(" + CONFIG_FORMAT + r"\))\s*\+=(.*)"
    regex_subdir = re.compile(subdir_line)

    def __init__(self, model, arch):
        super(_02_LinuxObjects, self).__init__(model, arch)

    def __process(self, parser, line, basepath):
        line = line.processed_line

        # Try obj-... +=/:=/= objfile.o
        regex_match = self.regex_obj.match(line)
        if regex_match:
            rhs = regex_match.group(5)
            # Fixes one special case in arch/mips/lib, could be extended with
            # other make-commands.
            if rhs.startswith("$(filter-out"):
                return False
            # First, check for match on obj-y or obj-m
            if regex_match.group(2) == "y" or regex_match.group(2) == "m":
                matches = [x for x in re.split("\t| ", rhs) if x]
                for match in matches:
                    fullpath = basepath + "/" + match
                    if os.path.isdir(fullpath):
                        parser.local_vars["dir_cond_collection"][fullpath].\
                            add_alternative(
                                parser.local_vars["ifdef_condition"][:]
                            )
                    else:
                        sourcefile = Helper.guess_source_for_target(fullpath)
                        if sourcefile:
                            parser.local_vars["file_features"][sourcefile].\
                                add_alternative(
                                    parser.local_vars["ifdef_condition"][:]
                                )
                        else:
                            parser.local_vars["composite_map"][fullpath].\
                                add_alternative(
                                    parser.local_vars["ifdef_condition"][:]
                                )
            else:
                # Then test obj-$(CONFIG_XY)
                config = regex_match.group(3)

                condition = Helper.get_config_string(config, self.model)

                matches = [x for x in re.split("\t| ", rhs) if x]

                parser.local_vars["ifdef_condition"].add_condition(condition)

                for match in matches:
                    fullpath = basepath + "/" + match
                    if os.path.isdir(fullpath):
                        # Has this directory been picked up via subdir-XY?
                        if parser.local_vars["ifdef_condition"] in \
                                parser.local_vars["dir_cond_collection"][fullpath]:
                            continue
                        parser.local_vars["dir_cond_collection"][fullpath].\
                            add_alternative(
                                parser.local_vars["ifdef_condition"][:]
                            )
                    else:
                        sourcefile = Helper.guess_source_for_target(fullpath)
                        if sourcefile:
                            parser.local_vars["file_features"][sourcefile].\
                                add_alternative(
                                    parser.local_vars["ifdef_condition"][:]
                                )
                        # Remove 'else' if composite lists with the name of
                        # a source file exist (drivers/media/pci/mantis/)
                        else:
                            parser.local_vars["composite_map"][fullpath].\
                                add_alternative(
                                    parser.local_vars["ifdef_condition"][:]
                                )

                parser.local_vars["ifdef_condition"].pop()
        # Up to v3.15, the security/ subdir used only subdir-$(CONFIG..) for
        # descending into subdirectories. All other directories didn't...
        else:
            match = self.regex_subdir.match(line)
            if not match:
                return False

            # If subdir is conditional, add condition to ifdef_condition
            if match.group(1) != "y":
                condition = Helper.get_config_string(match.group(2), self.model)
                parser.local_vars["ifdef_condition"].add_condition(condition)

            rhs = match.group(3)
            rhs_matches = [x.rstrip("/") for x in re.split("\t| ", rhs) if x]
            for m in rhs_matches:
                fullpath = basepath + "/" + m + "/"
                if not os.path.isdir(fullpath):
                    continue

                # Has this directory been picked up via obj-XY?
                if parser.local_vars["ifdef_condition"] in \
                        parser.local_vars["dir_cond_collection"][fullpath]:
                    continue

                parser.local_vars["dir_cond_collection"][fullpath].\
                    add_alternative(
                        parser.local_vars["ifdef_condition"][:]
                    )

            if match.group(1) != "y":
                parser.local_vars["ifdef_condition"].pop()

        return True

    def process(self, parser, line, basepath):
        if "$(BITS)" in line.processed_line:
            line_1 = DataStructures.LineObject(line.raw_line)
            line_1.processed_line = line.processed_line.replace(r"$(BITS)", "32")
            line_1.condition = line.condition
            line_1.invalid = line.invalid
            line_2 = DataStructures.LineObject(line.raw_line)
            line_2.processed_line = line.processed_line.replace(r"$(BITS)", "64")
            line_2.condition = line.condition
            line_2.invalid = line.invalid

            lines = [line_1, line_2]
        else:
            lines = [line]

        for line in lines:
            self.__process(parser, line, basepath)


class _01_LinuxExpandMacros(BaseClasses.AfterPass):
    """ Expand macros in Linux Makefiles."""

    # Static strings/regexes
    regex_base = re.compile(r"([A-Za-z0-9,_-]+)\.o|\$\(([A-Za-z0-9,_-]+)\)")

    def __init__(self, model, arch):
        """ Constructor for _01_LinuxExpandMacros. """
        super(_01_LinuxExpandMacros, self).__init__(model, arch)

    def expand_macro(self, name, path, condition, already_expanded, parser, maxdepth=3):
        """ Expand a macro named @name. Preconditions to the folder are given
        in @condition. The input file is @path and to avoid endless
        recursion processing is aborted if the current name is already present
        in @already_expanded. To save the results, the local variables are
        accessed via the @parser parameter."""

        if maxdepth == 0:
            return

        if name in already_expanded:
            return
        else:
            already_expanded.add(name)

        basepath = os.path.dirname(name)
        filename = os.path.basename(name)

        basename = ""

        # Extract base name from macro name
        match = self.regex_base.match(filename)
        if not match:
            return

        if match.group(1) is None:  # we have a macro
            basename = match.group(2)
            if basename.endswith("y"):
                basename = basename[:-1]
        elif match.group(2) is None:  # we have a file
            basename = match.group(1)

        scan_regex_string = ""
        if match.group(1) is None:
            scan_regex_string = r"\s*" + basename + r"(|y|\$\(" + \
                                CONFIG_FORMAT + r"\))\s*(:=|\+=|=)\s*(.*)"
        else:
            scan_regex_string = r"\s*" + basename + r"(|-y|-objs|-\$\(" + \
                                CONFIG_FORMAT + r"\))\s*(:=|\+=|=)\s*(.*)"

        scan_regex = re.compile(scan_regex_string)

        if not path in parser.file_content_cache:
            parser.read_whole_file(path)

        inputs = parser.file_content_cache[path]

        for line in inputs:
            if line.invalid:
                continue

            ifdef_condition = line.condition
            line = line.processed_line

            match = scan_regex.match(line)
            if not match:
                continue

            config_in_composite = match.group(2)
            condition_comp = ""
            if config_in_composite:
                condition_comp = Helper.get_config_string(config_in_composite,
                                                         self.model)

            rhs = match.group(4)

            matches = [x for x in re.split("\t| ", rhs) if x]
            for item in matches:
                fullpath = basepath + "/" + item
                passdown_condition = condition[:]
                if config_in_composite:
                    passdown_condition.append(condition_comp)

                if os.path.isdir(fullpath):
                    parser.local_vars["dir_cond_collection"]\
                        [fullpath].add_alternative(passdown_condition[:])
                else:
                    sourcefile = Helper.guess_source_for_target(fullpath)
                    if not sourcefile:
                        self.expand_macro(fullpath, path,passdown_condition,
                                          already_expanded, parser, maxdepth-1)
                    else:
                        full_condition = DataStructures.Precondition()
                        if len(condition) > 0:
                            full_condition = condition[:]
                        if config_in_composite:
                            full_condition.append(condition_comp)
                        if len(ifdef_condition) > 0:
                            full_condition.extend(ifdef_condition)

                        parser.local_vars["file_features"][sourcefile].\
                            add_alternative(full_condition[:])

        already_expanded.discard(name)

    def process(self, parser, path, condition_for_current_dir):
        """ Process macros from composite_map variable. """
        # Macro expansion
        for obj in parser.local_vars.get_variable("composite_map"):
            downward_condition = Helper.build_precondition(parser.\
                                    local_vars["composite_map"][obj])
            already_expanded = set()

            # Pass an empty set as the already_expanded parameter, as
            # expand_macro is allowed to call itself recursively
            self.expand_macro(obj, path, downward_condition,
                              already_expanded, parser)


class _02_LinuxProcessSubdirectories(BaseClasses.AfterPass):
    """ Process subdirectories in Linux."""

    def __init__(self, model, arch):
        """ Constructor for _02_LinuxProcessSubdirectories. """
        super(_02_LinuxProcessSubdirectories, self).__init__(model, arch)

    def process(self, parser, path, condition_for_current_dir):
        """ Process all subdirectories."""
        for directory in parser.local_vars["dir_cond_collection"]:
            downward_condition = Helper.build_precondition(
                parser.local_vars["dir_cond_collection"][directory],
                condition_for_current_dir)
            descend = parser.init_class.get_file_for_subdirectory(directory)

            parser.process_kbuild_or_makefile(descend, downward_condition)


class _03_LinuxOutput(BaseClasses.AfterPass):
    """ Output class for Linux."""

    def __init__(self, model, arch):
        """ Constructor for _03_LinuxOutput. """
        super(_03_LinuxOutput, self).__init__(model, arch)
        self.config = {}

    def process(self, parser, path, condition_for_current_dir):
        """ Print conditions collected in file_features variable. """
        for item in sorted(parser.local_vars["file_features"]):
            # Build the precondition, including the conditions for the current
            # directory.
            precondition = Helper.\
                    build_precondition(parser.local_vars["file_features"][item],
                                       condition_for_current_dir)

            full_string = " & ".join(precondition)
            self.config[item] = full_string
