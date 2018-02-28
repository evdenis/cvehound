import os
import re

import cvehound.kbuildparse.base_classes as BaseClasses
import cvehound.kbuildparse.data_structures as DataStructures
import cvehound.kbuildparse.helper as Helper
import cvehound.kbuildparse.linux as Linux

class KbuildParser(object):
    """ Main class: parse Kbuild files recursively."""

    def __init__(self, model=None, arch='x86'):
        """ Initialize the parser. We need a model for _MODULE options."""
        self.model = model
        self.arch = arch
        self.local_vars = DataStructures.VariableStore()
        self.global_vars = DataStructures.VariableStore()
        self.init_class = Linux.LinuxInit(model, arch)
        self.before_pass = [Linux.LinuxBefore(model, arch)]
        self.during_pass = [
            Linux._00_LinuxDefinitions(model, arch),
            Linux._01_LinuxIf(model, arch),
            Linux._02_LinuxObjects(model, arch)
        ]
        self.output = Linux._03_LinuxOutput(model, arch)
        self.after_pass = [
            Linux._01_LinuxExpandMacros(model, arch),
            Linux._02_LinuxProcessSubdirectories(model, arch),
            self.output
        ]
        self.before_exit = []
        self.file_content_cache = {}

    def enter_new_symbolic_level(self):
        """ Get a fresh mapping for variables, save old mapping in nxt."""
        new_store = DataStructures.VariableStore()
        new_store.nxt = self.local_vars
        self.local_vars = new_store

    def leave_symbolic_level(self):
        """ Restore old mapping from local_vars.nxt."""
        assert self.local_vars.nxt is not None
        self.local_vars = self.local_vars.nxt

    def process_kbuild_or_makefile(self, path, conditions):
        """ Central processing function. Parse the file in @path which
        has preconditions @conditions. Processing is done by classes which
        have previously been gathered in corresponding lists."""

        if not os.path.isfile(path):
            return

        basepath = os.path.dirname(path)

        # Create new symbol table for local variables
        self.enter_new_symbolic_level()

        # Execute BeforePass subclass functions
        for processor in self.before_pass:
            processor.process(self, basepath)

        self.read_whole_file(path)

        # Main processing loop, iteration over file
        for line in self.file_content_cache[path]:
            # Execute DuringPass module functions
            for processor in self.during_pass:
                # As soon as one method returns True, continue with next line
                if processor.process(self, line, basepath):
                    break
        # End of main processing loop

        # Execute subclasses of AfterPass
        for processor in self.after_pass:
            processor.process(self, path, conditions)

        # Drop current symbol table
        self.leave_symbolic_level()

    def get_config(self):
        return self.output.config 

    def_regex = re.compile(r"([A-Z_]+)\s*(?:=|:=)\s*(.*)$")
    def_add_regex = re.compile(r"([A-Z_]+)\s*(?:\+=)\s*(.*)$")
    addprefix_regex = re.compile(r"(.*)\$\(addprefix (.+)\s*,\s*(.+?)\)(.*)")
    addsuffix_regex = re.compile(r"(.*)\$\(addsuffix (.+)\s*,\s*(.+?)\)(.*)")

    def process_addprefix(self, string):
        m = self.addprefix_regex.match(string)
        if m:
            pre, prefix, targets, post = m.groups()
            l = []
            for t in targets.split():
                l.append(prefix + t)
            string = "{}{}{}".format(pre, " ".join(l), post)
        return string

    def process_addsuffix(self, string):
        m = self.addsuffix_regex.match(string)
        if m:
            pre, suffix, targets, post = m.groups()
            l = []
            for t in targets.split():
                l.append(t + suffix)
            string = "{}{}{}".format(pre, " ".join(l), post)
        return string

    def resolve(self, content, defs, srcpath="."):
        used_vars = re.findall(r"\$\(([A-Z_]+)\)", content)
        content = re.sub(r"\$\(src\)", srcpath, content)
        for var in used_vars:
            if not var in defs:
                continue
            content = re.sub(r"\$\(" + var + r"\)", defs[var], content)
        content = self.process_addprefix(content)
        content = self.process_addsuffix(content)
        return content

    def note_definition(self, line, defs):
        match = self.def_regex.match(line)
        if match:
            lhs, rhs = match.groups()
            defs[lhs] = self.resolve(rhs, defs)
        else:
            match = self.def_add_regex.match(line)
            if match:
                lhs, rhs = match.groups()
                if not lhs in defs:
                    defs[lhs] = ""
                defs[lhs] += " " + self.resolve(rhs, defs)

    def read_whole_file(self, path):
        """ Read the content of the file in @path into the file_content_cache
        dictionary. Include statements are resolved on-the-fly (see comment in
        resolve_includes())."""
        defs = {}
        output = []
        with open(path, "r") as infile:
            dirname = os.path.dirname(path)
            while True:
                (good, line) = Helper.get_multiline_from_file(infile)
                if not good:
                    break

                self.note_definition(line, defs)

                inputs = self.resolve_includes(line, dirname, defs)
                output.extend(inputs)

        self.file_content_cache[path] = output

    def resolve_includes(self, line, srcpath, defs):
        """ If @line starts with "include", read all the lines in the included
        file. This is done recursively to treat recursive includes. The @srcpath
        parameter is needed to correctly resolve the $(src) variable in the
        included files (it needs to contain the path to the folder of the
        top-most including Makefile)."""

        line = self.resolve(line, defs, srcpath)

        if not line.startswith("include "):
            return [DataStructures.LineObject(line)]

        lines = []

        targets = [x.rstrip() for x in line.split()[1:]]
        for target in targets:
            if not os.path.isfile(target):
                target = os.path.join(srcpath, target)
                if not os.path.isfile(target):
                    continue

            with open(target, "r") as infile:
                while True:
                    (good, line) = Helper.get_multiline_from_file(infile)
                    if not good:
                        break
                    self.note_definition(line, defs)
                    lines.extend(self.resolve_includes(line, srcpath, defs))

        return lines

