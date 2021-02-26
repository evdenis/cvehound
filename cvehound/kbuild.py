#!/usr/bin/env python3

import sys
import os
import re
from copy import deepcopy
from os.path import join, basename, dirname

from pprint import pprint

class Makefile():
    @staticmethod
    def __get_kernel_topdirs(path):
        topdirs = []
        with os.scandir(path) as it:
            for entry in it:
                name = entry.name
                if entry.is_dir() and \
                    name != '.git' and \
                    name != 'Documentation' and \
                    name != 'scripts' and \
                    name != 'samples' and \
                    name != 'LICENSES' and \
                    name != '.tmp_versions' and \
                    name != 'tools':
                    topdirs.append(join(path, name))
        return topdirs

    def __init__(self, linux_dir, subdirs=None):
        self.linux_dir = linux_dir
        if subdirs:
            self.topdirs = subdirs
        else:
            self.topdirs = Makefile.__get_kernel_topdirs(linux_dir)
        self.filetree = { 'path': linux_dir, 'makefile': [], 'cfiles': [], 'dirs': {} }
        self.file_config = {}
        self.index = { linux_dir: self.filetree }

    def scan(self):
        for dir in self.topdirs:
            for root, dirs, files in os.walk(dir, topdown=True):
                cfiles = []
                parent = dirname(root) or '.'
                subdir = self.index[parent]['dirs']
                entry = { 'path': root, 'makefile': [], 'cfiles': [], 'dirs': {} }
                for name in files:
                    if name == 'Makefile' or name == 'Kbuild':
                        entry['makefile'].append(name)
                    elif name.endswith('.c') or name.endswith('.S'):
                        cfiles.append(name)
                entry['cfiles'] = cfiles
                subdir[basename(root)] = entry
                self.index[root] = entry

    @staticmethod
    def __merge_obj_configs(old, new):
        assert not set(old.keys()) & set(new.keys()), 'same keys'
        return { **old, **new }

    parse_obj = re.compile(r'obj-(?P<config>y|\$[({]CONFIG_[A-Z0-9_]+[})])\s*.?=\s*')
    parse_objs = re.compile(r'(?P<obj>[a-z0-9_]+)-(objs|y)\s*.?=\s*')

    parse_expr_enabled = re.compile(r'\(\s*\$\(\s*(?P<config>CONFIG_[A-Z0-9_]+)\s*\)\s*,\s*y\s*\)')
    rules = re.compile(r"^([-A-Za-z0-9_]+)-([^-+=: \t\n]+)\s*[:+]?=[ \t]*(.*)$", re.MULTILINE|re.ASCII)

    ignore_rules = frozenset(
    ('clean', 'ccflags', 'cflags', 'aflags', 'asflags', 'mflags', 'cpuflags', 'subdir-ccflags', 'extra'))

    @staticmethod
    def __parse_cmd(obj_config, context, cmd):
        res = Makefile.parse_obj.match(cmd)
        if res:
            config = None
            cfg = res.group('config')
            if cfg != 'y':
                config = cfg[2:-1]
            objs = cmd[res.end():].split()
            for obj in objs:
                #FIXME: assert obj not in obj_config, 'already ' + obj
                if config:
                    if obj not in obj_config:
                        obj_config[obj] = { 'enabled': [config], 'disabled': [] }
                    else:
                        obj_config[obj]['enabled'].append(config)
                else:
                    if obj not in obj_config:
                        obj_config[obj] = deepcopy(context)
            return obj_config
        res = Makefile.parse_objs.match(cmd)
        if res:
            entry = res.group('obj') + '.o'
            if entry in obj_config:
                objs = cmd[res.end():].split()
                config = obj_config[entry]
                del obj_config[entry]
                for obj in objs:
                    obj_config[obj] = config
        elif cmd.startswith('CFLAGS_'):
            pass
        else:
            print('MISS', cmd)
        return obj_config

    @staticmethod
    def __parse_makefile(makefile):
        obj_config = {}
        with open(makefile, 'rt', encoding='utf-8') as fh:
            cmd = ''
            if_level = 0
            context = { 'enabled': [], 'disabled': [] }
            current = []
            for line in fh:
                line = line.lstrip()
                if not line:
                    continue
                if line[0:1] == '#':
                    continue
                elif line.endswith('\\\n'):
                    cmd += line[:-2]
                    continue
                elif line.startswith('if'):
                    if line.startswith('ifdef'):
                        enabled = line.split()[1]
                        context['enabled'].append(enabled)
                        current.append(( enabled, True ))
                    elif line.startswith('ifndef'):
                        disabled = line.split()[1]
                        context['disabled'].append(disabled)
                        current.append(( disabled, False ))
                    elif line.startswith('ifeq'):
                        expr = line.split()[1]
                        res = Makefile.parse_expr_enabled.match(expr)
                        if res:
                            enabled = res.group('config')
                            context['enabled'].append(enabled)
                            current.append(( enabled, True ))
                        else:
                            print('TODO', expr)
                            current.append(None)
                    elif line.startswith('ifneq'):
                        expr = line.split()[1]
                        res = Makefile.parse_expr_enabled.match(expr)
                        if res:
                            disabled = res.group('config')
                            context['disabled'].append(disabled)
                            current.append(( disabled, False ))
                        else:
                            print('TODO', expr)
                            current.append(None)
                    else:
                        print('unknown', line)
                    if_level += 1
                    continue
                elif line.startswith('endif'):
                    config = current.pop()
                    if config:
                        if config[1]:
                            context['enabled'].pop()
                        else:
                            context['disabled'].pop()
                    if_level -= 1
                    assert if_level >= 0, 'if/endif mess'
                    continue
                else:
                    cmd += line
                cmd = cmd.strip()
                obj_config = Makefile.__parse_cmd(obj_config, context, cmd)
                cmd = ''
        return obj_config

    def process(self, tree=None):
        obj_config = {}
        if tree == None:
            tree = self.filetree
        for d in tree['dirs']:
            self.process(tree['dirs'][d])
        configs = {}
        for f in tree['cfiles']:
            configs[f] = { 'enabled': [], 'disabled': [] }
        for makefile in tree['makefile']:
            obj_config = self.__merge_obj_configs(obj_config, self.__parse_makefile(join(tree['path'], makefile)))
        for obj in obj_config:
            if obj.endswith('.o'):
                cfile = obj[:-2] + '.c'
                sfile = obj[:-2] + '.S'
                assert cfile not in configs or sfile not in configs, 'Both files ' + cfile + ' ' + sfile
                file = None
                if cfile in configs:
                    file = cfile
                elif sfile in configs:
                    file = sfile
                else:
                    print("WARNING: can't find", obj)
                    continue
                configs[file]['enabled'].extend(obj_config[obj]['enabled'])
                configs[file]['disabled'].extend(obj_config[obj]['disabled'])
            elif obj.endswith('/'):
                dir = obj[:-1]
                if '/' in dir:
                    continue
                assert '/' not in dir, 'not nested dir ' + dir
                if dir not in tree['dirs']:
                    print('Unknown dir', dir)
                    continue
                path = tree['dirs'][dir]['path']
                for file in tree['dirs'][dir]['cfiles']:
                    file = join(path, file)
                    if not self.file_config[file]['enabled']:
                        self.file_config[file]['enabled'].extend(obj_config[obj]['enabled'])
                    self.file_config[file]['disabled'].extend(obj_config[obj]['disabled'])
            else:
                # FIXME assert False, 'Unknown obj ' + obj
                pass
        for file in configs:
            self.file_config[join(tree['path'], file)] = configs[file]

