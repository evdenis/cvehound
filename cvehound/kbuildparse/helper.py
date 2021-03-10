""" Helper module for kbuildparse."""

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

import os
import cvehound.kbuildparse.data_structures as DataStructures

def build_precondition(input_list, additional=None):
    """ Build a DataStructures.Precondition object from a given @input_list.
    Additional constraints from @additional are added to the Precondition."""
    alternatives = []
    for alternative in input_list:
        string = " & ".join(alternative)
        if string != "":
            alternatives.append(string)
        else:
            # This case means that at least one unconditional path was found ->
            # return no condition.
            alternatives = []
            break

    alt_string = " | ".join(alternatives)

    ret = DataStructures.Precondition()
    if additional:
        for condition in additional:
            ret.add_condition(condition, keep_duplicates=False)

    if len(alternatives) > 1:
        ret.add_condition("(" + alt_string + ")", keep_duplicates=False)
    elif len(alt_string) > 1:
        ret.add_condition(alt_string, keep_duplicates=False)

    return ret

def guess_source_for_target(target):
    """
    for the given target, try to determine its source file.
    generic version for linux and busybox
    return None if no source file could be found
    """
    for suffix in ('.c', '.S', '.s', '.l', '.y', '.ppm'):
        sourcefile = target[:-2] + suffix
        if os.path.exists(sourcefile):
            return sourcefile
    return None

def remove_makefile_comment(line):
    """ Strips everything after the first # (Makefile comment) from a line."""
    return line.split("#", 1)[0].rstrip()

def get_multiline_from_file(infile):
    """ Reads a line from infile. If the line ends with a line continuation,
    it is substituted with a space and the next line is appended. Returns
    (True, line) if reading has succeeded, (False, "") otherwise. The boolean
    value is required to distinguish an error from empty lines in the input
    (which might also occur by stripping the comment from a line which only
    contains that comment)."""
    line = ""
    current = infile.readline()
    if not current:
        return (False, "")
    current = remove_makefile_comment(current)
    while current.endswith('\\'):
        current = current.replace('\\', ' ')
        line += current
        current = infile.readline()
        if not current:
            break
        current = remove_makefile_comment(current)
    line += current
    line.rstrip()
    return (True, line)

def get_config_string(item, model=None):
    """ Return a string with CONFIG_ for a given item. If the item is
    a tristate symbol in model, CONFIG_$(item)_MODULE is added as an
    alternative."""
    if item.startswith("CONFIG_"):
        item = item[7:]
    if model and model.get_type(item) == "tristate":
        return "(CONFIG_" + item + " || CONFIG_" + item + "_MODULE)"
    return "CONFIG_" + item
