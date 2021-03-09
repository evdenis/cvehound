""" Data structures useful for kbuildparse modules."""

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

class VariableStore(dict):
    """ Class managing variables for easy access across different
    subclasses."""

    def __init__(self):
        super(VariableStore, self).__init__()
        self.nxt = None

    def create_variable(self, name, variable):
        """ Create a variable with name referenced in @name."""
        self[name] = variable

    def get_variable(self, name):
        """ Get a variable of name @name from the store. Returns None,
        if no corresponding variable was found."""
        if name in self:
            return self[name]
        return None

    def increment_variable(self, name, amount=1):
        """ int has no reference semantics, so incrementing a number
        requires rewriting the entry in the dictionary."""
        self[name] += amount

    def decrement_variable(self, name, amount=1):
        """ see increment_variable """
        self[name] -= amount


class Precondition(list):
    """ Class representing a list of preconditions for a file."""

    def add_condition(self, condition, keep_duplicates=True):
        """ Add a condition to this Precondition."""
        if keep_duplicates or condition not in self:
            self.append(condition)

    def __hash__(self):
        """ Hashing is deferred to superclass."""
        return hash(super(Precondition, self))


class Alternatives(list):
    """ Class representing a list of alternative Preconditions."""

    def add_alternative(self, precondition):
        """ Add an alternative Precondition."""
        self.append(precondition)


class LineObject(object):
    """ Class representing a line with conditions."""

    def __init__(self, line):
        self.raw_line = line
        self.processed_line = line
        self.condition = []
        # Invalid means that this line is inside a if{n}{def,eq} block for which
        # we could not evaluate the correct condition.
        self.invalid = False
