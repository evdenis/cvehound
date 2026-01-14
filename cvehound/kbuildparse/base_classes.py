"""Base classes for parser functionality extensions."""

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

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from cvehound.kbuildparse.data_structures import Precondition


class InitClass:
    """Base class for initializer objects for the parser."""

    def __init__(self, model: str, arch: str) -> None:
        """Constructor for InitClass, takes model and arch parameters."""
        self.model = model
        self.arch = arch

    def get_file_for_subdirectory(self, directory: str) -> str | None:
        """This method must implement the selection and precedence rules
        for files in a given subdirectory."""
        raise NotImplementedError('get_file_for_subdirectory not implemented!')

    def process(self, parser: Any, args: Any, dirs_to_process: list[str]) -> None:
        """Initialize data structures that are needed across runs, such as
        the directories which will be processed or any global variables."""
        pass


class BeforePass:
    """Base class for functionality run inside a Makefile but before
    any lines are read from the file."""

    def __init__(self, model: str, arch: str) -> None:
        """Constructor for BeforePass, takes model and arch parameters."""
        self.model = model
        self.arch = arch

    def process(self, parser: Any, basepath: str) -> None:
        """This function is executed before the main processing loop to
        initialize local variables or other helper structures."""
        pass


class DuringPass:
    """Base class for functionality exerted on every line in the Makefile."""

    def __init__(self, model: str, arch: str) -> None:
        """Constructor for DuringPass, takes model and arch parameters."""
        self.model = model
        self.arch = arch

    def process(self, parser: Any, line: str, basepath: str) -> bool | None:
        """Processing function. Returns true to signal successful handling
        so other DuringPass classes will not consider this line."""
        pass


class AfterPass:
    """Base class for functionality after a file has been parsed."""

    def __init__(self, model: str, arch: str) -> None:
        """Constructor for AfterPass, takes model and arch parameters."""
        self.model = model
        self.arch = arch

    def process(self, parser: Any, path: str, condition_for_current_dir: 'Precondition') -> None:
        """This is called after the main processing loop has finished.
        Here, descending into subdirectories or expanding macros can be
        achieved."""
        pass


class BeforeExit:
    """Base class for functionality being called right before the end of the
    parser process."""

    def __init__(self, model: str, arch: str) -> None:
        """Constructor for BeforeExit"""
        self.model = model
        self.arch = arch

    def process(self, parser: Any) -> None:
        """This is called after all base directories have been crawled and
        the parser is about to exit."""
        pass
