"""Subcommand dispatch for the `cvehound` console script.

`cvehound scan` is the scanner; `diff` and `bisect` are the git modes; `update`
refreshes content and has its own parser in cvehound.scripts.update. A first
argument that is none of those is the historical invocation,
`cvehound --kernel DIR ...`, and still means `scan` -- so do `--list`,
`--version` and `--cache-clear`, which the scan parser owns.

Kept to a lookup so that `python -m cvehound` imports only the subcommand it
runs; the pool callables live in cvehound.worker (see there for why).
"""

import importlib
import sys

from cvehound.exception import GitError

SUBCOMMANDS = ('scan', 'diff', 'bisect')


def main(args: list[str] | None = None) -> None:
    if args is None:
        args = sys.argv[1:]
    if args and args[0] == 'update':
        from cvehound.scripts.update import main as update_main

        sys.exit(update_main(args[1:]))
    if args and args[0] in SUBCOMMANDS:
        command, rest, prog = args[0], args[1:], 'cvehound ' + args[0]
    else:
        command, rest, prog = 'scan', args, 'cvehound'
    module = importlib.import_module('cvehound.cli.' + command)
    try:
        sys.exit(module.main(rest, prog=prog))
    except GitError as err:
        # The one boundary for git failing: every GitError carries the message
        # the user needs, whichever call raised it.
        print(err, file=sys.stderr)
        sys.exit(1)
