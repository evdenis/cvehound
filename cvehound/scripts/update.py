#!/usr/bin/env python3
"""`cvehound update`: refresh the detection rules and CVE metadata.

Content sets are downloaded from the project's rolling `content-latest`
GitHub release (or any mirror directory/URL given with --from), verified
against their manifest, and installed into the user's content overlay --
never into the installed package.  See cvehound/content.py.
"""

import argparse
import sys

from cvehound.content import (
    DEFAULT_BASE,
    ContentError,
    check_content,
    get_content_home,
    install_content,
    repo_content_wins,
)


def main(args: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog='cvehound update',
        description='Update the detection rules and CVE metadata',
    )
    parser.add_argument(
        '--check',
        action='store_true',
        help='only report whether an update is available (exit 10 when one is)',
    )
    parser.add_argument(
        '--force', action='store_true', help='reinstall even when already up to date'
    )
    parser.add_argument(
        '--from',
        dest='source',
        default=DEFAULT_BASE,
        metavar='URL|DIR',
        help='content location: an URL prefix or a local directory holding '
        'manifest.json and the content tarball',
    )
    opts = parser.parse_args(args)

    try:
        if opts.check:
            installed, available = check_content(opts.source)
            print('installed:', installed or 'none (packaged content in use)')
            print('available:', available)
            return 0 if installed == available else 10

        content_id, updated = install_content(opts.source, force=opts.force)
        if updated:
            print('Updated content to', content_id, 'in', get_content_home())
            if repo_content_wins():
                print(
                    'Note: this is a git checkout, so the repository content '
                    'is used by default; set CVEHOUND_CONTENT to use the overlay.',
                    file=sys.stderr,
                )
        else:
            print('Already up to date:', content_id)
        return 0
    except ContentError as err:
        print(f'Error: {err}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
