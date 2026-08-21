"""Pool worker helpers for the CLI.

These live in their own importable module (not cvehound/__main__.py) because the
spawn/forkserver start methods pickle pool callables by qualified name: under
``python -m cvehound`` the CLI module is ``__main__``, a name worker processes
cannot resolve, so the helpers must be addressable as ``cvehound.worker.*``.
"""

import logging
from typing import Any

from cvehound import CVEhound

# The hound instance each worker process operates on: sent once per worker
# via the pool initializer instead of being pickled into every task (the
# Kbuild config map alone is several MB).
_hound: CVEhound | None = None


def _worker_init(hound: CVEhound, loglevel: int) -> None:
    global _hound
    _hound = hound
    # Workers do the user-facing logging; under the spawn/forkserver start
    # methods (the default on some platforms) the parent's logging setup is
    # not inherited. basicConfig is a no-op when it was (fork).
    setup_logging(loglevel)


def _worker_check_cve(cve: str, all_files: bool) -> dict[str, Any] | bool:
    assert _hound is not None
    return _hound.check_cve(cve, all_files)


def setup_logging(loglevel: int) -> None:
    logging.basicConfig(level=loglevel, format='%(message)s')
