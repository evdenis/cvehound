"""Pool worker helpers for the CLI.

These live in their own importable module (not cvehound/__main__.py) because the
spawn/forkserver start methods pickle pool callables by qualified name: under
``python -m cvehound`` the CLI module is ``__main__``, a name worker processes
cannot resolve, so the helpers must be addressable as ``cvehound.worker.*``.
"""

import logging
from typing import Any

from cvehound import CVEhound
from cvehound.oracle import hound_at

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


def _worker_check_cve(cve: str, all_files: bool, tree: str | None = None) -> dict[str, Any] | bool:
    """check_cve() on the worker's hound, or on a copy pointed at `tree`.

    The git modes materialize one directory per revision and hand each task
    the one it is about; the copy is shallow (cvehound.oracle hound_at), so the
    rule and metadata caches stay the worker's.
    """
    assert _hound is not None
    hound = _hound if tree is None else hound_at(_hound, tree)
    return hound.check_cve(cve, all_files)


def setup_logging(loglevel: int) -> None:
    logging.basicConfig(level=loglevel, format='%(message)s')
    # basicConfig leaves an already-configured root alone, which under fork is
    # the parent's; the level asked for still has to take.
    logging.getLogger().setLevel(loglevel)
