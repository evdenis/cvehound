"""Run the real CLI through its ProcessPoolExecutor fan-out.

The pool callables are pickled by qualified name under the spawn/forkserver
start methods (forkserver is the Linux default since Python 3.14), which the
in-process tests never exercise. Regression test for the `python -m cvehound`
invocation, where helpers defined in cvehound/__main__.py would be pickled as
unresolvable `__main__.*` names. Detection hits are not asserted: they depend
on the kernel checkout state, and the guarded failure is a hard crash.
"""

import json
import subprocess
import sys

import pytest

# The CLI scans the shared tests/linux tree; share test_06's fallback group so
# shared-tree checkouts never run concurrently (a no-op in worktree mode).
pytestmark = pytest.mark.xdist_group('shared-tree')


def test_cli_module_invocation(hound, tmp_path):
    report = tmp_path / 'report.json'
    result = subprocess.run(
        [
            sys.executable,
            '-m',
            'cvehound',
            '--kernel',
            hound.kernel,
            '--cve',
            'CVE-2013-2930',  # .cocci rule
            'CVE-2017-1000407',  # .grep rule
            '--report',
            str(report),
        ],
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(report.read_text())['args']['cve'] == ['CVE-2013-2930', 'CVE-2017-1000407']
