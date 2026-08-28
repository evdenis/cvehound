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
    written = json.loads(report.read_text())
    assert written['args']['cve'] == ['CVE-2013-2930', 'CVE-2017-1000407']
    # Both rules are checkable here, so nothing should have failed -- and the key
    # is present either way, which is what lets a consumer tell an empty
    # 'results' apart from a scan that could not finish.
    assert written['errors'] == {}


def test_mode_values_from_config_are_validated(hound, tmp_path):
    """argparse only checks `choices` for a value it parsed off the command line.

    cvehound.ini overrides the default without reaching that check, so 'maybe'
    would read as "not off" and silently pick a transport nobody asked for.
    """
    config = tmp_path / 'cvehound.ini'
    config.write_text('zygote = maybe\n')
    result = subprocess.run(
        [
            sys.executable,
            '-m',
            'cvehound',
            '--kernel',
            hound.kernel,
            '--cve',
            'CVE-2013-2930',
            '--config',
            str(config),
        ],
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert result.returncode == 1, result.stdout
    assert 'Wrong --zygote value' in result.stderr


def test_report_records_the_transport(hound, tmp_path):
    """A report from a warm server and one from a process per rule are the same
    verdicts produced differently; which it was belongs next to the budgets."""
    report = tmp_path / 'report.json'
    result = subprocess.run(
        [
            sys.executable,
            '-m',
            'cvehound',
            '--kernel',
            hound.kernel,
            '--cve',
            'CVE-2013-2930',
            '--zygote',
            'off',
            '--report',
            str(report),
        ],
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert result.returncode == 0, result.stderr
    tools = json.loads(report.read_text())['tools']
    assert tools['spatch_zygote'] is False
    assert tools['spatch_ast_cache'] is False
