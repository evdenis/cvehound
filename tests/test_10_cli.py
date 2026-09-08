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


CVE_REV = 'CVE-2014-0100'


def _cli(*args, timeout=600):
    return subprocess.run(
        [sys.executable, '-m', 'cvehound', *args],
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _scan(*args):
    return _cli('scan', *args)


def _diff(*args):
    return _cli('diff', *args)


def _bisect(*args):
    return _cli('bisect', *args)


def test_scan_rev_reads_the_revision_not_the_checkout(hound, repo, tmp_path):
    """--rev answers for the commit named, whatever the working tree is at."""
    fix = hound.get_rule_fix(CVE_REV)
    report = tmp_path / 'report.json'
    result = _scan(
        '--kernel', hound.kernel, '--rev', fix + '~', '--cve', CVE_REV, '--report', report
    )
    assert result.returncode == 0, result.stderr
    assert 'Found: ' + CVE_REV in result.stderr
    written = json.loads(report.read_text())
    assert list(written['results']) == [CVE_REV]
    assert written['errors'] == {}
    assert written['args']['rev'] == [fix + '~']
    assert written['args']['kernel'] == hound.kernel
    assert written['kernel']['rev'] == fix + '~'
    assert written['kernel']['commit'] == repo.git.rev_parse(fix + '~')
    assert written['kernel']['full'], 'the Makefile of the revision, not of the checkout'

    result = _scan('--kernel', hound.kernel, '--rev', fix, '--cve', CVE_REV, '--report', report)
    assert result.returncode == 0, result.stderr
    written = json.loads(report.read_text())
    assert written['results'] == {}
    assert written['errors'] == {}


def test_scan_several_revs_report_side_by_side(hound, tmp_path):
    fix = hound.get_rule_fix(CVE_REV)
    report = tmp_path / 'report.json'
    result = _scan(
        '--kernel', hound.kernel, '--rev', fix + '~', fix, '--cve', CVE_REV, '--report', report
    )
    assert result.returncode == 0, result.stderr
    written = json.loads(report.read_text())
    assert 'results' not in written and 'kernel' not in written
    assert set(written['revs']) == {fix + '~', fix}
    assert list(written['revs'][fix + '~']['results']) == [CVE_REV]
    assert written['revs'][fix]['results'] == {}
    assert written['revs'][fix]['kernel']['commit'] == fix


def test_scan_rev_refuses_what_it_cannot_do(hound, tmp_path):
    result = _scan('--kernel', hound.kernel, '--rev', 'HEAD', '--all-files', '--cve', CVE_REV)
    assert result.returncode == 1
    assert '--all-files needs a full tree' in result.stderr

    result = _scan('--kernel', hound.kernel, '--rev', 'no-such-rev-0000', '--cve', CVE_REV)
    assert result.returncode == 1
    assert 'unknown revision' in result.stderr

    result = _scan('--kernel', str(tmp_path), '--rev', 'HEAD', '--cve', CVE_REV)
    assert result.returncode == 1
    assert 'not a git repository' in result.stderr


def test_plain_scan_of_a_checkout_records_head(hound, repo, tmp_path):
    report = tmp_path / 'report.json'
    result = _scan('--kernel', hound.kernel, '--cve', CVE_REV, '--report', report)
    assert result.returncode == 0, result.stderr
    written = json.loads(report.read_text())
    assert written['kernel']['commit'] == repo.head.commit.hexsha
    assert written['kernel']['dirty'] is False
    assert 'rev' not in written['kernel']


def test_diff_classifies_the_fix_commit_as_fixed(hound, tmp_path):
    fix = hound.get_rule_fix(CVE_REV)
    report = tmp_path / 'report.json'
    result = _diff(
        '--kernel', hound.kernel, fix + '~..' + fix, '--cve', CVE_REV,
        '--report', report, '--fail-on', 'introduced',
    )  # fmt: skip
    assert result.returncode == 0, result.stderr
    assert f'{CVE_REV}: fixed (detected at {fix}~, not at {fix})' in result.stdout
    written = json.loads(report.read_text())
    entry = written['results'][CVE_REV]
    assert entry['status'] == 'fixed'
    assert entry['from'] and entry['to'] is False
    assert entry['files_present'] == {'from': True, 'to': True}
    assert written['args']['cve'] == [CVE_REV]
    assert written['range']['from']['commit'] != written['range']['to']['commit']
    assert written['range']['to']['commit'] == fix
    assert hound.get_rule_files(CVE_REV)[0] in written['range']['changed_files']
    # The fix commit itself is the CVE's known fix: history says so without a rule.
    assert written['evidence']['fixes'].get(CVE_REV) == [fix]
    assert written['errors'] == {}


def test_diff_fail_on_introduced_exits_three(hound):
    fix = hound.get_rule_fix(CVE_REV)
    result = _diff(
        '--kernel',
        hound.kernel,
        fix + '..' + fix + '~',
        '--cve',
        CVE_REV,
        '--fail-on',
        'introduced',
    )
    assert result.returncode == 3, result.stderr
    assert f'{CVE_REV}: introduced' in result.stdout


def test_diff_per_commit_names_the_fix(hound, tmp_path):
    fix = hound.get_rule_fix(CVE_REV)
    report = tmp_path / 'report.json'
    result = _diff(
        '--kernel', hound.kernel, fix + '~3..' + fix, '--cve', CVE_REV, '--per-commit',
        '--report', report,
    )  # fmt: skip
    assert result.returncode == 0, result.stderr
    written = json.loads(report.read_text())
    assert written['results'][CVE_REV]['commit'] == fix
    assert written['results'][CVE_REV]['commit_subject'].startswith(fix[:7])


def test_diff_patch_applies_on_a_private_index(hound, repo, tmp_path):
    fix = hound.get_rule_fix(CVE_REV)
    patch = tmp_path / 'fix.patch'
    patch.write_text(repo.git.format_patch('-1', '--stdout', fix))
    report = tmp_path / 'report.json'
    head_before = repo.head.commit.hexsha
    result = _diff(
        '--kernel', hound.kernel, '--patch', str(patch), '--base', fix + '~', '--cve', CVE_REV,
        '--report', report,
    )  # fmt: skip
    assert result.returncode == 0, result.stderr
    written = json.loads(report.read_text())
    assert written['results'][CVE_REV]['status'] == 'fixed'
    # A patch produces a tree, and no commit exists to point a reader at.
    assert written['range']['to']['tree'] == repo.git.rev_parse(fix + '^{tree}')
    assert 'commit' not in written['range']['to']
    assert written['range']['to']['rev'] == fix + '~ + fix.patch'
    # Its message speaks for the CVE, but the patch has no sha to cite it by.
    assert written['evidence']['candidates'][CVE_REV] == ['<patch>']
    assert written['args']['patch'] == str(patch)
    assert repo.head.commit.hexsha == head_before
    assert not repo.is_dirty()


def test_diff_rejects_ambiguous_invocations(hound, tmp_path):
    result = _diff('--kernel', hound.kernel, 'HEAD~1..HEAD', '--patch', '/dev/null')
    assert result.returncode == 1 and 'either a commit range' in result.stderr
    result = _diff('--kernel', hound.kernel, 'HEAD~1...HEAD')
    assert result.returncode == 1 and 'two dots' in result.stderr
    result = _diff('--kernel', hound.kernel, '--patch', '/dev/null', '--per-commit')
    assert result.returncode == 1 and '--per-commit' in result.stderr
    result = _diff('--kernel', str(tmp_path), 'HEAD~1..HEAD')
    assert result.returncode == 1 and 'not a git repository' in result.stderr


def test_scan_rev_annotates_findings_with_git_evidence(hound, tmp_path):
    """At the fix's parent the fix is known and not yet applied: fix-absent."""
    fix = hound.get_rule_fix(CVE_REV)
    report = tmp_path / 'report.json'
    result = _scan(
        '--kernel', hound.kernel, '--rev', fix + '~', '--cve', CVE_REV, '--report', report
    )
    assert result.returncode == 0, result.stderr
    assert f'git evidence ({fix}~):' in result.stderr
    assert f'  {CVE_REV}: fix-absent' in result.stderr
    written = json.loads(report.read_text())
    assert written['results'][CVE_REV]['git'] == {
        'fix': fix,
        'fix_in_history': False,
        'backports': [],
        'reverted_by': None,
        'verdict': 'fix-absent',
    }


def test_scan_prune_unintroduced_records_what_it_skipped(hound, repo, tmp_path):
    """Scanned at a commit before the rule's introducing commit, the rule is
    provably not applicable and is skipped -- and the report says so."""
    fixes = hound.get_rule_fixes(CVE_REV)
    report = tmp_path / 'report.json'
    result = _scan(
        '--kernel', hound.kernel, '--rev', fixes + '~', '--cve', CVE_REV,
        '--prune-unintroduced', '--report', report,
    )  # fmt: skip
    assert result.returncode == 0, result.stderr
    written = json.loads(report.read_text())
    assert written['results'] == {}
    assert list(written['skipped']) == [CVE_REV]
    assert fixes[:12] in written['skipped'][CVE_REV]


def test_bisect_names_the_fix_commit(hound, tmp_path):
    fix = hound.get_rule_fix(CVE_REV)
    report = tmp_path / 'report.json'
    result = _bisect(
        '--kernel', hound.kernel, '--cve', CVE_REV, fix + '~3..' + fix, '--report', report
    )
    assert result.returncode == 0, result.stderr
    assert f'{CVE_REV}: detected at {fix}~3, clean at {fix}' in result.stdout
    assert f'verdict flips at {fix[:12]}' in result.stdout
    assert '(detected -> clean)' in result.stdout
    written = json.loads(report.read_text())
    assert written['flip']['commit'] == fix
    assert written['flip']['direction'] == 'detected -> clean'
    assert written['flip']['blind'] is False
    assert written['runs'] >= 2
    # What the header says it is bisecting: distinct contents, not the collapsed
    # steps, which count a recurring content once per run of it.
    assert written['contents'] <= written['steps']
    assert f'({written["contents"]} distinct contents)' in result.stdout
    assert written['errors'] == {}


def test_bisect_reports_no_change_when_the_ends_agree(hound):
    fix = hound.get_rule_fix(CVE_REV)
    result = _bisect('--kernel', hound.kernel, '--cve', CVE_REV, fix + '..' + fix + '~0')
    assert result.returncode == 0, result.stderr
    assert 'no change between' in result.stdout


def test_bisect_takes_exactly_one_cve(hound):
    result = _bisect('--kernel', hound.kernel, 'HEAD~1..HEAD')
    assert result.returncode == 2 and '--cve' in result.stderr
    result = _bisect('--kernel', hound.kernel, '--cve', 'assigned', 'HEAD~1..HEAD')
    assert result.returncode == 1 and 'exactly one --cve' in result.stderr


def test_diff_accepts_the_range_after_repeatable_cve_options(hound):
    """diff's --cve is repeatable rather than greedy, so the range can follow it."""
    fix = hound.get_rule_fix(CVE_REV)
    result = _diff(
        '--kernel', hound.kernel, '--cve', CVE_REV, '--cve', 'CVE-2013-2930',
        '--exclude', 'CVE-2013-2930', fix + '~..' + fix,
    )  # fmt: skip
    assert result.returncode == 0, result.stderr
    assert f'{CVE_REV}: fixed' in result.stdout
    assert 'CVE-2013-2930' not in result.stdout
