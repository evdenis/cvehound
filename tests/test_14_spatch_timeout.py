#!/usr/bin/env python3

"""Pin the timeout classifier to what spatch actually prints.

parse_spatch_timeout() reads stderr because the exit code cannot answer the
question: handed a directory, spatch catches a fired --timeout per file, drops
that file's findings and still exits 0. That makes the marker text load-bearing,
and the marker text is not stable across builds -- the module prefix on the
exception depends on how coccinelle was compiled. The unit tests cover the
spellings seen so far; the live ones re-derive the marker from whichever spatch
is installed, so a coccinelle that renames it fails here instead of quietly
classifying every timeout as "nothing to see".
"""

import pickle
import subprocess

import pytest

import cvehound
from cvehound.exception import SpatchError, SpatchTimeout
from cvehound.oracle import hound_at
from cvehound.util import parse_spatch_timeout

# Captured verbatim from spatch 1.3.2 under --very-quiet. One shape per way
# cvehound can invoke it; see the comment above parse_spatch_timeout().
# Builds without OCaml's wrapped modules spell the exception without the prefix.
FILE_LIST_STDERR = (
    'timeout (we abort): /k/drivers/a.c /k/drivers/b.c\nFatal error: exception {}Common.Timeout\n'
)
DIRECTORY_STDERR = (
    'EXN: Coccinelle_modules.Common.Timeout in /k/drivers/a.c\n'
    'EXN: Coccinelle_modules.Common.Timeout in /k/drivers/b.c\n'
    'An error occurred when attempting to transform some files.\n'
)
PARMAP_STDERR = (
    '[Parmap]: error at index j=0 in (0,0), chunksize=1 of a total of 1 got '
    'exception Coccinelle_modules.Common.Timeout on core 0 \n\n'
    'Aborting computation due to exception(s) raised in the workers\n'
)


@pytest.mark.parametrize('prefix', ['Coccinelle_modules.', ''], ids=['wrapped', 'bare'])
def test_file_list_shape_names_every_file(prefix):
    stderr = FILE_LIST_STDERR.format(prefix)
    assert parse_spatch_timeout(stderr) == ['/k/drivers/a.c', '/k/drivers/b.c']


def test_directory_shape_names_the_files_it_gave_up_on():
    assert parse_spatch_timeout(DIRECTORY_STDERR) == ['/k/drivers/a.c', '/k/drivers/b.c']


def test_parmap_shape_is_a_timeout_with_no_file():
    # Empty means "timed out, files unknown" -- callers must not read it as None.
    assert parse_spatch_timeout(PARMAP_STDERR) == []


@pytest.mark.parametrize(
    'stderr',
    [
        '',
        'init_defs_builtins: /usr/share/coccinelle/standard.h\n',
        # A different fatal exception is a SpatchError, not a timeout.
        'Fatal error: exception Coccinelle_modules.Common.UnixExit(2)\n',
        'EXN: Failure("bad") in /k/a.c\n',
    ],
)
def test_benign_stderr_is_not_a_timeout(stderr):
    assert parse_spatch_timeout(stderr) is None


def test_timeout_survives_the_pool_boundary():
    # Raised inside a ProcessPoolExecutor worker, so the extra state has to
    # round-trip; the default reduce would replay __init__ with the message.
    err = SpatchTimeout('CVE-1', '/k', 2, FILE_LIST_STDERR, 60, ['/k/a.c'])
    back = pickle.loads(pickle.dumps(err))
    assert isinstance(back, SpatchError)
    assert (back.files, back.timeout, back.wall) == (['/k/a.c'], 60, False)
    assert str(back) == str(err)


def test_wall_and_engine_budgets_read_differently():
    engine = SpatchTimeout('CVE-1', '/k', 2, '', 60, ['/k/a.c'])
    wall = SpatchTimeout('CVE-1', '/k', -9, '', 3600, [], wall=True)
    assert '60 CPU-seconds on /k/a.c' in str(engine)
    assert '3600s of wall time' in str(wall)


# --- live: whatever spatch is installed still prints what we match on --------

CVE = 'CVE-0000-0000'
RULE = """\
/// Files: burn.c
virtual detect

@err depends on detect exists@
identifier f, t;
@@

  f(...)
  {
  ...
* free_thing(t);
  ...
  use(t);
  ...
  }
"""


@pytest.fixture(scope='module')
def slow_tree(tmp_path_factory):
    """A one-file tree whose matching costs far more than one CPU-second.

    --timeout takes whole seconds and 0 disables it, so 1 is the tightest budget
    there is; the file has to overrun it by enough that a much faster machine
    still trips. It costs ~9 CPU-seconds here, and the run aborts the moment the
    budget goes, so the test pays about a second either way.
    """
    root = tmp_path_factory.mktemp('slow-tree')
    body = '\n'.join(
        f'\tstruct thing *t{i} = lookup(n + {i});\n'
        f'\tif (t{i}) {{ use(t{i}); free_thing(t{i}); }}\n'
        f'\tfor (i = 0; i < {i} + 4; i++) {{ acc += probe(i, t{i}); }}'
        for i in range(400)
    )
    (root / 'burn.c').write_text(
        'struct thing { int v; };\n'
        + '\n'.join(
            f'static void burn_{k}(int n)\n{{\n\tint i, acc = 0;\n{body}\n\tsink(acc);\n}}\n'
            for k in range(8)
        )
    )
    rule = root / f'{CVE}.cocci'
    rule.write_text(RULE)
    return root


@pytest.fixture
def slow_hound(hound, slow_tree):
    """A CVEhound pointed at that tree, with the rule registered under CVE.

    hound_at only retargets .kernel; cve_all_rules and rules_metadata are shared
    with the session-wide instance, so both are replaced rather than mutated.
    """
    at = hound_at(hound, str(slow_tree))
    at.cve_all_rules = {**hound.cve_all_rules, CVE: str(slow_tree / f'{CVE}.cocci')}
    at.rules_metadata = {}
    return at


# The hinted-files shape depends on the build: stock spatch dies with the
# uncaught exception (exit 2); builds carrying the exit-124 patch (the zygote
# branch) report the coreutils-style timeout code instead.
@pytest.mark.parametrize(
    ('all_files', 'returncodes'),
    [(False, {2, 124}), (True, {0})],
    ids=['hinted-files', 'all-files'],
)
def test_check_cve_raises_spatch_timeout(slow_hound, monkeypatch, all_files, returncodes):
    """Both invocation shapes, through the code the CLI runs.

    This is also what pins the marker to whatever spatch is installed: err.files
    can only be right if parse_spatch_timeout matched what that build printed.
    The returncode is the reason the classifier reads stderr at all -- handed a
    directory spatch gives up on the file and still exits 0.
    """
    monkeypatch.setattr(cvehound, 'SPATCH_TIMEOUT', 1)
    with pytest.raises(SpatchTimeout) as excinfo:
        slow_hound.check_cve(CVE, all_files)
    err = excinfo.value
    assert err.files == ['burn.c']
    assert err.returncode in returncodes
    assert err.timeout == 1
    assert not err.wall


def test_wall_watchdog_reports_a_wall_timeout(slow_hound, monkeypatch):
    # The engine budget cannot see a process that is not burning CPU, which is
    # the whole reason for the outer one. It names no file: only spatch knows
    # where it got to, and it was killed before it could say.
    monkeypatch.setattr(cvehound, 'SPATCH_TIMEOUT', 0)
    monkeypatch.setattr(cvehound, 'SPATCH_WALL_TIMEOUT', 1)
    with pytest.raises(SpatchTimeout) as excinfo:
        slow_hound.check_cve(CVE)
    assert excinfo.value.wall
    assert excinfo.value.timeout == 1
    assert excinfo.value.files == []


def test_wall_watchdog_leaves_no_parmap_children(slow_hound, slow_tree, tmp_path, monkeypatch):
    """The reason the watchdog signals a process group and not a process.

    Under -j>1 spatch hands the work to parmap, which forks; killing the parent
    alone would orphan those children still burning cores. jobs=2 is what makes
    this test differ from the one above -- at jobs=1 there is nothing to orphan.

    chdir is belt and braces: check_cve() points --tmp-dir at a private
    mkdtemp it removes itself, so the scratch directory the SIGKILL strands
    lands nowhere near the repo root even without it.
    """
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cvehound, 'SPATCH_TIMEOUT', 0)
    monkeypatch.setattr(cvehound, 'SPATCH_WALL_TIMEOUT', 2)
    with pytest.raises(SpatchTimeout):
        slow_hound.check_cve(CVE, True, jobs=2)
    # pgrep matches the rule path, which is unique to this tree, so a surviving
    # child cannot be confused with another worker's spatch under xdist.
    survivors = subprocess.run(
        ['pgrep', '-fa', str(slow_tree / f'{CVE}.cocci')], capture_output=True, text=True
    )
    assert survivors.stdout == '', survivors.stdout
