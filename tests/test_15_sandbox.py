#!/usr/bin/env python3

"""Pin the sandbox to the two things that can go wrong with it.

It can fail to confine -- a rights mask that quietly drops the bit it meant to
set, a filter whose jump lands past its own program -- and it can confine too
much, which is the worse half: denied a path it needs, spatch prints "0 files
match" and exits 0, so an over-tight policy reads as a clean kernel rather than
an error. The unit tests below cover the assembly, and the live ones prove both
directions on the running kernel: things that must be denied are, and a rule
that fires unsandboxed still fires sandboxed.

Everything that installs a sandbox runs in a child process. landlock_restrict_self
cannot be undone, so a test that applied one in-process would confine the rest of
the session -- pytest's own writes included.
"""

import ctypes
import json
import os
import pickle
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap

import pytest
from conftest import write_tree

import cvehound.sandbox as sandbox
from cvehound.exception import SandboxError
from cvehound.sandbox import (
    _DENY,
    _NR_SOCKET,
    FS,
    SandboxPolicy,
    _PathBeneathAttr,
    _rights_for,
    _ruleset_attr,
    build_policy,
    build_seccomp_program,
    fs_mask,
    landlock_abi,
    self_test,
)

ARCHES = tuple(sandbox._DENY)


# --- units: the bits and the program --------------------------------------


@pytest.mark.parametrize(
    ('abi', 'highest'),
    [(1, 'MAKE_SYM'), (2, 'REFER'), (3, 'TRUNCATE'), (4, 'TRUNCATE'), (5, 'IOCTL_DEV')],
    ids=lambda v: str(v),
)
def test_fs_mask_stops_at_the_abi(abi, highest):
    """Each ABI gets every right up to its own, and none above it."""
    mask = fs_mask(abi)
    assert mask & FS[highest]
    above = {name: bit for name, bit in FS.items() if bit > FS[highest]}
    assert not [name for name, bit in above.items() if mask & bit]


def test_fs_mask_does_not_guess_past_the_table():
    """A kernel newer than the table gets what we understand, not what we hope.

    Landlock fails the whole ruleset for one unknown bit, so an ABI we have never
    seen has to be treated as the newest we have, never as "probably has more".
    """
    assert fs_mask(99) == fs_mask(5)


@pytest.mark.parametrize(('abi', 'size'), [(1, 8), (3, 8), (4, 16), (5, 16), (6, 24), (9, 24)])
def test_ruleset_attr_is_sized_for_the_abi(abi, size):
    attr, got = _ruleset_attr(abi)
    assert got == size
    # Net and scope fields must stay zero when they are not being sent, or the
    # kernel reads a non-zero tail it does not know about.
    assert (attr.handled_access_net == 0) == (size < 16)
    assert (attr.scoped == 0) == (size < 24)


def test_path_beneath_attr_is_packed():
    """landlock_add_rule takes no size, so 12 bytes is the only layout it reads."""
    assert ctypes.sizeof(_PathBeneathAttr) == 12


def test_directory_only_rights_are_dropped_for_a_file(tmp_path):
    """Landlock answers EINVAL for MAKE_DIR on /dev/null rather than ignoring it."""
    a_file = tmp_path / 'f'
    a_file.write_text('')
    mask = fs_mask(5)

    on_dir = _rights_for(str(tmp_path), mask)
    on_file = _rights_for(str(a_file), mask)

    assert on_dir & FS['MAKE_DIR']
    assert not on_file & FS['MAKE_DIR']
    assert on_file & FS['WRITE_FILE']
    assert on_file & FS['READ_FILE']


def test_rights_are_clamped_by_the_abi_mask():
    """An old ABI must not be handed a right that only a newer one defines.

    Landlock fails the whole ruleset for one unknown bit, so the clamp the
    installer applies before asking for a path is what keeps ABI 1 usable.
    """
    assert not _rights_for('/', fs_mask(5) & fs_mask(1)) & FS['IOCTL_DEV']


@pytest.mark.parametrize('arch', ARCHES)
def test_seccomp_jumps_are_forward_and_addressable(arch):
    """Classic BPF has no backward branch and one byte per offset.

    Both limits are silent when broken: an offset that overflows a byte wraps, and
    the filter then allows whatever it lands on.
    """
    prog = build_seccomp_program(arch)
    jumps = 0
    for i, (code, jt, jf, _k) in enumerate(prog):
        if code & 0x07 != 0x05:  # BPF_JMP; jt/jf are unread on every other class
            continue
        jumps += 1
        assert 0 <= jt <= 255 and 0 <= jf <= 255
        assert i + 1 + jt < len(prog)
        assert i + 1 + jf < len(prog)
    assert jumps > len(prog) // 2, 'the deny comparisons went missing'


@pytest.mark.parametrize('arch', ARCHES)
def test_seccomp_checks_the_architecture_before_anything_else(arch):
    """Without this first, the compat ABI renumbers every syscall past the filter."""
    prog = build_seccomp_program(arch)
    load_arch, check_arch = prog[0], prog[1]
    assert load_arch[3] == 4  # offsetof(struct seccomp_data, arch)
    # The mismatch branch has to be the fatal one, not an errno.
    kill = prog[1 + 1 + check_arch[2]]
    assert kill[3] == 0x80000000  # SECCOMP_RET_KILL_PROCESS


@pytest.mark.parametrize('arch', ARCHES)
def test_seccomp_denies_the_families_landlock_cannot(arch):
    """The point of the filter: what Landlock has no way to express."""
    compared = {k for _code, _jt, _jf, k in build_seccomp_program(arch)}
    for name in ('ptrace', 'bpf', 'io_uring_setup', 'unshare', 'userfaultfd', 'keyctl'):
        assert _DENY[arch][name] in compared, name
    # socket() is filtered on its family rather than denied: the worker pool needs
    # AF_UNIX, and nothing in a scan needs any other family.
    assert _NR_SOCKET[arch] in compared
    assert 1 in compared  # AF_UNIX


def test_sandbox_error_survives_a_pickle_round_trip():
    """Exceptions in this package cross the pool boundary; this one may follow."""
    err = pickle.loads(pickle.dumps(SandboxError(['no landlock', 'no seccomp'])))
    assert err.reasons == ['no landlock', 'no seccomp']
    assert 'no landlock' in str(err)


def test_build_policy_drops_paths_that_do_not_exist(tmp_path):
    policy = build_policy(
        str(tmp_path), str(tmp_path), sys.executable, metadata=str(tmp_path / 'absent.gz')
    )
    assert str(tmp_path) in policy.read
    granted = policy.read + policy.read_exec + policy.write
    assert not [p for p in granted if not os.path.exists(p)]


def test_build_policy_covers_what_a_scan_reaches_for():
    """The paths whose absence would abort a real scan, each for a traced reason."""
    policy = build_policy('/etc', '/etc', sys.executable)
    # The interpreter, wherever it lives -- uv, pyenv and conda all put it outside
    # the venv, and the worker pool re-execs it under forkserver.
    assert os.path.realpath(sys.base_prefix) in policy.read_exec
    # coccinelle hardcodes /tmp/cocci_small_output-*; multiprocessing.SemLock is a
    # POSIX named semaphore under /dev/shm.
    assert '/tmp' in policy.write
    assert '/dev/shm' in policy.write
    assert '/dev/null' in policy.write


def test_self_test_reports_a_path_it_cannot_reach(tmp_path):
    """The guard against the silent half: an unreadable tree must raise, not scan."""
    missing = str(tmp_path / 'nope')
    with pytest.raises(SandboxError) as excinfo:
        self_test(SandboxPolicy(), missing, str(tmp_path), sys.executable)
    assert missing in str(excinfo.value)


def test_self_test_passes_when_the_policy_grants_what_it_covers(tmp_path):
    (tmp_path / 'a').write_text('')
    policy = SandboxPolicy(read=(str(tmp_path),), write=(str(tmp_path),))
    self_test(policy, str(tmp_path), str(tmp_path), sys.executable)


def test_self_test_catches_a_tree_the_policy_never_granted(tmp_path):
    """The other way to be one path too tight, and it reads identically.

    build_policy() drops a path that does not exist rather than failing, so a
    mistyped --kernel yields a policy granting nothing there -- and a tree the
    scan cannot read is a tree the scan calls clean.
    """
    gone = str(tmp_path / 'gone')
    policy = build_policy(gone, str(tmp_path), sys.executable)
    assert gone not in policy.read
    with pytest.raises(SandboxError, match='never granted'):
        self_test(policy, gone, str(tmp_path), sys.executable)


# --- live: what the running kernel actually enforces -----------------------

landlock = pytest.mark.skipif(landlock_abi() < 1, reason='kernel has no Landlock')


def _child(code, *argv):
    """Run a probe in its own interpreter and hand back what it printed.

    A sandbox cannot be taken back off, so every one of these has to be its own
    process; each child reports through a single JSON object on stdout.
    """
    run = subprocess.run(
        [sys.executable, '-c', textwrap.dedent(code), *argv],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert run.returncode == 0, run.stderr
    return json.loads(run.stdout)


# EACCES/EPERM/EAFNOSUPPORT are the sandbox saying no. Anything else -- most of
# all ECONNREFUSED from a port nobody listens on -- is the probe answering its own
# question, so the assertions below check the errno rather than "it raised".
DENIALS = (13, 1, 97)

PROBES = """
    import json, os, socket, sys
    from cvehound.sandbox import SandboxPolicy, apply

    status = apply(SandboxPolicy(
        read=('/etc',), read_exec=('/usr', '/lib', '/lib64'), write=('/tmp',),
    ))
    out = {'abi': status.landlock_abi, 'seccomp': status.seccomp, 'errno': {}}

    def probe(name, fn):
        try:
            got = fn()
        except OSError as err:
            out['errno'][name] = err.errno
            return
        out['errno'][name] = 0
        if hasattr(got, 'close'):
            got.close()

    home = os.path.expanduser('~/.cvehound-sandbox-probe')
    probe('home_write', lambda: open(home, 'w'))
    if not out['errno']['home_write']:
        os.unlink(home)
    # The home directory, not /etc/shadow: the real policy grants /etc read, so a
    # denial there would be file mode 0600 answering, not Landlock.
    probe('home_read', lambda: os.listdir(os.path.expanduser('~')))
    probe('tcp_connect', lambda: socket.create_connection(('127.0.0.1', 9), 1))
    probe('udp_socket', lambda: socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
    probe('netlink_socket', lambda: socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0))
    probe('unix_socket', lambda: socket.socket(socket.AF_UNIX, socket.SOCK_STREAM))
    probe('tmp_write', lambda: open('/tmp/.cvehound-sandbox-probe', 'w'))
    if not out['errno']['tmp_write']:
        os.unlink('/tmp/.cvehound-sandbox-probe')
    print(json.dumps(out))
"""


@landlock
def test_the_sandbox_denies_what_it_advertises():
    out = _child(PROBES)
    errno = out['errno']

    assert out['abi'] >= 1
    assert errno['home_write'] in DENIALS, 'the home directory is still writable'
    assert errno['home_read'] in DENIALS, 'the home directory is still readable'
    if out['abi'] >= 4 or out['seccomp']:
        assert errno['tcp_connect'] in DENIALS, f'TCP is still reachable ({errno["tcp_connect"]})'
    if out['seccomp']:
        # Landlock governs TCP only, which is exactly why the filter is there.
        assert errno['udp_socket'] in DENIALS, 'UDP is still reachable'
        assert errno['netlink_socket'] in DENIALS, 'netlink is still reachable'

    # The other half: the pool needs AF_UNIX, and spatch needs to write /tmp.
    assert not errno['unix_socket'], 'AF_UNIX was denied; the worker pool needs it'
    assert not errno['tmp_write'], '/tmp was denied; coccinelle hardcodes paths there'


@landlock
def test_install_self_tests_the_policy_it_just_locked(hound):
    """install() must come back clean on the tree a scan is about to read."""
    out = _child(INSTALL, hound.kernel, hound.spatch)
    assert out['abi'] >= 1
    assert not out['degraded'], out['degraded']


# The one rule this file names. The equivalence check needs a rule that actually
# fires, and firing needs source the rule matches -- so the tree below is built
# from this rule's own starred lines. If the rule ever goes away the test skips
# rather than passing on a tree nothing looks at.
FIRES_CVE = 'CVE-2013-2930'
VULNERABLE = (
    'static int perf_trace_event_perm(struct ftrace_event_call *tp_event,\n'
    '\t\t\t\t struct perf_event *p_event)\n'
    '{\n'
    '\tif (ftrace_event_is_function(tp_event) &&\n'
    '\t    perf_paranoid_kernel() &&\n'
    '\t    !capable(CAP_SYS_ADMIN))\n'
    '\t\treturn -EPERM;\n'
    '\n'
    '\treturn 0;\n'
    '}\n'
)


@pytest.fixture(scope='module')
def vulnerable_tree(tmp_path_factory):
    """A tree small enough to scan twice, real enough for the CLI to accept."""
    root = tmp_path_factory.mktemp('vulnerable-tree')
    write_tree(
        root,
        {
            'Makefile': 'VERSION = 5\nPATCHLEVEL = 10\nSUBLEVEL = 0\nEXTRAVERSION =\n',
            'kernel/trace/trace_event_perf.c': VULNERABLE,
        },
    )
    return root


@pytest.mark.slow
@landlock
def test_a_rule_that_fires_unsandboxed_still_fires_sandboxed(hound, vulnerable_tree, tmp_path):
    """The regression this whole module is scaffolding for.

    A policy one path too tight costs detections without costing an exit code, so
    comparing verdicts across the two modes is the only check that would notice.
    """
    if FIRES_CVE not in hound.cve_all_rules:
        pytest.skip(f'{FIRES_CVE} is no longer a rule in this tree')

    verdicts = {}
    for mode in ('off', 'strict'):
        report = tmp_path / f'{mode}.json'
        run = subprocess.run(
            [
                sys.executable,
                '-m',
                'cvehound',
                '--kernel',
                str(vulnerable_tree),
                '--cve',
                FIRES_CVE,
                '--report',
                str(report),
                f'--sandbox={mode}',
            ],
            capture_output=True,
            text=True,
            timeout=600,
            check=False,
        )
        assert run.returncode == 0, f'--sandbox={mode} failed: {run.stderr}'
        loaded = json.loads(report.read_text())
        verdicts[mode] = (sorted(loaded['results']), loaded['errors'])

    assert verdicts['off'][0] == [FIRES_CVE], 'the fixture stopped being vulnerable'
    assert verdicts['strict'] == verdicts['off']


DEGRADE = """
    import json, sys
    import cvehound.sandbox as sandbox
    from cvehound.exception import SandboxError

    # Stand in for a kernel built without Landlock, or one that left it out of
    # the boot-time lsm= list. Both report the same way.
    sandbox.landlock_abi = lambda: 0

    status = sandbox.apply(sandbox.SandboxPolicy(read=('/etc',)))
    strict = None
    try:
        sandbox.install('/etc', '/etc', sys.argv[1], strict=True)
    except SandboxError as err:
        strict = str(err)
    print(json.dumps({
        'abi': status.landlock_abi,
        'degraded': list(status.degraded),
        'summary': status.summary(),
        'strict': strict,
    }))
"""


INSTALL = """
    import json, sys
    from cvehound.content import resolve_content
    from cvehound.sandbox import install

    status = install(sys.argv[1], resolve_content().rules_dir, sys.argv[2])
    print(json.dumps({'abi': status.landlock_abi, 'degraded': list(status.degraded)}))
"""


def test_a_kernel_without_landlock_degrades_but_strict_refuses(hound):
    """The default is on-with-fallback, so the fallback is load-bearing.

    auto has to come back with a scan still possible and a reason worth printing;
    strict has to refuse rather than scan unconfined. Neither can be checked in
    process -- apply() installs a seccomp filter that outlives the assertion.
    """
    out = _child(DEGRADE, hound.spatch)

    assert out['abi'] == 0
    assert any('landlock' in reason for reason in out['degraded'])
    assert 'landlock' in out['summary']
    assert out['strict'] is not None, 'strict scanned anyway'
    assert 'landlock' in out['strict']


def test_the_working_directory_is_not_swept_in_from_sys_path(monkeypatch, tmp_path):
    """`python -m cvehound` puts '.' on sys.path, and $HOME is a common cwd.

    Granting sys.path wholesale would hand read and execute over whatever directory
    the tool was run from -- which is most of what the sandbox is for. The package's
    own parent is granted on its own line, so nothing an import needs rides on this.
    """
    monkeypatch.chdir(tmp_path)
    monkeypatch.syspath_prepend('.')
    home = os.path.abspath(os.path.expanduser('~'))
    monkeypatch.syspath_prepend(home)

    policy = build_policy(str(tmp_path), str(tmp_path), sys.executable)

    assert str(tmp_path) not in policy.read_exec, 'the working directory was granted'
    assert home not in policy.read_exec, '$HOME was granted'
    # ...while cvehound itself stays importable, which is what a forkserver worker
    # re-does after the lock.
    package_parent = os.path.dirname(os.path.dirname(os.path.abspath(sandbox.__file__)))
    assert package_parent in policy.read_exec


# --- the raw numbers, checked against the kernel's own headers -------------
#
# Every constant in cvehound/sandbox.py is a value from a uapi header that
# cannot be imported from Python. Typing them out is unavoidable; leaving them
# unchecked is not. These tests ask the C preprocessor what the headers on this
# machine actually say, so a transcription error fails here instead of silently
# confining the wrong thing -- or, worse, failing open.

PROBE_TEMPLATE = """\
#include <stdio.h>
#include <linux/landlock.h>
#include <linux/seccomp.h>
#include <linux/audit.h>
#include <linux/prctl.h>
#include <linux/bpf_common.h>
#include <asm/unistd_64.h>
int main(void) {{
{body}
    return 0;
}}
"""


def _ask_the_headers(wanted):
    """{{key: C expression}} -> {{key: value}}, as this machine's headers define it.

    Each line is #ifdef-guarded on its own macro, so a header too old to know a
    constant simply omits it rather than failing the build -- an ABI we cannot
    check here is not the same as one we got wrong.
    """
    if not shutil.which('cc'):
        pytest.skip('no C compiler to read the kernel headers with')
    body = '\n'.join(
        f'#ifdef {guard}\n    printf("{key} %llu\\n", (unsigned long long)({expr}));\n#endif'
        for key, (expr, guard) in wanted.items()
    )
    with tempfile.TemporaryDirectory() as tmp:
        src = os.path.join(tmp, 'probe.c')
        exe = os.path.join(tmp, 'probe')
        with open(src, 'w') as fh:
            fh.write(PROBE_TEMPLATE.format(body=body))
        built = subprocess.run(['cc', src, '-o', exe], capture_output=True, text=True, check=False)
        if built.returncode != 0:
            pytest.skip(f'kernel uapi headers unavailable: {built.stderr.strip()[:200]}')
        run = subprocess.run([exe], capture_output=True, text=True, check=True)
    out = {}
    for line in run.stdout.split('\n'):
        if line:
            name, value = line.split()
            out[name] = int(value)
    return out


def test_landlock_constants_match_the_kernel_headers():
    wanted = {f'FS_{n}': (f'LANDLOCK_ACCESS_FS_{n}', f'LANDLOCK_ACCESS_FS_{n}') for n in FS}
    wanted.update(
        {
            'NET_BIND': ('LANDLOCK_ACCESS_NET_BIND_TCP', 'LANDLOCK_ACCESS_NET_BIND_TCP'),
            'NET_CONNECT': ('LANDLOCK_ACCESS_NET_CONNECT_TCP', 'LANDLOCK_ACCESS_NET_CONNECT_TCP'),
            'SCOPE_UNIX': (
                'LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET',
                'LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET',
            ),
            'SCOPE_SIGNAL': ('LANDLOCK_SCOPE_SIGNAL', 'LANDLOCK_SCOPE_SIGNAL'),
            'VERSION': ('LANDLOCK_CREATE_RULESET_VERSION', 'LANDLOCK_CREATE_RULESET_VERSION'),
            'PATH_BENEATH': ('LANDLOCK_RULE_PATH_BENEATH', 'LANDLOCK_RULE_PATH_BENEATH'),
        }
    )
    got = _ask_the_headers(wanted)

    for name, bit in FS.items():
        if f'FS_{name}' in got:
            assert got[f'FS_{name}'] == bit, f'LANDLOCK_ACCESS_FS_{name}'
    for key, ours in (
        ('NET_BIND', sandbox._NET_BIND_TCP),
        ('NET_CONNECT', sandbox._NET_CONNECT_TCP),
        ('SCOPE_UNIX', sandbox._SCOPE_ABSTRACT_UNIX_SOCKET),
        ('SCOPE_SIGNAL', sandbox._SCOPE_SIGNAL),
        ('VERSION', sandbox._LANDLOCK_CREATE_RULESET_VERSION),
        ('PATH_BENEATH', sandbox._LANDLOCK_RULE_PATH_BENEATH),
    ):
        if key in got:
            assert got[key] == ours, key
    # The FS table is a bit-per-right list; a header that knows a right we do not
    # is fine, but a gap in the middle would silently shift every later bit.
    assert got['FS_EXECUTE'] == 1


def test_seccomp_and_bpf_constants_match_the_kernel_headers():
    got = _ask_the_headers(
        {
            'RET_KILL_PROCESS': ('SECCOMP_RET_KILL_PROCESS', 'SECCOMP_RET_KILL_PROCESS'),
            'RET_ERRNO': ('SECCOMP_RET_ERRNO', 'SECCOMP_RET_ERRNO'),
            'RET_ALLOW': ('SECCOMP_RET_ALLOW', 'SECCOMP_RET_ALLOW'),
            'SET_MODE_FILTER': ('SECCOMP_SET_MODE_FILTER', 'SECCOMP_SET_MODE_FILTER'),
            'FLAG_TSYNC': ('SECCOMP_FILTER_FLAG_TSYNC', 'SECCOMP_FILTER_FLAG_TSYNC'),
            'NNP': ('PR_SET_NO_NEW_PRIVS', 'PR_SET_NO_NEW_PRIVS'),
            'LD_W_ABS': ('BPF_LD|BPF_W|BPF_ABS', 'BPF_LD'),
            'JMP_JEQ_K': ('BPF_JMP|BPF_JEQ|BPF_K', 'BPF_JMP'),
            'JMP_JGE_K': ('BPF_JMP|BPF_JGE|BPF_K', 'BPF_JMP'),
            'RET_K': ('BPF_RET|BPF_K', 'BPF_RET'),
            'ARCH_NATIVE': (f'AUDIT_ARCH_{platform.machine().upper()}', 'AUDIT_ARCH_X86_64'),
        }
    )
    for key, ours in (
        ('RET_KILL_PROCESS', sandbox._SECCOMP_RET_KILL_PROCESS),
        ('RET_ERRNO', sandbox._SECCOMP_RET_ERRNO),
        ('RET_ALLOW', sandbox._SECCOMP_RET_ALLOW),
        ('SET_MODE_FILTER', sandbox._SECCOMP_SET_MODE_FILTER),
        ('FLAG_TSYNC', sandbox._SECCOMP_FILTER_FLAG_TSYNC),
        ('NNP', sandbox._PR_SET_NO_NEW_PRIVS),
        ('LD_W_ABS', sandbox._BPF_LD_W_ABS),
        ('JMP_JEQ_K', sandbox._BPF_JMP_JEQ_K),
        ('JMP_JGE_K', sandbox._BPF_JMP_JGE_K),
        ('RET_K', sandbox._BPF_RET_K),
    ):
        if key in got:
            assert got[key] == ours, key
    if 'ARCH_NATIVE' in got and platform.machine() in sandbox._AUDIT_ARCH:
        assert got['ARCH_NATIVE'] == sandbox._AUDIT_ARCH[platform.machine()]


def test_native_syscall_numbers_match_the_kernel_headers():
    """The deny-list is only a deny-list if the numbers name the right calls."""
    arch = platform.machine()
    if arch not in sandbox._DENY:
        pytest.skip(f'no syscall table for {arch}')
    wanted = {n: (f'__NR_{n}', f'__NR_{n}') for n in sandbox._DENY[arch]}
    wanted['socket'] = ('__NR_socket', '__NR_socket')
    wanted['seccomp'] = ('__NR_seccomp', '__NR_seccomp')
    wanted['landlock_create_ruleset'] = (
        '__NR_landlock_create_ruleset',
        '__NR_landlock_create_ruleset',
    )
    wanted['landlock_add_rule'] = ('__NR_landlock_add_rule', '__NR_landlock_add_rule')
    wanted['landlock_restrict_self'] = (
        '__NR_landlock_restrict_self',
        '__NR_landlock_restrict_self',
    )
    got = _ask_the_headers(wanted)

    for name, number in sandbox._DENY[arch].items():
        if name in got:
            assert got[name] == number, f'__NR_{name} on {arch}'
    for key, ours in (
        ('socket', sandbox._NR_SOCKET[arch]),
        ('seccomp', sandbox._NR_SECCOMP[arch]),
        ('landlock_create_ruleset', sandbox._NR_LANDLOCK_CREATE_RULESET),
        ('landlock_add_rule', sandbox._NR_LANDLOCK_ADD_RULE),
        ('landlock_restrict_self', sandbox._NR_LANDLOCK_RESTRICT_SELF),
    ):
        if key in got:
            assert got[key] == ours, key
    assert len([n for n in sandbox._DENY[arch] if n in got]) > 15, 'headers checked almost nothing'


def test_aarch64_syscall_numbers_match_asm_generic():
    """aarch64 takes the asm-generic table verbatim, and it is plain #defines.

    Worth checking from an x86_64 box too: nothing else in the suite can catch a
    typo in the table for the architecture the developer is not sitting on.
    """
    header = '/usr/include/asm-generic/unistd.h'
    if not os.path.isfile(header):
        pytest.skip('asm-generic/unistd.h not installed')
    with open(header) as fh:
        text = fh.read()
    numbers = dict(re.findall(r'^#define __NR_(\w+)\s+(\d+)$', text, re.MULTILINE))
    if not numbers:
        pytest.skip('asm-generic/unistd.h has no plain __NR_ defines')

    checked = 0
    for name, number in {
        **sandbox._DENY['aarch64'],
        'socket': sandbox._NR_SOCKET['aarch64'],
    }.items():
        if name in numbers:
            assert int(numbers[name]) == number, f'__NR_{name} on aarch64'
            checked += 1
    assert checked > 15, 'the generic header checked almost nothing'
