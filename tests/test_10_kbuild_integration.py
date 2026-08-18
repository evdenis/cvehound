"""Integration tests: Kbuild config map built on pinned real kernel tags.

Uses a detached git worktree of tests/linux so the shared checkout state
managed by the fixtures is never touched.
"""

import os
import shutil
import tempfile
import time

import pytest
from test_09_kbuild import build_map

pytestmark = pytest.mark.slow

# Ground-truth conditions, cross-checked against kmax under a real .config.
EXPECTED = {
    'v6.1': {
        'arch/x86/kvm/x86.c': 'CONFIG_KVM',
        'arch/x86/kvm/svm/sev.c': 'CONFIG_KVM & CONFIG_KVM_AMD',
        'virt/kvm/kvm_main.c': 'CONFIG_KVM',
        'io_uring/io_uring.c': 'CONFIG_IO_URING',
        'kernel/bpf/verifier.c': 'CONFIG_BPF & CONFIG_BPF_SYSCALL',
        'drivers/block/floppy.c': 'CONFIG_BLK_DEV_FD',
    },
    'v7.1': {
        'arch/x86/kvm/x86.c': 'CONFIG_KVM & CONFIG_KVM_X86',
        'arch/x86/kvm/svm/sev.c': 'CONFIG_KVM & CONFIG_KVM_AMD & CONFIG_KVM_AMD_SEV',
        'virt/kvm/kvm_main.c': 'CONFIG_KVM & CONFIG_KVM_X86',
        'io_uring/io_uring.c': 'CONFIG_IO_URING',
        'kernel/bpf/verifier.c': 'CONFIG_BPF & CONFIG_BPF_SYSCALL',
        'drivers/block/floppy.c': 'CONFIG_BLK_DEV_FD',
    },
}


@pytest.fixture(params=sorted(EXPECTED))
def kernel_tree(repo, request):
    tag = request.param
    tmpdir = tempfile.mkdtemp(prefix='cvehound-kbuild-')
    try:
        repo.git.worktree('add', '--detach', tmpdir, tag)
        yield tag, tmpdir
    finally:
        try:
            repo.git.worktree('remove', '--force', tmpdir)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


def test_kbuild_map_on_tag(kernel_tree):
    tag, tree = kernel_tree

    start = time.perf_counter()
    config = build_map(tree)
    elapsed = time.perf_counter() - start

    for path, condition in EXPECTED[tag].items():
        assert config.get(path) == condition, path

    arch_entries = [k for k in config if k.startswith('arch/x86/')]
    assert len(arch_entries) > 300
    assert any(k.startswith('io_uring/') for k in config)
    assert not any('..' in os.path.normpath(k).split(os.sep) for k in config)
    assert elapsed < 15
