"""Unit tests for the Kbuild config-map parser and the .config evaluation.

These run on synthetic mini-trees written to tmp_path: no kernel checkout,
no spatch, no network.
"""

import os

import pytest
from conftest import build_map, write_tree

from cvehound import evaluate_file_condition
from cvehound.config import Config
from cvehound.util import get_srcarch


def test_get_srcarch():
    assert get_srcarch('x86_64') == 'x86'
    assert get_srcarch('i386') == 'x86'
    assert get_srcarch('sparc64') == 'sparc'
    assert get_srcarch('parisc64') == 'parisc'
    assert get_srcarch('arm64') == 'arm64'
    assert get_srcarch('x86') == 'x86'


def test_root_kbuild_seeding_v61_scheme(tmp_path):
    """The >= v6.1 layout: all descent starts from the root Kbuild."""
    write_tree(
        tmp_path,
        {
            'Kbuild': """\
                obj-y += init/
                obj-y += arch/$(SRCARCH)/
                obj-$(CONFIG_IO_URING) += io_uring/
                obj-y += drivers/
            """,
            'init/Makefile': 'obj-y += main.o\n',
            'init/main.c': '',
            'arch/x86/Kbuild': """\
                obj-y += kernel/
                obj-$(CONFIG_KVM) += kvm/
            """,
            'arch/x86/Makefile': 'libs-y += arch/x86/lib/\n',
            'arch/x86/kernel/Makefile': 'obj-y += setup.o\n',
            'arch/x86/kernel/setup.c': '',
            'arch/x86/lib/Makefile': 'obj-y += memcpy.o\n',
            'arch/x86/lib/memcpy.c': '',
            'arch/x86/kvm/Makefile': """\
                include $(srctree)/virt/kvm/Makefile.kvm
                kvm-y += x86.o
                kvm-amd-$(CONFIG_KVM_AMD_SEV) += svm/sev.o
                obj-$(CONFIG_KVM_X86) += kvm.o
                obj-$(CONFIG_KVM_AMD) += kvm-amd.o
            """,
            'arch/x86/kvm/x86.c': '',
            'arch/x86/kvm/svm/sev.c': '',
            'virt/kvm/Makefile.kvm': """\
                KVM ?= ../../../virt/kvm
                kvm-y += $(KVM)/kvm_main.o
            """,
            'virt/kvm/kvm_main.c': '',
            'io_uring/Makefile': 'obj-$(CONFIG_IO_URING) += io_uring.o\n',
            'io_uring/io_uring.c': '',
            'drivers/Makefile': 'obj-$(CONFIG_NET) += net/\n',
            'drivers/net/Makefile': 'obj-$(CONFIG_TUN) += tun.o\n',
            'drivers/net/tun.c': '',
        },
    )
    config = build_map(tmp_path)

    assert config['init/main.c'] == ''
    assert config['arch/x86/kernel/setup.c'] == ''
    assert config['arch/x86/lib/memcpy.c'] == ''
    assert config['arch/x86/kvm/x86.c'] == 'CONFIG_KVM & CONFIG_KVM_X86'
    assert config['arch/x86/kvm/svm/sev.c'] == 'CONFIG_KVM & CONFIG_KVM_AMD & CONFIG_KVM_AMD_SEV'
    # Reached through include $(srctree)/... and a $(KVM)-relative path.
    assert config['virt/kvm/kvm_main.c'] == 'CONFIG_KVM & CONFIG_KVM_X86'
    assert config['io_uring/io_uring.c'] == 'CONFIG_IO_URING'
    assert config['drivers/net/tun.c'] == 'CONFIG_NET & CONFIG_TUN'
    assert not any('..' in os.path.normpath(k).split(os.sep) for k in config)


def test_top_makefile_seeding_v510_scheme(tmp_path):
    """The <= v6.0 layout: core-y/drivers-y in the top Makefile, plus the
    arch Makefile adding core-y += arch/x86/."""
    write_tree(
        tmp_path,
        {
            'Makefile': """\
                core-y := init/ usr/
                core-y += kernel/
                drivers-$(CONFIG_SAMPLES) += samples/
                net-y := net/
            """,
            'init/Makefile': 'obj-y += main.o\n',
            'init/main.c': '',
            'kernel/Makefile': 'obj-$(CONFIG_BPF) += bpf/\n',
            'kernel/bpf/Makefile': 'obj-$(CONFIG_BPF_SYSCALL) += verifier.o\n',
            'kernel/bpf/verifier.c': '',
            'samples/Makefile': 'obj-y += sample.o\n',
            'samples/sample.c': '',
            'net/Makefile': 'obj-$(CONFIG_INET) += ipv4/\n',
            'net/ipv4/Makefile': 'obj-y += tcp.o\n',
            'net/ipv4/tcp.c': '',
            'arch/x86/Makefile': 'core-y += arch/x86/\n',
            'arch/x86/Kbuild': 'obj-$(CONFIG_KVM) += kvm/\n',
            'arch/x86/kvm/Makefile': """\
                KVM := ../../../virt/kvm
                kvm-y += x86.o $(KVM)/kvm_main.o
                obj-$(CONFIG_KVM) += kvm.o
            """,
            'arch/x86/kvm/x86.c': '',
            'virt/kvm/kvm_main.c': '',
        },
    )
    config = build_map(tmp_path)

    assert config['init/main.c'] == ''
    assert config['kernel/bpf/verifier.c'] == 'CONFIG_BPF & CONFIG_BPF_SYSCALL'
    assert config['samples/sample.c'] == 'CONFIG_SAMPLES'
    assert config['net/ipv4/tcp.c'] == 'CONFIG_INET'
    assert config['arch/x86/kvm/x86.c'] == 'CONFIG_KVM'
    assert config['virt/kvm/kvm_main.c'] == 'CONFIG_KVM'


def test_multi_parent_conditions_are_merged(tmp_path):
    """A source reached from two different Makefiles keeps both conditions."""
    write_tree(
        tmp_path,
        {
            'Kbuild': 'obj-y += a/ b/\n',
            'a/Makefile': 'obj-$(CONFIG_A) += ../shared/x.o\n',
            'b/Makefile': 'obj-$(CONFIG_B) += ../shared/x.o\n',
            'shared/x.c': '',
        },
    )
    config = build_map(tmp_path)
    assert config['shared/x.c'] == '(CONFIG_A) | (CONFIG_B)'


def test_unconditional_path_wins_merge(tmp_path):
    write_tree(
        tmp_path,
        {
            'Kbuild': 'obj-y += a/ b/\n',
            'a/Makefile': 'obj-$(CONFIG_A) += ../shared/x.o\n',
            'b/Makefile': 'obj-y += ../shared/x.o\n',
            'shared/x.c': '',
        },
    )
    config = build_map(tmp_path)
    assert config['shared/x.c'] == ''


def test_config_parsing(tmp_path):
    dot_config = tmp_path / '.config'
    dot_config.write_text(
        '# Linux/x86 6.1.0 Kernel Configuration\nCONFIG_A=y\nCONFIG_B=m\n# CONFIG_C is not set\n'
    )
    config = Config(str(dot_config))
    assert config['CONFIG_A'] is True
    assert config['CONFIG_B'] is True
    assert config['CONFIG_C'] is False
    assert config['CONFIG_ABSENT'] is False


def make_config(tmp_path, content):
    dot_config = tmp_path / '.config'
    dot_config.write_text(content)
    return Config(str(dot_config))


DOT_CONFIG = 'CONFIG_A=y\nCONFIG_M=m\n# CONFIG_OFF is not set\n'

# (condition from the Kbuild map, file, srcarch, has .config) -> (logic, affected)
EVALUATIONS = [
    # A file the parser knows nothing about is assumed to be built.
    (None, 'drivers/foo/bar.c', 'x86', True, ('unknown', True)),
    (None, 'drivers/foo/bar.c', 'x86', False, ('unknown', None)),
    # No condition at all means unconditionally built.
    ('', 'kernel/fork.c', 'x86', True, ('True', True)),
    ('', 'kernel/fork.c', 'x86', False, ('True', None)),
    # Another architecture's sources are never built into this kernel (#26).
    ('CONFIG_A', 'arch/x86/events/intel/ds.c', 'arm64', True, ('False', False)),
    (None, 'arch/x86/kvm/x86.c', 'arm64', True, ('False', False)),
    ('CONFIG_A', 'arch/x86/kvm/x86.c', 'x86', True, ('CONFIG_A', True)),
    # =y and =m both count as built, absent and "is not set" as disabled.
    ('CONFIG_M', 'foo.c', 'x86', True, ('CONFIG_M', True)),
    ('CONFIG_A & CONFIG_M', 'foo.c', 'x86', True, ('CONFIG_A & CONFIG_M', True)),
    ('CONFIG_A & CONFIG_ABSENT', 'foo.c', 'x86', True, ('CONFIG_A & CONFIG_ABSENT', False)),
    ('CONFIG_A & CONFIG_OFF', 'foo.c', 'x86', True, ('CONFIG_A & CONFIG_OFF', False)),
    ('CONFIG_A | CONFIG_OFF', 'foo.c', 'x86', True, ('CONFIG_A | CONFIG_OFF', True)),
    ('CONFIG_OFF | CONFIG_ABSENT', 'foo.c', 'x86', True, ('CONFIG_ABSENT | CONFIG_OFF', False)),
    # Without a .config there is a condition but no verdict.
    ('CONFIG_A', 'foo.c', 'x86', False, ('CONFIG_A', None)),
]


@pytest.mark.parametrize(('logic', 'relpath', 'srcarch', 'with_config', 'expected'), EVALUATIONS)
def test_evaluate_file_condition(tmp_path, logic, relpath, srcarch, with_config, expected):
    config = make_config(tmp_path, DOT_CONFIG) if with_config else None
    assert evaluate_file_condition(logic, relpath, srcarch, config) == expected
