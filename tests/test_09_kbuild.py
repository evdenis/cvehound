"""Unit tests for the Kbuild config-map parser and the .config evaluation.

These run on synthetic mini-trees written to tmp_path: no kernel checkout,
no spatch, no network.
"""

import collections
import os
import textwrap

from cvehound import evaluate_file_condition
from cvehound.config import Config
from cvehound.kbuild import KbuildParser
from cvehound.util import get_srcarch


def write_tree(root, files):
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(content))


def build_map(root, arch='x86'):
    kernel = str(root)
    parser = KbuildParser(None, arch, kernel)
    dirs_to_process = collections.OrderedDict()
    parser.init_class.process(parser, dirs_to_process, kernel)
    for item in dirs_to_process:
        descend = parser.init_class.get_file_for_subdirectory(item)
        parser.process_kbuild_or_makefile(descend, dirs_to_process[item])
    return {os.path.relpath(k, kernel): v for k, v in parser.get_config().items()}


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


def test_evaluate_unknown_file_is_affected(tmp_path):
    config = make_config(tmp_path, 'CONFIG_A=y\n')
    assert evaluate_file_condition(None, 'drivers/foo/bar.c', 'x86', config) == ('unknown', True)
    assert evaluate_file_condition(None, 'drivers/foo/bar.c', 'x86', None) == ('unknown', None)


def test_evaluate_unconditional_file(tmp_path):
    config = make_config(tmp_path, 'CONFIG_A=y\n')
    assert evaluate_file_condition('', 'kernel/fork.c', 'x86', config) == ('True', True)
    assert evaluate_file_condition('', 'kernel/fork.c', 'x86', None) == ('True', None)


def test_evaluate_arch_mismatch(tmp_path):
    config = make_config(tmp_path, 'CONFIG_KVM=y\n')
    # An x86-only file can never be built into an arm64 kernel (issue #26).
    assert evaluate_file_condition(
        'CONFIG_PERF_EVENTS', 'arch/x86/events/intel/ds.c', 'arm64', config
    ) == ('False', False)
    assert evaluate_file_condition(None, 'arch/x86/kvm/x86.c', 'arm64', config) == (
        'False',
        False,
    )
    # Same arch evaluates normally.
    logic, affected = evaluate_file_condition('CONFIG_KVM', 'arch/x86/kvm/x86.c', 'x86', config)
    assert affected is True


def test_evaluate_absent_symbol_is_disabled(tmp_path):
    config = make_config(tmp_path, 'CONFIG_A=y\n')
    logic, affected = evaluate_file_condition('CONFIG_A & CONFIG_B', 'foo.c', 'x86', config)
    assert affected is False
    config = make_config(tmp_path, 'CONFIG_A=y\nCONFIG_B=m\n')
    logic, affected = evaluate_file_condition('CONFIG_A & CONFIG_B', 'foo.c', 'x86', config)
    assert affected is True


def test_evaluate_not_set_symbol(tmp_path):
    config = make_config(tmp_path, 'CONFIG_A=y\n# CONFIG_B is not set\n')
    logic, affected = evaluate_file_condition('CONFIG_A & CONFIG_B', 'foo.c', 'x86', config)
    assert affected is False
    logic, affected = evaluate_file_condition('CONFIG_A | CONFIG_B', 'foo.c', 'x86', config)
    assert affected is True
