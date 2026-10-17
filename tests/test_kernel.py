import os
from unittest.mock import patch

import pytest

from lkmhunter import KernelSession, MemoryReadError, MetadataError
from lkmhunter.memory import ElfMemory, LkmMemory
from lkmhunter.session import note_build_id
from lkmhunter.symbols import Symbol, read_symbols, relocation


def test_exact_elf_mapping_includes_segment_start_and_crosses_adjacent_segments(elf_factory):
    path = elf_factory([(0x1000, b'abcd'), (0x1004, b'efgh')])
    with ElfMemory(path) as image:
        assert image.read(0x1000, 8) == b'abcdefgh'
        assert image.read(0x1008, 0) == b''
        with pytest.raises(MemoryReadError):
            image.read(0x1007, 2)
    assert image.file.closed


def test_memory_size_does_not_make_bss_file_backed(elf_factory):
    with ElfMemory(elf_factory([(0x1000, b'ab')], mem_sizes=[4096])) as image:
        with pytest.raises(MemoryReadError):
            image.read(0x1002, 1)
        with patch('lkmhunter.memory.os.pread', return_value=b'a'):
            with pytest.raises(MemoryReadError, match='short read'):
                image.read(0x1000, 2)
        with pytest.raises(ValueError):
            image.read(-1, 1)


def test_lkm_ioctl_uses_unsigned_address_and_rejects_short_read():
    with patch('lkmhunter.memory.os.open', return_value=5), patch('lkmhunter.memory.os.close') as close:
        with LkmMemory() as memory:
            with patch('lkmhunter.memory.fcntl.ioctl', return_value=1) as ioctl:
                with pytest.raises(MemoryReadError, match='short ioctl'):
                    memory.read(0xffffffffc0123456, 8)
                transfer = ioctl.call_args.args[2]
                assert int.from_bytes(transfer[:8], 'little') == 0xffffffffc0123456
        close.assert_called_once_with(5)


def test_auto_backend_is_selected_once_and_does_not_fallback_after_read_error(elf_factory):
    image = elf_factory([(0x1000, b'abcdefgh')])
    with patch('lkmhunter.session.LkmMemory', side_effect=FileNotFoundError('missing')):
        with KernelSession(kcore=image) as session:
            assert session.memory.backend == 'kcore'
            assert session.memory is session.memory
            assert session.memory.read(0x1000, 8) == b'abcdefgh'
        assert session.memory.file.closed
    with patch('lkmhunter.session.LkmMemory') as helper, patch('lkmhunter.session.ElfMemory') as elf:
        helper.return_value.read.side_effect = MemoryReadError(0, 8, 'failure')
        with KernelSession(kcore=image) as session:
            with pytest.raises(MemoryReadError):
                session.memory.read(0, 8)
            elf.assert_not_called()
        helper.return_value.close.assert_called_once()


def test_lazy_session_and_closed_session_do_not_open_resources():
    with patch('lkmhunter.session.LkmMemory') as helper:
        session = KernelSession()
        session.close()
        with pytest.raises(RuntimeError, match='closed'):
            session.memory
        helper.assert_not_called()


def test_symbol_parser_ignores_module_aliases_and_handles_whitespace(tmp_path):
    path = tmp_path / 'kallsyms'
    path.write_text('0000 T _text\n1000\tT\t_text\n2000 t _text [rogue]\n3000 T other\n')
    symbols = read_symbols(path)
    assert symbols['_text'].address == 0x1000
    assert symbols['other'].address == 0x3000


def test_relocation_handles_nonzero_offset_and_rejects_mismatch():
    baseline = {n: Symbol(n, a) for n, a in [('_text', 0x1000), ('sys_call_table', 0x2000)]}
    live = {n: Symbol(n, s.address + 0x200000) for n, s in baseline.items()}
    assert relocation(live, baseline)[0] == 0x200000
    live['_text'] = Symbol('_text', 0x9999)
    with pytest.raises(MetadataError, match='Inconsistent'):
        relocation(live, baseline)
    with pytest.raises(MetadataError, match='nonzero'):
        relocation({'_text': Symbol('_text', 0)}, baseline)


def test_build_id_note():
    import struct
    note = struct.pack('<III', 4, 4, 3) + b'GNU\0' + bytes.fromhex('12345678')
    assert note_build_id(note) == '12345678'
    assert note_build_id(note[:12]) is None


def test_baseline_build_id_must_match_target(elf_factory, tmp_path):
    import struct
    note = struct.pack('<III', 4, 4, 3) + b'GNU\0' + bytes.fromhex('12345678')
    path = elf_factory([(0x1000, b'code'), (0, note)], segment_types=[1, 4])
    live_notes = tmp_path / 'notes'
    live_notes.write_bytes(note[:-4] + bytes.fromhex('87654321'))
    with KernelSession(vmlinux=path, live_notes=live_notes) as session:
        with pytest.raises(MetadataError, match='differs from live'):
            session.baseline


def test_syscall_count_never_falls_back_to_static_enumeration():
    with KernelSession() as session:
        session.__dict__['baseline_symbols'] = {'sys_call_table': Symbol('sys_call_table', 0x1000, 473 * 8)}
        assert session.syscall_count() == 473
        with pytest.raises(MetadataError, match='disagrees'):
            session.syscall_count(314)


@pytest.mark.integration
def test_live_symbols_layout_and_helper_fault_containment():
    # Explicitly opted-in read checks only: this test never loads a module.
    with KernelSession() as session:
        assert session.live_symbols
        assert session.module_layout.size > 0
        if os.path.exists('/proc/lkm/mem'):
            assert session.memory.fault_contained, 'rebuild/reload the updated helper'
            with pytest.raises(MemoryReadError):
                session.memory.read(0xfffffffffefff000, 4096)


@pytest.mark.integration
def test_live_scanners_and_known_module_owner():
    from lkmhunter import FtraceScanner, ModuleScanner, ScanStatus, SyscallScanner
    with KernelSession() as session:
        syscalls = SyscallScanner().scan(session)
        assert syscalls.status == ScanStatus.COMPLETE, syscalls.to_dict()
        assert syscalls.coverage['compared'] == syscalls.coverage['total']
        ftrace = FtraceScanner().scan(session)
        assert ftrace.status == ScanStatus.COMPLETE, ftrace.to_dict()
        if session.memory.backend == 'lkm_mem':
            with open('/proc/modules') as source:
                fields = next(line.split() for line in source if line.startswith('lkm_mem '))
            owner = ModuleScanner().scan(session, int(fields[5], 16))
            assert owner.status == ScanStatus.COMPLETE, owner.to_dict()
            assert owner.findings[0].evidence['name'] == 'lkm_mem'
