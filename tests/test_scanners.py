import json
from unittest.mock import patch

import pytest

from lkmhunter import FtraceScanner, KernelSession, ModuleScanner, ScanStatus, SyscallScanner, dump_module
from lkmhunter.metadata import Field, ModuleLayout, RegionLayout
from lkmhunter.scanners import MODULE_START
from lkmhunter.symbols import Symbol


def test_syscall_scanner_uses_full_64_bit_pointers_and_metadata_count(byte_memory, fake_session):
    base = 0xffffffff81000000
    slide = 0x200000
    count = 450  # beyond the old enumeration
    table = b''.join((base + n * 16).to_bytes(8, 'little') for n in range(count))
    live = bytearray(b''.join((base + n * 16 + slide).to_bytes(8, 'little') for n in range(count)))
    live[440*8:441*8] = (MODULE_START + 0x1000).to_bytes(8, 'little')
    session = fake_session(
        baseline=byte_memory({base: table}), memory=byte_memory({base + slide: live}),
        baseline_symbols={'sys_call_table': Symbol('sys_call_table', base, count * 8)},
        kaslr_offset=slide, runtime_address=lambda name: base + slide,
        syscall_count=lambda override: count,
    )
    result = SyscallScanner().scan(session)
    assert result.status == ScanStatus.COMPLETE
    assert result.coverage['compared'] == count
    assert [f.evidence['number'] for f in result.findings] == [440]
    assert result.exit_code == 1
    session.memory = byte_memory({base + slide: live[:16]})
    result = SyscallScanner().scan(session)
    assert result.status == ScanStatus.PARTIAL
    assert result.exit_code == 2


def test_missing_baseline_is_unavailable(tmp_path):
    with KernelSession(vmlinux=tmp_path / 'missing') as session:
        result = SyscallScanner().scan(session)
    assert result.status == ScanStatus.UNAVAILABLE
    assert result.exit_code == 2


def test_ftrace_requires_no_memory_or_baseline(tmp_path):
    path = tmp_path / 'enabled_functions'
    path.write_text('\n'.join(f'{name} (1) R I tramp: 0xffffffffc0001000 (0xffffffffc0002000)' for name in ['read', 'kill', 'getdents']))
    with patch('lkmhunter.session.LkmMemory') as memory:
        with KernelSession(tracefs=path, vmlinux='/missing') as session:
            result = FtraceScanner().scan(session)
        memory.assert_not_called()
    assert result.status == ScanStatus.COMPLETE
    assert len(result.findings) == 1
    assert result.exit_code == 1
    assert result.findings[0].evidence['heuristic']
    path.write_text('new kernel format unknown\n')
    with KernelSession(tracefs=path) as session:
        assert FtraceScanner().scan(session).status == ScanStatus.PARTIAL
    path.unlink()
    with KernelSession(tracefs=path) as session:
        assert FtraceScanner().scan(session).exit_code == 2


def test_ftrace_duplicates_do_not_trigger_threshold(tmp_path):
    path = tmp_path / 'trace'
    path.write_text('read (1) R tramp: 0xffffffffc0001000 (0xffffffffc0002000)\n' * 4)
    with KernelSession(tracefs=path) as session:
        assert not FtraceScanner().scan(session).findings


@pytest.mark.parametrize('continuation', ['direct-->bpf_trampoline_123+0x0/0xf1',
                                         'direct(jmp)-->bpf_trampoline_123+0x0/0xf1'])
def test_ftrace_accepts_kernel_direct_call_continuations(tmp_path, continuation):
    path = tmp_path / 'trace'
    path.write_text('__hid_bpf_tail_call (1) R D M tramp: ftrace_regs_caller+0x0/0x78 (call_direct_funcs+0x0/0x20)\n'
                    + '\t' + continuation + '\n')
    with KernelSession(tracefs=path) as session:
        result = FtraceScanner().scan(session)
    assert result.status == ScanStatus.COMPLETE
    assert result.coverage['unparsed'] == 0
    assert not result.findings


@pytest.fixture
def module_fixture(byte_memory, fake_session):
    layout = ModuleLayout(128, Field(0, 4), Field(24, 32), Field(8, 8), Field(16, 8),
                          [RegionLayout('text', Field(64, 8), Field(72, 4))], {0: 'LIVE'}, 'fixture', Field(88, 8)).validate()
    target = MODULE_START + 0x100000
    owner = target + 4096 - 32  # name and structure straddle a page/window boundary
    start = target + 4096 - 4096
    data = bytearray(3 * 4096)
    offset = owner - start
    data[offset + 8:offset + 16] = (0x100).to_bytes(8, 'little')
    data[offset + 16:offset + 24] = (0x122).to_bytes(8, 'little')
    data[offset + 24:offset + 31] = b'hidden\0'
    data[offset + 64:offset + 72] = target.to_bytes(8, 'little')
    data[offset + 72:offset + 76] = (4096).to_bytes(4, 'little')
    data[offset + 88:offset + 96] = owner.to_bytes(8, 'little')
    memory = byte_memory({start: data})
    return fake_session(memory=memory, module_layout=layout), target, owner


def test_module_recovers_owner_across_boundaries_and_gaps(module_fixture):
    session, target, owner = module_fixture
    result = ModuleScanner().scan(session, target, max_back=16384, chunk_size=4096)
    assert result.status == ScanStatus.COMPLETE
    assert result.findings[0].evidence['struct_addr'] == owner
    assert result.findings[0].suspicious
    assert result.coverage['unreadable_bytes'] > 0


def test_module_ownership_must_contain_target(module_fixture):
    session, target, _ = module_fixture
    result = ModuleScanner().scan(session, target - 8192, max_back=16384, chunk_size=4096)
    assert not result.findings
    assert result.status == ScanStatus.PARTIAL


def test_module_rejects_region_descriptor_without_matching_self_pointer(module_fixture):
    session, target, owner = module_fixture
    start, data = next(iter(session.memory.regions.items()))
    data[owner - start + 88:owner - start + 96] = bytes(8)
    result = ModuleScanner().scan(session, target, max_back=16384, chunk_size=4096)
    assert not result.findings


def test_module_old_helper_is_rejected(module_fixture):
    session, target, _ = module_fixture
    session.memory.backend = 'lkm_mem'
    session.memory.fault_contained = False
    result = ModuleScanner().scan(session, target)
    assert result.status == ScanStatus.UNAVAILABLE
    assert not session.memory.reads


def test_module_recovers_erased_name_and_arbitrary_list_pointers(module_fixture):
    session, target, owner = module_fixture
    start, data = next(iter(session.memory.regions.items()))
    offset = owner - start
    data[offset + 24:offset + 56] = bytes(32)
    data[offset + 8:offset + 16] = (0x22373717).to_bytes(8, 'little')
    data[offset + 16:offset + 24] = (0x37373731).to_bytes(8, 'little')
    result = ModuleScanner().scan(session, target, max_back=16384, chunk_size=4096)
    assert result.findings[0].evidence['struct_addr'] == owner
    assert result.findings[0].evidence['name_erased']
    assert result.findings[0].evidence['list_pointer_anomaly']
    assert result.findings[0].suspicious


def test_module_accepts_configured_poison_pointer_delta(module_fixture):
    session, target, owner = module_fixture
    start, data = next(iter(session.memory.regions.items()))
    offset = owner - start
    delta = 0xdead000000000000
    data[offset + 8:offset + 16] = (delta + 0x100).to_bytes(8, 'little')
    data[offset + 16:offset + 24] = (delta + 0x122).to_bytes(8, 'little')
    result = ModuleScanner().scan(session, target, max_back=16384, chunk_size=4096)
    assert result.findings[0].evidence['hidden_from_module_list']


def test_search_budget_is_exact_without_overshooting_chunk(module_fixture):
    session, target, _ = module_fixture
    result = ModuleScanner().scan(session, target, max_back=64, chunk_size=4096, direction='forward')
    assert not result.findings
    assert all(target <= address and address + size <= target + 64 for address, size in session.memory.reads)


def test_forward_search_does_not_accept_header_behind_target(module_fixture):
    session, _, owner = module_fixture
    result = ModuleScanner().scan(session, owner + 16, max_back=8192, chunk_size=4096, direction='forward')
    assert not result.findings


def test_dump_manifest_records_gaps_and_does_not_overwrite(module_fixture, tmp_path, byte_memory):
    session, target, _ = module_fixture
    finding = ModuleScanner().scan(session, target).findings[0]
    session.memory = byte_memory({})
    path, manifest = dump_module(session, finding, tmp_path)
    assert not manifest['complete']
    assert manifest['gaps'][0]['address'] == target
    assert json.loads(path.read_text())['gaps']
    assert (path.parent / 'hidden.text.bin').read_bytes() == bytes(4096)
    with pytest.raises(FileExistsError):
        dump_module(session, finding, tmp_path)
