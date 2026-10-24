import io
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from elftools.elf.elffile import ELFFile

from lkmhunter import KernelSession
from lkmhunter.gdb_bridge import MemoryTarget, frame, prepare_gdb, serve, write_symbol_elf
from lkmhunter.symbols import Symbol, read_symbols


def test_protocol_exact_memory_and_unavailable_registers(byte_memory):
    memory = byte_memory({0xffffffffc0001000: b'\x01\x02\x03\x04'})
    target = MemoryTarget(memory)
    assert target.dispatch(b'mffffffffc0001000,4') == b'01020304'
    assert target.dispatch(b'mffffffffc0001002,4') == b'E14'
    assert target.dispatch(b'mffffffffc0001000,100000') == b'E22'
    assert target.dispatch(b'm-1,4') == b'E22'
    assert target.dispatch(b'p0') == b'x' * 16
    assert target.dispatch(b'p10') == b'0' * 16  # synthetic inspection PC
    assert target.dispatch(b'qUnknownFeature') == b''


@pytest.mark.parametrize('packet', [b'Mffffffffc0001000,1:ff', b'X0,1:a', b'G00', b'P0=00',
                                     b'Z0,0,1', b'z0,0,1', b'c', b's', b'vCont;c', b'vKill;1', b'k'])
def test_protocol_rejects_mutations_and_execution(packet, byte_memory):
    memory = byte_memory({})
    assert MemoryTarget(memory).dispatch(packet) == b'E01'
    assert memory.reads == []


def test_transport_checksum_retry_ack_and_noack(byte_memory):
    request = frame(b'm1000,2')
    bad = request[:-2] + b'00'
    reader = io.BytesIO(bad + request + b'-' + frame(b'QStartNoAckMode') + frame(b'D'))
    output = io.BytesIO()
    serve(byte_memory({0x1000: b'ab'}), reader, output)
    assert output.getvalue() == b'-+' + frame(b'6162') * 2 + b'+' + frame(b'OK') + frame(b'OK')


def test_symbol_elf_has_runtime_addresses_and_no_memory_bytes(tmp_path):
    symbols = {'function': Symbol('function', 0xffffffff81000000, kind='T'),
               'table': Symbol('table', 0xffffffff82000000, kind='D'),
               'restricted': Symbol('restricted', 0)}
    path = tmp_path / 'symbols.elf'
    assert write_symbol_elf(symbols, path) == 2
    assert path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        write_symbol_elf(symbols, path)
    with path.open('rb') as source:
        elf = ELFFile(source)
        table = elf.get_section_by_name('.symtab')
        assert table.get_symbol_by_name('table')[0]['st_value'] == 0xffffffff82000000
        assert elf.get_section_by_name('.text.0')['sh_type'] == 'SHT_NOBITS'


def test_module_symbols_have_namespaces(tmp_path):
    path = tmp_path / 'kallsyms'
    path.write_text('ffffffff81000000 T func\nffffffffc0000000 t func [module]\n')
    symbols = read_symbols(path, include_modules=True)
    assert symbols['func'].address == 0xffffffff81000000
    assert symbols['module__func'].address == 0xffffffffc0000000


def test_prepare_kallsyms_needs_no_baseline(tmp_path):
    path = tmp_path / 'kallsyms'
    path.write_text('ffffffff81000000 T func\nffffffff82000000 D table\n')
    with KernelSession(kallsyms=path, vmlinux=tmp_path / 'missing') as session:
        script = prepare_gdb(session, tmp_path / 'session', mode='kallsyms', server_arguments=['--backend', 'kcore'])
    text = script.read_text()
    assert 'gdb-serve --backend kcore' in text
    assert 'set may-write-memory off' in text
    assert 'set trust-readonly-sections off' in text
    assert 'target remote | ' in text


def test_real_gdb_over_local_pipe(tmp_path, elf_factory):
    if not shutil.which('gdb'):
        pytest.skip('GDB not installed')
    address = 0xffffffff81000000
    image = elf_factory([(address, b'\x78\x56\x34\x12' + bytes(4092))])
    symbols = tmp_path / 'kallsyms'
    symbols.write_text(f'{address-4096:016x} T before\n{address:016x} D kernel_probe\n{address+4096:016x} T after\n')
    result = subprocess.run([
        sys.executable, '-m', 'lkmhunter', 'gdb', '--symbols', 'kallsyms', '--backend', 'kcore',
        '--kcore', str(image), '--kallsyms', str(symbols), '--batch',
        '--command', 'x/wx &kernel_probe', '--command', 'info address kernel_probe',
        '--command', 'info symbol &kernel_probe',
        '--command', 'detach',
    ], capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stdout + result.stderr
    assert '0x12345678' in result.stdout
    assert 'kernel_probe' in result.stdout
    assert 'kernel_probe in section' in result.stdout
    assert 'Rejected target-supplied description' not in result.stderr


def test_real_gdb_types_and_kaslr(tmp_path, elf_factory):
    if not shutil.which('gdb') or not shutil.which('cc'):
        pytest.skip('GDB and C compiler required')
    source = tmp_path / 'probe.c'
    source.write_text('''
    struct probe { unsigned long marker; unsigned int flags; };
    struct probe sample = { 0x1122334455667788UL, 42 };
    void _stext(void) {}
    void _text(void) {}
    ''')
    binary = tmp_path / 'vmlinux'
    subprocess.run(['cc', '-g', '-O0', '-ffreestanding', '-fno-pie', '-mcmodel=kernel',
                    '-nostdlib', '-no-pie', '-Wl,--build-id=none', '-Wl,-e,_stext',
                    '-Wl,-Ttext=0xffffffff81000000', str(source), '-o', str(binary)], check=True)
    slide = 0x2000000
    with binary.open('rb') as stream:
        elf = ELFFile(stream)
        entries = {s.name: s['st_value'] for s in elf.get_section_by_name('.symtab').iter_symbols()
                   if s.name in ('_stext', '_text', 'sample')}
        segments = [(s['p_vaddr'] + slide, s.data()) for s in elf.iter_segments()
                    if s['p_type'] == 'PT_LOAD' and s['p_filesz']]
    memory = elf_factory(segments)
    live, base = tmp_path / 'kallsyms', tmp_path / 'System.map'
    live.write_text(''.join(f'{address + slide:016x} T {name}\n' for name, address in entries.items()))
    base.write_text(''.join(f'{address:016x} T {name}\n' for name, address in entries.items()))
    result = subprocess.run([
        sys.executable, '-m', 'lkmhunter', 'gdb', '--symbols', 'vmlinux', '--vmlinux', str(binary),
        '--backend', 'kcore', '--kcore', str(memory), '--kallsyms', str(live),
        '--system-map', str(base), '--live-notes', '', '--kernel-release', 'fixture', '--batch',
        '--command', 'p/x sample', '--command', 'x/gx &sample', '--command', 'info registers rax',
        '--command', 'detach',
    ], capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'marker = 0x1122334455667788' in result.stdout
    assert 'flags = 0x2a' in result.stdout
    assert f'{entries["sample"] + slide:x}' in result.stdout
    assert '<unavailable>' in result.stdout
