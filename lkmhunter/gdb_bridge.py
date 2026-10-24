"""Read-only GDB remote protocol over a local subprocess pipe.

The protocol's synthetic stopped thread is a memory view, not a stopped CPU.
No request can write memory, set registers, or control kernel execution.
"""
import logging
import os
import re
import shlex
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

from .errors import HunterError, MemoryReadError, UnavailableError
from .symbols import read_symbols

logger = logging.getLogger(__name__)
PACKET_SIZE = 16384
MAX_READ = 4096

# GDB's standard amd64 core and SSE register layout. Only the synthetic
# inspection PC is supplied; no values represent a CPU/thread context.
CORE_REGISTERS = [(n, 64) for n in
                  'rax rbx rcx rdx rsi rdi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15 rip'.split()]
CORE_REGISTERS += [(n, 32) for n in 'eflags cs ss ds es fs gs'.split()]
CORE_REGISTERS += [(f'st{i}', 80) for i in range(8)]
CORE_REGISTERS += [(n, 32) for n in 'fctrl fstat ftag fiseg fioff foseg fooff fop'.split()]
SSE_REGISTERS = [(f'xmm{i}', 128) for i in range(16)] + [('mxcsr', 32)]
REGISTERS = CORE_REGISTERS + SSE_REGISTERS


def target_description():
    features = []
    for feature, registers in [('core', CORE_REGISTERS), ('sse', SSE_REGISTERS)]:
        fields = []
        for name, bits in registers:
            kind = 'i387_ext' if name.startswith('st') else 'uint128' if bits == 128 else 'int'
            if name == 'rip':
                kind = 'code_ptr'
            elif name in ('rsp', 'rbp'):
                kind = 'data_ptr'
            fields.append(f'<reg name="{name}" bitsize="{bits}" type="{kind}"/>')
        features.append(f'<feature name="org.gnu.gdb.i386.{feature}">' + ''.join(fields) + '</feature>')
    return ('<?xml version="1.0"?><!DOCTYPE target SYSTEM "gdb-target.dtd">'
            '<target><architecture>i386:x86-64</architecture>' + ''.join(features) + '</target>').encode()


TARGET_XML = target_description()


def frame(payload):
    wire = bytearray()
    for byte in payload:
        if byte in b'$#}*':
            wire.extend((ord('}'), byte ^ 0x20))
        else:
            wire.append(byte)
    return b'$' + wire + b'#' + f'{sum(wire) & 255:02x}'.encode()


def unescape(payload):
    result = bytearray()
    iterator = iter(payload)
    for byte in iterator:
        result.append(next(iterator) ^ 0x20 if byte == ord('}') else byte)
    return bytes(result)


class MemoryTarget:
    """Bounded, read-only protocol operations, independent of transport."""

    def __init__(self, memory, inspection_address=0):
        self.memory = memory
        self.inspection_address = inspection_address

    def dispatch(self, packet):
        if packet == b'qSupported' or packet.startswith(b'qSupported:'):
            return f'PacketSize={PACKET_SIZE:x};qXfer:features:read+;QStartNoAckMode+;swbreak-;hwbreak-'.encode()
        if packet == b'QStartNoAckMode':
            return b'OK'
        if packet.startswith(b'qXfer:features:read:target.xml:'):
            try:
                offset, size = (int(n, 16) for n in packet.rsplit(b':', 1)[1].split(b','))
                if offset < 0 or size <= 0:
                    return b'E22'
                data = TARGET_XML[offset:offset + min(size, MAX_READ)]
                return (b'l' if offset + len(data) >= len(TARGET_XML) else b'm') + data
            except ValueError:
                return b'E22'
        if packet == b'?':
            return b'T05thread:1;'
        if packet in (b'qAttached', b'qAttached:1'):
            return b'1'
        if packet == b'qC':
            return b'QC1'
        if packet == b'qfThreadInfo':
            return b'm1'
        if packet == b'qsThreadInfo':
            return b'l'
        if packet == b'qThreadExtraInfo,1':
            return b'Live memory view; synthetic PC; CPUs NOT stopped'.hex().encode()
        if packet in (b'Hg0', b'Hg1', b'Hg-1', b'Hc0', b'Hc1', b'Hc-1', b'T1'):
            return b'OK'
        # Do not implement qOffsets: GDB would overwrite the symbol-file -o
        # relocation already calculated by KernelSession (including with zero).
        if packet == b'qSymbol::':
            return b'OK'
        if packet == b'g':
            return b''.join(self.register(index) for index in range(len(REGISTERS)))
        if re.fullmatch(rb'p[0-9a-fA-F]+', packet):
            number = int(packet[1:], 16)
            return self.register(number) if number < len(REGISTERS) else b'E22'
        if packet.startswith(b'm'):
            match = re.fullmatch(rb'm([0-9a-fA-F]+),([0-9a-fA-F]+)', packet)
            if not match:
                return b'E22'
            address, size = (int(value, 16) for value in match.groups())
            if size > MAX_READ:
                return b'E22'
            try:
                return self.memory.read(address, size).hex().encode()
            except (MemoryReadError, OSError, ValueError) as exc:
                logger.debug('GDB memory read failed: %s', exc)
                return b'E14'
        if packet == b'D' or re.fullmatch(rb'D;[0-9a-fA-F]+', packet):
            return b'OK'
        if packet.startswith((b'M', b'X', b'G', b'P', b'Z', b'z', b'c', b'C', b's', b'S', b'vCont;', b'vKill', b'vRun', b'vAttach', b'R', b'k', b'!')):
            return b'E01'
        # Unknown feature probes must get an empty response, not OK.
        return b''

    def register(self, number):
        if REGISTERS[number][0] == 'rip':
            return self.inspection_address.to_bytes(8, 'little').hex().encode()
        return b'x' * (REGISTERS[number][1] // 4)


def serve(memory, reader, writer, inspection_address=0):
    """Serve one local GDB connection; no stdout diagnostics or network socket."""
    target = MemoryTarget(memory, inspection_address)
    ack = True
    last = b''

    def send(payload):
        nonlocal last
        last = frame(payload)
        writer.write(last)
        writer.flush()

    while True:
        byte = reader.read(1)
        if not byte:
            return
        if byte == b'-':
            if ack and last:
                writer.write(last)
                writer.flush()
            continue
        if byte == b'\x03':
            send(b'T05thread:1;')
            continue
        if byte != b'$':
            continue
        wire = bytearray()
        oversized = False
        while True:
            byte = reader.read(1)
            if not byte:
                return
            if byte == b'#':
                break
            if len(wire) < PACKET_SIZE:
                wire.extend(byte)
            else:
                oversized = True
        checksum = reader.read(2)
        if len(checksum) != 2:
            return
        try:
            valid = int(checksum, 16) == sum(wire) & 255
            packet = unescape(wire)
        except (ValueError, StopIteration):
            valid, packet = False, b''
        if not valid or oversized:
            if ack:
                writer.write(b'-')
                writer.flush()
                continue
            return
        if ack:
            writer.write(b'+')
            writer.flush()
        send(target.dispatch(packet))
        if packet == b'QStartNoAckMode':
            ack = False
        if packet == b'D' or re.fullmatch(rb'D;[0-9a-fA-F]+', packet):
            return


def inspection_memory(session):
    session.require_platform()
    memory = session.memory
    if memory.backend == 'lkm_mem' and not memory.fault_contained:
        raise UnavailableError('GDB inspection requires an updated helper with fault-contained reads')
    return memory


def serve_session(session):
    memory = inspection_memory(session)
    inspection_address = 0
    try:
        symbols = session.live_symbols
        start = symbols.get('_stext') or symbols.get('_text')
        if start and start.address:
            inspection_address = start.address
        else:
            inspection_address = min((s.address for s in symbols.values() if s.address >= 0xFFFF800000000000), default=0)
    except UnavailableError:
        pass
    print(f'lkmhunter: read-only live memory via {memory.backend}; CPUs keep running; '
          f'$pc={inspection_address:#x} is a synthetic inspection address, NOT CPU state', file=sys.stderr)
    # GDB handles terminal interrupts. This subprocess only handles its framed
    # protocol interrupt, which never stops CPUs or changes execution state.
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    serve(memory, sys.stdin.buffer, sys.stdout.buffer, inspection_address)


def write_symbol_elf(symbols, path):
    """Create an amd64 symbol-only ELF; memory always comes from the adapter.

    Allocated NOBITS sections give minimal symbols memory addresses (rather
    than absolute constants) without placing captured kernel bytes in the ELF.
    """
    symbols = [s for s in symbols.values() if 0xFFFF800000000000 <= s.address < (1 << 64)]
    if not symbols:
        raise UnavailableError('No nonzero kernel virtual addresses in kallsyms')
    # A broad text section spanning core and module code would overlap kernel
    # data and make GDB label data addresses as unrelated code symbols. Partition
    # the address-ordered symbols into non-overlapping code/data runs instead.
    ordered = sorted(symbols, key=lambda s: s.address)
    by_address = {}
    for symbol in ordered:
        by_address.setdefault(symbol.address, []).append(symbol)
    runs = []
    symbol_sections = {}
    for address, aliases in by_address.items():
        executable = any(s.kind in ('t', 'T', 'w', 'W') for s in aliases)
        if not runs or runs[-1]['executable'] != executable:
            if runs:
                runs[-1]['end'] = address
            runs.append({'start': address, 'end': address + 1, 'executable': executable})
        runs[-1]['end'] = max(runs[-1]['end'], address + max(max(1, s.size) for s in aliases))
        for symbol in aliases:
            symbol_sections[symbol.name] = len(runs)
    if len(runs) + 4 >= 0xff00:
        raise UnavailableError('Too many synthetic symbol sections for a regular ELF section table')
    strings = bytearray(b'\0')
    entries = bytearray(24)
    for symbol in symbols:
        name = symbol.name.encode('utf-8', errors='replace').replace(b'\0', b'')
        name_offset = len(strings)
        strings.extend(name + b'\0')
        function = symbol.kind in ('t', 'T', 'w', 'W')
        entries.extend(struct.pack('<IBBHQQ', name_offset, 0x12 if function else 0x11, 0,
                                   symbol_sections[symbol.name], symbol.address, symbol.size))
    names = [('.text' if run['executable'] else '.data') + f'.{index}' for index, run in enumerate(runs)]
    section_names = bytearray(b'\0')
    name_offsets = {}
    for name in [*names, '.symtab', '.strtab', '.shstrtab']:
        name_offsets[name] = len(section_names)
        section_names.extend(name.encode() + b'\0')
    content = bytearray(64)
    sym_offset = len(content)
    content.extend(entries)
    str_offset = len(content)
    content.extend(strings)
    names_offset = len(content)
    content.extend(section_names)
    content.extend(bytes((-len(content)) % 8))
    section_offset = len(content)
    sections = [(0, 0, 0, 0, 0, 0, 0, 0, 0, 0)]
    for name, run in zip(names, runs):
        sections.append((name_offsets[name], 8, 6 if run['executable'] else 3,
                         run['start'], 0, run['end'] - run['start'], 0, 0, 1, 0))
    sections.extend([
        (name_offsets['.symtab'], 2, 0, 0, sym_offset, len(entries), len(runs) + 2, 1, 8, 24),
        (name_offsets['.strtab'], 3, 0, 0, str_offset, len(strings), 0, 0, 1, 0),
        (name_offsets['.shstrtab'], 3, 0, 0, names_offset, len(section_names), 0, 0, 1, 0),
    ])
    for section in sections:
        content.extend(struct.pack('<IIQQQQIIQQ', *section))
    content[:64] = (b'\x7fELF\x02\x01\x01' + bytes(9) +
                    struct.pack('<HHIQQQIHHHHHH', 2, 62, 1, 0, 0, section_offset, 0, 64, 0, 0, 64, len(sections), len(sections) - 1))
    private_file(path, content)
    return len(symbols)


def private_file(path, data):
    # Exports contain runtime kernel addresses. Do not follow existing files
    # or expose their contents through a permissive umask.
    with Path(path).open('xb') as target:
        os.fchmod(target.fileno(), 0o600)
        target.write(data)


def quote_gdb_path(path):
    value = str(path)
    if any(c in value for c in '\r\n\0'):
        raise ValueError('GDB paths cannot contain newline or NUL characters')
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"') + '"'


def adapter_arguments(session):
    """Carry the same memory source into the local adapter subprocess."""
    arguments = ['--backend', session.backend]
    for flag, value in [('--kcore', session.kcore_path), ('--lkm-mem', session.lkm_mem_path),
                        ('--kallsyms', session.kallsyms_path)]:
        arguments.extend([flag, str(Path(value).resolve()) if value else str(value)])
    return arguments


def prepare_gdb(session, directory, mode='auto', server_arguments=None):
    """Write symbols and a local GDB command file; return the command-file path."""
    session.require_platform()
    if mode not in ('auto', 'vmlinux', 'kallsyms', 'none'):
        raise ValueError('Unknown GDB symbol mode')
    directory = Path(directory).resolve()
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    symbols = None
    offset = 0
    if mode in ('auto', 'vmlinux'):
        explicit = session.vmlinux_path is not None
        local = any(p.is_file() for p in session._image_candidates())
        if mode == 'vmlinux' or explicit or local:
            try:
                symbols = Path(session.baseline.path).resolve()
                if (session.baseline.elf.get_section_by_name('.symtab') is None
                        and session.baseline.elf.get_section_by_name('.debug_info') is None):
                    raise UnavailableError('vmlinux contains no symbol table or debug types')
                offset = session.kaslr_offset
                if not explicit and not any(p.resolve() == symbols for p in session._image_candidates()):
                    # Extracted boot images belong to the session's temporary
                    # directory. Keep a copy with the exported GDB session.
                    retained = directory / 'vmlinux'
                    if retained != symbols:
                        shutil.copyfile(symbols, retained)
                        symbols = retained
                print(f'lkmhunter: symbols from {symbols}; KASLR relocation {offset:#x}', file=sys.stderr)
            except HunterError as exc:
                if mode == 'vmlinux' or explicit:
                    raise
                print(f'lkmhunter: cannot use local vmlinux ({exc}); using kallsyms', file=sys.stderr)
                symbols = None
    if symbols is None and mode != 'none':
        symbols = directory / 'kallsyms.elf'
        count = write_symbol_elf(read_symbols(session.kallsyms_path, include_modules=True), symbols)
        print(f'lkmhunter: {count} runtime symbols from kallsyms; no C structure types', file=sys.stderr)
    if server_arguments is None:
        server_arguments = adapter_arguments(session)
    command = [sys.executable, '-m', 'lkmhunter', 'gdb-serve', *server_arguments]
    if any(any(c in str(arg) for c in '\r\n\0') for arg in command):
        raise ValueError('GDB adapter arguments cannot contain newline or NUL characters')
    lines = ['set pagination off', 'set auto-load off', 'set auto-solib-add off',
             'set remotetimeout 30',
             'set architecture i386:x86-64', 'set trust-readonly-sections off',
             'set stack-cache off', 'set code-cache off',
             'set may-write-memory off', 'set may-write-registers off',
             'set may-insert-breakpoints off', 'set may-insert-fast-tracepoints off']
    if symbols is not None:
        lines.append(f'symbol-file -o {offset:#x} {quote_gdb_path(symbols)}')
    lines.extend(['target remote | ' + shlex.join(command),
                  'echo Live read-only kernel memory. CPUs run; $pc is synthetic; other registers unavailable.\\n'])
    script = directory / 'session.gdb'
    private_file(script, ('\n'.join(lines) + '\n').encode())
    return script


def launch_gdb(session, *, mode='auto', server_arguments=None, export=None,
               binary='gdb', commands=(), batch=False):
    if export is None:
        memory = inspection_memory(session)
        if server_arguments is None:
            server_arguments = adapter_arguments(session)
        server_arguments = [*server_arguments, '--backend', memory.backend]
    def run(directory):
        script = prepare_gdb(session, directory, mode, server_arguments)
        if export is not None:
            print(f'GDB command file: {script}')
            print(f'Run locally: {shlex.join([binary, "-nx", "-q", "-x", str(script)])}')
            return 0
        args = [binary, '-nx', '-q', '-x', str(script)]
        if batch:
            args.append('-batch')
        for command in commands:
            args.extend(['-ex', command])
        process = subprocess.Popen(args)
        # Let interactive GDB handle Ctrl-C without the waiting Python launcher
        # tearing down its connection and temporary symbol files.
        try:
            previous = signal.signal(signal.SIGINT, signal.SIG_IGN)
        except ValueError:  # library caller outside the main thread
            previous = None
        try:
            return process.wait()
        finally:
            if previous is not None:
                signal.signal(signal.SIGINT, previous)
    if export is not None:
        Path(export).mkdir(mode=0o700, parents=True, exist_ok=False)
        return run(export)
    with tempfile.TemporaryDirectory(prefix='lkmhunter-gdb-') as directory:
        return run(directory)
