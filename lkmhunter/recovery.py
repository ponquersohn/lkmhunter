"""Read-only recovery of the lab KoviD unhide value from its runtime AES state."""
import hashlib
from io import BytesIO
import shutil
import struct
import subprocess

from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import ELFError

from .errors import HunterError, MetadataError, UnavailableError
from .memory import validate_read


def _symbol(elf, name):
    table = elf.get_section_by_name('.symtab')
    matches = table.get_symbol_by_name(name) if table else None
    if not matches or len(matches) != 1 or not isinstance(matches[0]['st_shndx'], int):
        raise MetadataError(f'Exact unstripped module ELF required: missing/ambiguous {name}')
    return matches[0]


def _crypto_layouts(elf):
    if not elf.has_dwarf_info():
        raise MetadataError('Module ELF needs DWARF debug information for crypto object layout')
    layouts = {}
    names = {'kv_crypto_st', 'kv_data_st'}
    for cu in elf.get_dwarf_info().iter_CUs():
        for die in cu.iter_DIEs():
            attr = die.attributes.get('DW_AT_name')
            if die.tag != 'DW_TAG_structure_type' or not attr or attr.value.decode() not in names:
                continue
            members = {}
            for child in die.iter_children():
                if child.tag != 'DW_TAG_member':
                    continue
                label = child.attributes.get('DW_AT_name')
                offset = child.attributes.get('DW_AT_data_member_location')
                if label and offset and isinstance(offset.value, int):
                    members[label.value.decode()] = offset.value
            if members:
                layouts[attr.value.decode()] = members
                if layouts.keys() == names:
                    return layouts['kv_crypto_st'], layouts['kv_data_st']
    raise MetadataError('Missing DWARF crypto object layouts')


def locate_state(elf, memory, dispatcher):
    """Recover .bss from relocated references to the static AES key in .text."""
    thunk = _symbol(elf, 'fh_ftrace_thunk')
    text = elf.get_section(thunk['st_shndx'])
    if text.name != '.text':
        raise MetadataError('Unsupported dispatcher section; expected .text')
    text_base = dispatcher - thunk['st_value']
    init = _symbol(elf, 'kv_crypto_engine_init')
    state = _symbol(elf, 'kvmgc_unhidekey')
    if init['st_shndx'] != thunk['st_shndx'] or not init['st_size']:
        raise MetadataError('Unsupported crypto initialization function layout')
    table = elf.get_section_by_name('.symtab')
    keys = [s for s in table.iter_symbols()
            if (s.name == 'key' or s.name.startswith('key.')) and s['st_size'] == 32
            and s['st_shndx'] == state['st_shndx']]
    if len(keys) != 1 or elf.get_section(state['st_shndx']).name != '.bss':
        raise MetadataError('Expected one 32-byte static AES key in the state .bss section')
    key = keys[0]
    bases = set()
    references = 0
    for section in elf.iter_sections():
        if section['sh_type'] != 'SHT_RELA' or section['sh_info'] != thunk['st_shndx']:
            continue
        symbols = elf.get_section(section['sh_link'])
        for relocation in section.iter_relocations():
            offset = relocation['r_offset']
            if not init['st_value'] <= offset < init['st_value'] + init['st_size'] - 3:
                continue
            target = symbols.get_symbol(relocation['r_info_sym'])
            if target['st_shndx'] != key['st_shndx']:
                continue
            kind = relocation['r_info_type']
            # R_X86_64_PC32 includes the -4 addend for a RIP-relative operand;
            # R_X86_64_32S holds an absolute sign-extended kernel address.
            if kind not in (2, 11):
                continue
            effective = target['st_value'] + relocation['r_addend'] + (4 if kind == 2 else 0)
            if effective != key['st_value']:
                continue
            site = text_base + offset
            value = struct.unpack('<i', memory.read(site, 4))[0]
            key_address = (site + 4 + value if kind == 2 else value) & ((1 << 64) - 1)
            bases.add(key_address - key['st_value'])
            references += 1
    if len(bases) != 1 or references < 2:
        raise MetadataError('Cannot cross-check runtime .bss from at least two AES-key references; '
                            'check exact module ELF and dispatcher address')
    bss_base = bases.pop()
    key_address = bss_base + key['st_value']
    state_address = bss_base + state['st_value']
    for address in (text_base, key_address, state_address):
        if address < 0xffff800000000000:
            raise MetadataError('Derived address is outside x86-64 kernel space')
        validate_read(address, 32)
    return text_base, bss_base, key_address, state_address


def read_snapshot(memory, key_address, state_address, layout, data_layout):
    pointer_bytes = memory.read(state_address, 8)
    pointer = int.from_bytes(pointer_bytes, 'little')
    if pointer < 0xffff800000000000:
        raise MetadataError('Invalid live crypto object pointer')
    data_offset = layout['kv_data']
    size = max(layout['iv'] + 16, data_offset + data_layout['buf'] + 8,
               data_offset + data_layout['buflen'] + 8)
    if size > 4096:
        raise MetadataError('Unexpected crypto object layout')
    obj = memory.read(pointer, size)
    def field(offset):
        return int.from_bytes(obj[offset:offset + 8], 'little')
    buffer = field(data_offset + data_layout['buf'])
    length = field(data_offset + data_layout['buflen'])
    if buffer < 0xffff800000000000 or not 16 <= length <= 4096 or length % 16:
        raise MetadataError('Invalid ciphertext pointer/length; unsupported or changing module state')
    return (pointer_bytes, obj, memory.read(key_address, 32),
            obj[layout['iv']:layout['iv'] + 16], memory.read(buffer, length))


def decrypt_snapshot(key, iv, ciphertext):
    executable = shutil.which('openssl')
    if not executable:
        raise UnavailableError('KoviD recovery requires the openssl executable for offline AES decryption')
    try:
        result = subprocess.run([executable, 'enc', '-d', '-aes-256-cbc', '-nopad',
                                 '-K', key.hex(), '-iv', iv.hex()], input=ciphertext,
                                capture_output=True, timeout=10)
    except subprocess.TimeoutExpired as exc:
        raise HunterError('Offline AES decryption timed out') from exc
    if result.returncode or len(result.stdout) != len(ciphertext):
        raise HunterError('Offline AES-256-CBC decryption failed')
    return result.stdout


def recover_unhidekey(session, module_elf, dispatcher):
    """Snapshot twice, then decrypt offline. Never invoke module/kernel functions."""
    session.require_platform()
    if not shutil.which('openssl'):
        raise UnavailableError('KoviD recovery requires the openssl executable')
    with open(module_elf, 'rb') as source:
        # DWARF makes many small seeks; snapshot the ELF once, particularly on
        # the testbed's shared filesystem. Hash the same bytes we interpret.
        image = source.read()
        try:
            elf = ELFFile(BytesIO(image))
        except ELFError as exc:
            raise MetadataError(f'Cannot read module ELF: {exc}') from exc
        if (elf.elfclass != 64 or not elf.little_endian or elf['e_machine'] != 'EM_X86_64'
                or elf['e_type'] != 'ET_REL'):
            raise MetadataError('Expected an unstripped little-endian x86-64 module ELF')
        try:
            layout, data_layout = _crypto_layouts(elf)
            if not {'iv', 'kv_data'} <= layout.keys() or not {'buf', 'buflen'} <= data_layout.keys():
                raise MetadataError('Required crypto object members are missing')
            memory = session.memory
            text, bss, key, state = locate_state(elf, memory, dispatcher)
            snapshot = read_snapshot(memory, key, state, layout, data_layout)
            if snapshot != read_snapshot(memory, key, state, layout, data_layout):
                raise UnavailableError('Crypto state changed during reads; retry on a quiescent lab guest')
            digest = hashlib.sha256(image)
        except KeyError as exc:
            raise MetadataError(f'Unsupported KoviD metadata: {exc}') from exc
    plain = decrypt_snapshot(*snapshot[2:])
    return {'unhidekey': f'{int.from_bytes(plain[:8], "little"):016x}',
            'dispatcher': hex(dispatcher), 'text_base': hex(text), 'bss_base': hex(bss),
            'aes_key_address': hex(key), 'crypto_pointer_address': hex(state),
            'crypto_object': hex(int.from_bytes(snapshot[0], 'little')),
            'ciphertext_size': len(snapshot[4]), 'backend': memory.backend,
            'module_elf': str(module_elf), 'module_sha256': digest.hexdigest(),
            'stable_snapshot': True, 'credential_validated': False}
