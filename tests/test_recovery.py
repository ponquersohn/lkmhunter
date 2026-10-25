import shutil
import struct
import subprocess
from unittest.mock import patch

import pytest
from elftools.elf.elffile import ELFFile

from lkmhunter.cli import main, parser
from lkmhunter.errors import MetadataError, UnavailableError
from lkmhunter.recovery import decrypt_snapshot, locate_state, read_snapshot, recover_unhidekey


KEY = bytes.fromhex('bf6e344c7222e3f09753893330e2b55adf89a769c542cd532c5dde6b608782ee')
IV = bytes.fromhex('61023e5890745b1d2e67492b9005e2be')
CIPHERTEXT = bytes.fromhex('594d70ff71c4776d0f7755b3c3a14af8')


@pytest.fixture(params=['absolute', 'relative'])
def module_fixture(tmp_path, byte_memory, fake_session, request):
    if not shutil.which('gcc'):
        pytest.skip('gcc needed to produce a harmless ET_REL DWARF fixture')
    source = tmp_path / 'example.c'
    source.write_text('''
struct kv_data_st { unsigned char *buf; unsigned long buflen; };
struct kv_crypto_st { unsigned char iv[16]; unsigned char padding[40]; struct kv_data_st kv_data; };
struct kv_crypto_st *kvmgc_unhidekey;
extern void fill(void *, int);
extern void consume(void *);
void fh_ftrace_thunk(void) { }
void kv_crypto_engine_init(void) {
    static unsigned char key[32];
    fill(key, 32);
    consume(key);
}
''')
    path = tmp_path / 'example.o'
    flags = ['-fno-pic', '-fno-pie', '-mcmodel=kernel'] if request.param == 'absolute' else ['-fPIC']
    subprocess.run(['gcc', '-g', '-O0', *flags, '-c', str(source), '-o', str(path)], check=True)
    text_base, bss_base, pointer, buffer = (0xffffffffc0100000, 0xffffffffc0200000,
                                           0xffff888001000000, 0xffff888002000000)
    with path.open('rb') as handle:
        elf = ELFFile(handle)
        table = elf.get_section_by_name('.symtab')
        symbol = lambda name: table.get_symbol_by_name(name)[0]
        key = next(s for s in table.iter_symbols() if s.name.startswith('key.'))
        text = bytearray(elf.get_section_by_name('.text').data())
        relocation_section = elf.get_section_by_name('.rela.text')
        symbols = elf.get_section(relocation_section['sh_link'])
        for relocation in relocation_section.iter_relocations():
            target = symbols.get_symbol(relocation['r_info_sym'])
            if target['st_shndx'] != key['st_shndx']:
                continue
            value = bss_base + target['st_value'] + relocation['r_addend']
            if relocation['r_info_type'] == 2:
                value -= text_base + relocation['r_offset']
            elif relocation['r_info_type'] != 11:
                continue
            struct.pack_into('<I', text, relocation['r_offset'], value & 0xffffffff)
        state_address = bss_base + symbol('kvmgc_unhidekey')['st_value']
        key_address = bss_base + key['st_value']
        dispatcher = text_base + symbol('fh_ftrace_thunk')['st_value']
    obj = IV + bytes(40) + struct.pack('<QQ', buffer, len(CIPHERTEXT))
    memory = byte_memory({text_base: text, state_address: struct.pack('<Q', pointer),
                          key_address: KEY, pointer: obj, buffer: CIPHERTEXT})
    return path, fake_session(memory=memory), dispatcher, (text_base, bss_base, key_address, state_address)


def test_recover_from_relocated_module_and_dwarf(module_fixture):
    path, session, dispatcher, addresses = module_fixture
    with patch('lkmhunter.recovery.decrypt_snapshot', return_value=bytes.fromhex('4200262017107819') + bytes(8)) as decrypt:
        report = recover_unhidekey(session, path, dispatcher)
    decrypt.assert_called_once_with(KEY, IV, CIPHERTEXT)
    assert report['unhidekey'] == '1978101720260042'
    assert report['aes_key_address'] == hex(addresses[2])
    assert report['stable_snapshot'] is True
    assert report['credential_validated'] is False
    assert len(report['module_sha256']) == 64
    assert 'key' not in report


def test_reference_cross_check_rejects_mismatched_live_text(module_fixture):
    path, session, dispatcher, addresses = module_fixture
    session.memory.regions[addresses[0]] = bytes(len(session.memory.regions[addresses[0]]))
    with path.open('rb') as handle, pytest.raises(MetadataError):
        locate_state(ELFFile(handle), session.memory, dispatcher)


def test_changed_snapshot_refuses_decryption(module_fixture):
    path, session, dispatcher, _ = module_fixture
    with patch('lkmhunter.recovery.read_snapshot', side_effect=[('first',), ('second',)]), \
            patch('lkmhunter.recovery.decrypt_snapshot') as decrypt:
        with pytest.raises(UnavailableError, match='changed during reads'):
            recover_unhidekey(session, path, dispatcher)
    decrypt.assert_not_called()


@pytest.mark.parametrize('length', [0, 15, 4097, 1 << 63])
def test_invalid_ciphertext_length_never_reads_buffer(byte_memory, length):
    pointer, buffer, state, key = (0xffff888001000000, 0xffff888002000000,
                                   0xffffffffc0100000, 0xffffffffc0200000)
    memory = byte_memory({state: struct.pack('<Q', pointer),
                          pointer: IV + struct.pack('<QQ', buffer, length)})
    with pytest.raises(MetadataError, match='ciphertext'):
        read_snapshot(memory, key, state, {'iv': 0, 'kv_data': 16}, {'buf': 0, 'buflen': 8})
    assert not any(address == buffer for address, _ in memory.reads)


def test_offline_decryption_known_snapshot():
    if not shutil.which('openssl'):
        pytest.skip('openssl unavailable')
    plain = decrypt_snapshot(KEY, IV, CIPHERTEXT)
    assert plain == bytes.fromhex('4200262017107819') + bytes(8)


def test_missing_openssl_fails_before_memory_access():
    with patch('lkmhunter.recovery.shutil.which', return_value=None):
        with pytest.raises(UnavailableError, match='openssl'):
            decrypt_snapshot(KEY, IV, CIPHERTEXT)


def test_recovery_cli(module_fixture, capsys):
    path, session, dispatcher, _ = module_fixture
    argv = ['recover', 'kovid', '--module-elf', str(path), '--dispatcher', hex(dispatcher), '--json']
    assert parser().parse_args(argv).dispatcher == dispatcher
    with patch('lkmhunter.cli.KernelSession.open') as opening:
        opening.return_value.__enter__.return_value = session
        assert main(argv) == 0
    import json
    assert json.loads(capsys.readouterr().out)['unhidekey'] == '1978101720260042'


def test_invalid_elf_is_a_clear_failure(tmp_path, fake_session):
    path = tmp_path / 'bad.elf'
    path.write_bytes(b'not an ELF')
    with pytest.raises(MetadataError, match='Cannot read module ELF'):
        recover_unhidekey(fake_session(), path, 0xffffffffc0100000)


def test_openssl_timeout_is_a_clear_failure():
    with patch('lkmhunter.recovery.subprocess.run', side_effect=subprocess.TimeoutExpired('openssl', 10)):
        from lkmhunter.errors import HunterError
        with pytest.raises(HunterError, match='timed out'):
            decrypt_snapshot(KEY, IV, CIPHERTEXT)
