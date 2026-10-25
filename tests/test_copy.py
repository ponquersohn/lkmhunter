import json
from unittest.mock import patch

import pytest

from lkmhunter.cli import main, parser
from lkmhunter.copy import copy_from_vmlinux
from lkmhunter.errors import HunterError, MemoryReadError


@pytest.fixture
def copy_fixture(byte_memory, fake_session):
    source, slide = 0xffffffff81000000, 0x200000
    baseline = byte_memory({source: b'\x90\xc3\xcc'})
    baseline.path = '/baseline'
    session = fake_session(baseline=baseline, kaslr_offset=slide, lkm_mem_path='/helper')
    return session, source + slide


def test_copy_uses_relocated_source_exact_length_and_durable_backup(copy_fixture, tmp_path):
    session, address = copy_fixture
    backup = tmp_path / 'backup.json'
    with patch('lkmhunter.copy.LkmWriter') as writer:
        memory = writer.return_value.__enter__.return_value
        memory.read.side_effect = [b'AB', b'\x90\xc3']
        memory.write.return_value = 2
        report = copy_from_vmlinux(session, address, 2, backup=backup)
    writer.assert_called_once_with('/helper')
    memory.write.assert_called_once_with(address, b'\x90\xc3')
    assert report['verified']
    assert session.baseline.reads == [(address - session.kaslr_offset, 2)]
    saved = json.loads(backup.read_text())
    assert saved['previous_bytes'] == b'AB'.hex()
    assert saved['replacement_bytes'] == '90c3'
    assert backup.stat().st_mode & 0o777 == 0o600


def test_copy_unmapped_source_never_writes(copy_fixture):
    session, address = copy_fixture
    with patch('lkmhunter.copy.LkmWriter') as writer:
        with pytest.raises(MemoryReadError):
            copy_from_vmlinux(session, address, 4)
        writer.return_value.__enter__.return_value.write.assert_not_called()


def test_copy_existing_backup_prevents_write(copy_fixture, tmp_path):
    session, address = copy_fixture
    backup = tmp_path / 'existing'
    backup.write_text('keep')
    with patch('lkmhunter.copy.LkmWriter') as writer:
        memory = writer.return_value.__enter__.return_value
        memory.read.return_value = b'AB'
        with pytest.raises(FileExistsError):
            copy_from_vmlinux(session, address, 2, backup=backup)
        memory.write.assert_not_called()
    assert backup.read_text() == 'keep'


@pytest.mark.parametrize('written,readback', [(1, b'\x90\xc3'), (2, b'AB')])
def test_copy_partial_write_or_readback_mismatch_fails(copy_fixture, written, readback):
    session, address = copy_fixture
    with patch('lkmhunter.copy.LkmWriter') as writer:
        memory = writer.return_value.__enter__.return_value
        memory.read.side_effect = [b'AB', readback]
        memory.write.return_value = written
        with pytest.raises(HunterError):
            copy_from_vmlinux(session, address, 2)


def test_copy_cli_and_json(copy_fixture, capsys):
    session, address = copy_fixture
    args = parser().parse_args(['copy', hex(address), '4K'])
    assert args.size == 4096
    with patch('lkmhunter.cli.KernelSession.open') as opening, patch('lkmhunter.copy.copy_from_vmlinux') as copy:
        opening.return_value.__enter__.return_value = session
        copy.return_value = {'verified': True}
        assert main(['copy', hex(address), '2', '--json']) == 0
        copy.assert_called_once_with(session, address, 2, backup=None)
    assert json.loads(capsys.readouterr().out)['verified']
    assert main(['copy', hex(address), '2', '--backend', 'kcore']) == 2


def test_copy_missing_helper_fails_before_loading_baseline(copy_fixture):
    session, address = copy_fixture
    with patch('lkmhunter.copy.LkmWriter', side_effect=FileNotFoundError('/helper')):
        with pytest.raises(HunterError, match='Load the lkm_mem helper module first'):
            copy_from_vmlinux(session, address, 2)
    assert session.baseline.reads == []


def test_copy_unavailable_writer_does_not_resolve_lazy_symbols():
    from unittest.mock import Mock, PropertyMock
    session = Mock(lkm_mem_path='/missing-helper')
    with patch.object(type(session), 'kaslr_offset', new_callable=PropertyMock,
                      create=True) as slide, patch('lkmhunter.copy.LkmWriter',
                                                   side_effect=PermissionError('/missing-helper')):
        with pytest.raises(PermissionError):
            copy_from_vmlinux(session, 0xffffffff81000000, 5)
        slide.assert_not_called()
    session.require_platform.assert_called_once_with()
