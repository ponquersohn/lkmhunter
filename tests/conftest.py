import struct
from types import SimpleNamespace

import pytest

from lkmhunter.errors import MemoryReadError


def pytest_addoption(parser):
    parser.addoption('--live-kernel', action='store_true', help='Run read-only integration checks in a disposable VM')


def pytest_collection_modifyitems(config, items):
    if not config.getoption('--live-kernel'):
        for item in items:
            if 'integration' in item.keywords:
                item.add_marker(pytest.mark.skip(reason='requires --live-kernel in a disposable VM'))


@pytest.fixture
def elf_factory(tmp_path):
    def create(segments, *, mem_sizes=None, segment_types=None):
        # Minimal x86-64 ELF with program headers and no sections.
        ident = b'\x7fELF\x02\x01\x01' + bytes(9)
        header = ident + struct.pack('<HHIQQQIHHHHHH', 2, 62, 1, 0, 64, 0, 0, 64, 56, len(segments), 64, 0, 0)
        payload = bytearray(header + bytes(56 * len(segments)))
        for index, (address, data) in enumerate(segments):
            offset = len(payload)
            phdr = struct.pack('<IIQQQQQQ', segment_types[index] if segment_types else 1, 4, offset, address, 0, len(data),
                               mem_sizes[index] if mem_sizes else len(data), 1)
            payload[64 + index * 56:64 + (index + 1) * 56] = phdr
            payload.extend(data)
        path = tmp_path / f'image-{len(list(tmp_path.iterdir()))}.elf'
        path.write_bytes(payload)
        return path
    return create


class ByteMemory:
    backend = 'fixture'

    def __init__(self, regions):
        self.regions = regions
        self.reads = []

    def read(self, address, size):
        self.reads.append((address, size))
        for start, data in self.regions.items():
            if start <= address and address + size <= start + len(data):
                return bytes(data[address - start:address - start + size])
        raise MemoryReadError(address, size, 'fixture gap')


@pytest.fixture
def byte_memory():
    return ByteMemory


@pytest.fixture
def fake_session():
    def make(**kwargs):
        return SimpleNamespace(diagnostics=[], require_platform=lambda: None, **kwargs)
    return make
