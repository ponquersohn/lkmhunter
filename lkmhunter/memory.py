"""Exact virtual-address reads; file offsets never escape this module."""
import ctypes
import fcntl
import os
import struct
from dataclasses import dataclass

from elftools.elf.elffile import ELFFile

from .errors import HunterError, MemoryReadError, MetadataError

MAX_ADDRESS = 1 << 64


def validate_read(address, size):
    if not isinstance(address, int) or not isinstance(size, int):
        raise ValueError("address and size must be integers")
    if address < 0 or size < 0 or address >= MAX_ADDRESS or address + size > MAX_ADDRESS:
        raise ValueError("read must fit in the unsigned 64-bit address space")


@dataclass(frozen=True)
class Segment:
    start: int
    size: int
    offset: int


class ElfMemory:
    backend = "elf"

    def __init__(self, path):
        self.path = str(path)
        self.file = open(path, "rb")
        try:
            self.elf = ELFFile(self.file)
            if self.elf.elfclass != 64 or not self.elf.little_endian or self.elf["e_machine"] != "EM_X86_64":
                raise MetadataError("Only little-endian x86-64 ELF images are supported")
            self.segments = sorted([
                Segment(s["p_vaddr"], s["p_filesz"], s["p_offset"])
                for s in self.elf.iter_segments() if s["p_type"] == "PT_LOAD" and s["p_filesz"]
            ], key=lambda s: s.start, reverse=True)
            if not self.segments:
                raise MetadataError(f"No file-backed load segments in {path}")
        except Exception:
            self.close()
            raise

    def read(self, address, size):
        validate_read(address, size)
        result = bytearray()
        cursor = address
        while len(result) < size:
            segment = next((s for s in self.segments if s.start <= cursor < s.start + s.size), None)
            if segment is None:
                raise MemoryReadError(cursor, size - len(result), "unmapped or not file-backed")
            count = min(size - len(result), segment.start + segment.size - cursor)
            try:
                data = os.pread(self.file.fileno(), count, segment.offset + cursor - segment.start)
            except OSError as exc:
                raise MemoryReadError(cursor, count, str(exc)) from exc
            if len(data) != count:
                raise MemoryReadError(cursor, count, f"short read: {len(data)} bytes")
            result.extend(data)
            cursor += count
        return bytes(result)

    def close(self):
        self.file.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class LkmMemory:
    """Read-only use of the helper's existing 24-byte transfer ioctl ABI."""
    backend = "lkm_mem"
    READ = (1 << 30) | (24 << 16) | (ord("L") << 8) | 1
    CAPS = (ord("L") << 8) | 3

    def __init__(self, path="/proc/lkm/mem"):
        self.path = str(path)
        self.fd = os.open(path, os.O_RDONLY)

    @property
    def fault_contained(self):
        try:
            return bool(fcntl.ioctl(self.fd, self.CAPS) & 1)
        except OSError:
            return False

    def read(self, address, size):
        validate_read(address, size)
        data = bytearray()
        while len(data) < size:
            count = min(size - len(data), 1024 * 1024)
            cursor = address + len(data)
            buf = (ctypes.c_ubyte * count)()
            transfer = bytearray(struct.pack("=QQQ", cursor, count, ctypes.addressof(buf)))
            try:
                got = fcntl.ioctl(self.fd, self.READ, transfer, True)
            except OSError as exc:
                raise MemoryReadError(cursor, count, str(exc)) from exc
            if got != count:
                raise MemoryReadError(cursor, count, f"short ioctl read: {got} bytes")
            data.extend(buf)
        return bytes(data)

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class LkmWriter(LkmMemory):
    """Explicit raw write access; scanners and GDB use LkmMemory instead."""

    WRITE = (1 << 30) | (24 << 16) | (ord('L') << 8) | 2

    def __init__(self, path='/proc/lkm/mem'):
        self.path = str(path)
        self.fd = os.open(path, os.O_RDWR)

    def write(self, address, data):
        validate_read(address, len(data))
        total = 0
        while total < len(data):
            block = data[total:total + 1024 * 1024]
            buf = (ctypes.c_ubyte * len(block)).from_buffer_copy(block)
            transfer = bytearray(struct.pack('=QQQ', address + total, len(block), ctypes.addressof(buf)))
            try:
                written = fcntl.ioctl(self.fd, self.WRITE, transfer, True)
            except OSError as exc:
                raise HunterError(f'write at {address + total:#x} failed after {total} bytes: {exc}') from exc
            if written != len(block):
                raise HunterError(f'short write at {address + total:#x}: {written}/{len(block)} bytes; '
                                  'live memory may already be modified')
            total += written
        return total
