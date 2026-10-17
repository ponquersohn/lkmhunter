"""Compatibility helper. New read-only callers should use KernelSession.memory.

The legacy write operation remains explicit and retains its ioctl ABI.
"""
import ctypes
import fcntl
import os
import struct

from lkmhunter.memory import LkmMemory, validate_read


class LkmMem(LkmMemory):
    WRITE = (1 << 30) | (24 << 16) | (ord('L') << 8) | 2

    def __init__(self, path='/proc/lkm/mem'):
        self.path = str(path)
        self.fd = os.open(path, os.O_RDWR)

    def write(self, address, data):
        validate_read(address, len(data))
        if not data:
            return 0
        buf = (ctypes.c_ubyte * len(data))(*data)
        transfer = bytearray(struct.pack('=QQQ', address, len(data), ctypes.addressof(buf)))
        return fcntl.ioctl(self.fd, self.WRITE, transfer, True)
