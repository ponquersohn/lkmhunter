"""Userspace helper for the lkm_mem kernel module (/proc/lkm/mem).

The module exposes two interfaces:
  * read()/write() with lseek -- simple but limited to addresses that fit
    in signed loff_t (fine for userspace, breaks on x86-64 kernel addresses
    whose top bit is set).
  * ioctl LKM_IOC_READ / LKM_IOC_WRITE with an explicit {addr, len, buf*}
    struct -- the kernel reads addr as unsigned __u64 directly, so it works
    for the full kernel address range.

This helper uses ioctl so any kernel address works. Usage:

    from lkm_mem import LkmMem
    m = LkmMem()                              # opens /proc/lkm/mem
    data = m.read(0xffffffffc0c12170, 0x40)   # 64 bytes from a module address
    m.write(0xffffffff82800460, b"...")       # bytes to that address
    m.close()
"""
import ctypes
import fcntl
import os
import struct


# ioctl numbers must match the kernel module. _IOW('L', N, struct lkm_mem_xfer):
#   dir=1 (write)  type='L'  nr=N  size=sizeof(struct) = 24
# Encoded as (dir << 30) | (size << 16) | (type << 8) | nr
_IOC_WRITE = 1
_XFER_SIZE = 24
_MAGIC = ord('L')
_LKM_IOC_READ  = (_IOC_WRITE << 30) | (_XFER_SIZE << 16) | (_MAGIC << 8) | 1
_LKM_IOC_WRITE = (_IOC_WRITE << 30) | (_XFER_SIZE << 16) | (_MAGIC << 8) | 2


class LkmMem:
    def __init__(self, path="/proc/lkm/mem"):
        self.fd = os.open(path, os.O_RDWR)

    def _xfer(self, cmd, addr, buf):
        """Issue one ioctl. `buf` is a ctypes array holding the bytes being
        transferred -- we pass its address to the kernel via struct lkm_mem_xfer
        and the kernel copy_{to,from}_user()s against it."""
        user_buf_addr = ctypes.addressof(buf)
        xfer = struct.pack("=QQQ", addr, len(buf), user_buf_addr)
        xfer_buf = ctypes.create_string_buffer(xfer, len(xfer))
        # fcntl.ioctl returns the result of the kernel ioctl handler. Our
        # handler returns the byte count on success and a negative errno on
        # failure (but fcntl.ioctl raises OSError before we see negatives,
        # so success returns the positive count directly).
        return fcntl.ioctl(self.fd, cmd, xfer_buf, True)

    def read(self, addr, n):
        """Read `n` bytes starting at kernel virtual address `addr`."""
        buf = (ctypes.c_ubyte * n)()
        got = self._xfer(_LKM_IOC_READ, addr, buf)
        return bytes(buf)[:got]

    def write(self, addr, data):
        """Write `data` bytes at kernel virtual address `addr`."""
        n = len(data)
        buf = (ctypes.c_ubyte * n)(*data)
        return self._xfer(_LKM_IOC_WRITE, addr, buf)

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


if __name__ == "__main__":
    # Minimal self-check: read first 64 bytes of sys_call_table and show each
    # entry as a kernel pointer. Every slot should resolve to a function in
    # kernel/module space.
    import sys
    sct = None
    with open("/proc/kallsyms") as f:
        for line in f:
            if " sys_call_table" in line:
                sct = int(line.split()[0], 16)
                break
    if sct is None:
        print("sys_call_table not visible in /proc/kallsyms (kptr_restrict?)",
              file=sys.stderr)
        sys.exit(1)

    with LkmMem() as m:
        data = m.read(sct, 64)
    print(f"sys_call_table @ {sct:#x}:")
    for i in range(0, len(data), 8):
        ptr = int.from_bytes(data[i:i+8], "little")
        print(f"  [{i//8:3}] {ptr:#018x}")
