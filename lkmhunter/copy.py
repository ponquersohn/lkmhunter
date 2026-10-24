"""Explicit baseline-to-live byte copying, separate from detection."""
import hashlib
import json
import os

from .errors import HunterError
from .memory import LkmWriter, validate_read


def copy_from_vmlinux(session, address, size, *, backup=None):
    """Copy bytes at address-slide in vmlinux to a live virtual address.

    The payload is verbatim: embedded absolute pointers are not relocated.
    Writes use the helper directly, regardless of the session's read backend.
    """
    session.require_platform()
    if size <= 0:
        raise ValueError('Copy size must be positive')
    validate_read(address, size)
    slide = session.kaslr_offset
    source = address - slide
    validate_read(source, size)
    payload = session.baseline.read(source, size)
    report = {'address': address, 'source_address': source, 'size': size,
              'kaslr_offset': slide, 'backend': 'lkm_mem',
              'source': session.baseline.path,
              'sha256': hashlib.sha256(payload).hexdigest(), 'verified': False}
    with LkmWriter(session.lkm_mem_path) as memory:
        before = memory.read(address, size)
        report['previous_sha256'] = hashlib.sha256(before).hexdigest()
        if backup is not None:
            # Exclusive creation, private permissions, durable before writing.
            fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w') as handle:
                json.dump({**report, 'previous_bytes': before.hex(),
                           'replacement_bytes': payload.hex()}, handle, indent=2)
                handle.flush()
                os.fsync(handle.fileno())
        if memory.write(address, payload) != size:
            raise HunterError('Copy write was incomplete; live memory may already be modified')
        if memory.read(address, size) != payload:
            raise HunterError('Copy readback mismatch; live memory has been modified')
    report['verified'] = True
    return report
