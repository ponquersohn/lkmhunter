"""Errors callers can handle without parsing command output."""


class HunterError(Exception):
    pass


class UnavailableError(HunterError):
    """A required resource or capability is missing."""


class MemoryReadError(HunterError):
    def __init__(self, address, size, reason):
        self.address, self.size = address, size
        super().__init__(f"read [{address:#x}, {address + size:#x}): {reason}")


class MetadataError(UnavailableError):
    """Required metadata is missing, inconsistent, or unsupported."""
