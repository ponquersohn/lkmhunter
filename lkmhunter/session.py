"""Lazy ownership and discovery of resources used by hunting techniques."""
import logging
import os
import struct
import subprocess
import sys
import tempfile
from contextlib import ExitStack
from functools import cached_property
from pathlib import Path

from elftools.common.exceptions import ELFError

from .errors import MetadataError, UnavailableError
from .memory import ElfMemory, LkmMemory
from .metadata import ModuleLayout, TypeGraph
from .symbols import elf_symbols, read_symbols, relocation

logger = logging.getLogger(__name__)


def note_build_id(data):
    cursor = 0
    while cursor + 12 <= len(data):
        namesz, descsz, kind = struct.unpack_from("<III", data, cursor)
        cursor += 12
        if cursor + ((namesz + 3) & ~3) + descsz > len(data):
            break
        name = data[cursor:cursor + namesz].rstrip(b"\0")
        cursor += (namesz + 3) & ~3
        desc = data[cursor:cursor + descsz]
        cursor += (descsz + 3) & ~3
        if name == b"GNU" and kind == 3:
            return desc.hex()
    return None


class KernelSession:
    def __init__(self, *, backend="auto", kcore="/proc/kcore", lkm_mem="/proc/lkm/mem",
                 kallsyms="/proc/kallsyms", vmlinux=None, system_map=None,
                 btf="/sys/kernel/btf/vmlinux", layout=None, tracefs=None,
                 kernel_release=None, live_notes="/sys/kernel/notes"):
        if backend not in ("auto", "kcore", "lkm_mem"):
            raise ValueError("backend must be auto, kcore, or lkm_mem")
        self.backend = backend
        self.kcore_path, self.lkm_mem_path = kcore, lkm_mem
        self.kallsyms_path = kallsyms
        self.vmlinux_path, self.system_map_path = vmlinux, system_map
        self.btf_path, self.layout_path, self.tracefs_path = btf, layout, tracefs
        self.kernel_release = kernel_release or os.uname().release
        self.live_notes_path = live_notes
        self.diagnostics = []
        self._resources = ExitStack()
        self._closed = False
        self._baseline_build_id_verified = False

    @classmethod
    def open(cls, **kwargs):
        return cls(**kwargs)

    def _check_open(self):
        if self._closed:
            raise RuntimeError("KernelSession is closed")

    def require_platform(self):
        self._check_open()
        if sys.platform != "linux" or os.uname().machine != "x86_64":
            raise UnavailableError("Kernel scanners currently support Linux x86-64 only")

    def _record(self, message):
        self.diagnostics.append(message)
        logger.debug(message)

    @cached_property
    def memory(self):
        self._check_open()
        if self.backend in ("auto", "lkm_mem"):
            try:
                memory = LkmMemory(self.lkm_mem_path)
            except OSError as exc:
                if self.backend == "lkm_mem":
                    raise UnavailableError(f"Cannot open lkm_mem at {self.lkm_mem_path}: {exc}") from exc
                self._record(f"lkm_mem unavailable: {exc}; selecting kcore")
            else:
                self._resources.callback(memory.close)
                self._record(f"Memory backend: lkm_mem ({self.lkm_mem_path})")
                return memory
        try:
            memory = ElfMemory(self.kcore_path)
        except (OSError, ELFError) as exc:
            raise UnavailableError(f"Cannot open kcore at {self.kcore_path}: {exc}") from exc
        memory.backend = "kcore"
        self._resources.callback(memory.close)
        self._record(f"Memory backend: kcore ({self.kcore_path})")
        return memory

    @cached_property
    def live_symbols(self):
        self._check_open()
        try:
            symbols = read_symbols(self.kallsyms_path)
        except OSError as exc:
            raise UnavailableError(f"Cannot read live symbols: {exc}") from exc
        if not symbols or not any(s.address for s in symbols.values()):
            raise MetadataError("Live symbols are missing or zeroed; check kallsyms permissions/kptr_restrict")
        return symbols

    def _image_candidates(self):
        release = self.kernel_release
        return [Path(f"/usr/lib/debug/boot/vmlinux-{release}"),
                Path(f"/usr/lib/debug/lib/modules/{release}/vmlinux"),
                Path(f"/lib/modules/{release}/vmlinux"), Path(f"/boot/vmlinux-{release}")]

    def _extract_image(self):
        release = self.kernel_release
        boot = Path(f"/boot/vmlinuz-{release}")
        candidates = [Path(f"/lib/modules/{release}/build/scripts/extract-vmlinux"),
                      Path(f"/usr/src/linux-headers-{release}/scripts/extract-vmlinux")]
        extractor = next((p for p in candidates if p.is_file()), None)
        if not boot.is_file() or extractor is None:
            raise UnavailableError("No local baseline vmlinux or usable boot image/extract-vmlinux; supply --vmlinux")
        work = Path(self._resources.enter_context(tempfile.TemporaryDirectory(prefix="lkmhunter-")))
        output = work / "vmlinux"
        try:
            with output.open("wb") as target:
                subprocess.run(["sh", str(extractor), str(boot)], stdout=target,
                               stderr=subprocess.PIPE, check=True, timeout=60)
        except (OSError, subprocess.SubprocessError) as exc:
            raise UnavailableError(f"Cannot extract {boot}: {exc}") from exc
        self._record(f"Extracted local baseline {boot}")
        return output

    @cached_property
    def baseline(self):
        self._check_open()
        path = self.vmlinux_path
        if path is None:
            path = next((p for p in self._image_candidates() if p.is_file()), None)
        if path is None:
            path = self._extract_image()
        try:
            image = ElfMemory(path)
        except (OSError, ELFError) as exc:
            raise UnavailableError(f"Cannot open baseline {path}: {exc}") from exc
        self._resources.callback(image.close)
        self._record(f"Baseline image: {path}")
        # Match exact builds when both images expose GNU build IDs.
        baseline_id = None
        for segment in image.elf.iter_segments():
            if segment["p_type"] == "PT_NOTE":
                baseline_id = note_build_id(segment.data()) or baseline_id
        try:
            live_id = note_build_id(Path(self.live_notes_path).read_bytes()) if self.live_notes_path else None
        except OSError:
            live_id = None
        if live_id and baseline_id and live_id != baseline_id:
            raise MetadataError(f"Baseline build ID {baseline_id} differs from live kernel {live_id}")
        self._baseline_build_id_verified = bool(live_id and baseline_id)
        if not (live_id and baseline_id):
            self._record("Build ID unavailable; baseline identity requires consistent symbols and kernel release")
        return image

    @cached_property
    def baseline_symbols(self):
        symbols = elf_symbols(self.baseline.elf)
        map_path = self.system_map_path
        if map_path is None:
            candidate = Path(f"/boot/System.map-{self.kernel_release}")
            if candidate.is_file():
                map_path = candidate
        if map_path:
            try:
                mapped = read_symbols(map_path)
            except OSError as exc:
                raise MetadataError(f"Cannot read baseline System.map: {exc}") from exc
            for name, symbol in mapped.items():
                # Local C symbols can legitimately repeat their names at
                # different addresses. Only unique kernel anchors are suitable
                # for validating the map against the ELF symbol table.
                if name in ("_text", "_stext", "_etext", "init_task", "sys_call_table", "linux_banner") and name in symbols and symbol.address != symbols[name].address:
                    raise MetadataError(f"System.map disagrees with vmlinux for {name}")
                symbols.setdefault(name, symbol)
        if not symbols:
            raise MetadataError("No baseline symbols; supply matching --system-map or symbol-bearing --vmlinux")
        banner = symbols.get("linux_banner")
        if banner:
            # Read only the first line; kernels often place the banner near a segment edge.
            data = bytearray()
            for index in range(256):
                byte = self.baseline.read(banner.address + index, 1)
                if byte in (b"\0", b"\n"):
                    break
                data.extend(byte)
            fields = data.decode(errors="replace").split()
            if len(fields) >= 3 and fields[:2] == ["Linux", "version"] and fields[2] != self.kernel_release:
                raise MetadataError(f"Baseline release {fields[2]} differs from target {self.kernel_release}")
        return symbols

    @cached_property
    def kaslr_offset(self):
        self._check_open()
        offset, anchors = relocation(self.live_symbols, self.baseline_symbols)
        if len(anchors) < 2:
            raise MetadataError("At least two common relocation anchors are required to validate baseline matching")
        self._record(f"KASLR offset {offset:#x}; anchors: {', '.join(anchors)}")
        return offset

    def runtime_address(self, name):
        symbol = self.live_symbols.get(name)
        if symbol and symbol.address:
            return symbol.address
        symbol = self.baseline_symbols.get(name)
        if not symbol or not symbol.address:
            raise MetadataError(f"Cannot resolve runtime symbol {name}")
        return symbol.address + self.kaslr_offset

    @cached_property
    def btf(self):
        self._check_open()
        if not self.btf_path:
            raise MetadataError("Live BTF disabled")
        return TypeGraph.from_btf(self.btf_path)

    @cached_property
    def dwarf(self):
        self._check_open()
        # DWARF used for live layouts must belong to the same kernel.
        # A matching build ID is sufficient; type offsets do not need KASLR
        # or visible kallsyms when recovering from an already known address.
        baseline = self.baseline
        if not self._baseline_build_id_verified:
            self.kaslr_offset
        return TypeGraph.from_dwarf(baseline.elf, baseline.path)

    @cached_property
    def module_layout(self):
        self._check_open()
        # Explicit overrides take precedence so callers can work around unavailable
        # or filtered live metadata without changing their scanner.
        if self.layout_path:
            return ModuleLayout.from_file(self.layout_path)
        for provider in (lambda: self.btf, lambda: self.dwarf):
            try:
                layout = provider().module_layout()
            except UnavailableError as exc:
                self._record(str(exc))
            else:
                self._record(f"Module layout: {layout.source}")
                return layout
        raise MetadataError("No usable module layout; provide live BTF, matching DWARF, or --layout JSON")

    def syscall_count(self, override=None):
        symbol = self.baseline_symbols.get("sys_call_table")
        if not symbol:
            raise MetadataError("Baseline has no sys_call_table")
        derived = None
        if symbol.size:
            if symbol.size % 8:
                raise MetadataError("Baseline syscall table size is not a multiple of pointer size")
            derived = symbol.size // 8
            source = "ELF symbol size"
        else:
            source = "explicit count"
            for provider, description in ((lambda: self.btf, "live BTF"), (lambda: self.dwarf, "baseline DWARF")):
                try:
                    derived = provider().array_count("sys_call_table")
                except UnavailableError as exc:
                    self._record(str(exc))
                else:
                    source = description
                    break
        if override is not None:
            if derived and override != derived:
                raise MetadataError(f"Explicit syscall count {override} disagrees with metadata {derived}")
            derived = override
        if not derived or not 1 <= derived <= 65536:
            raise MetadataError("Cannot determine syscall table length; supply --syscall-count")
        self._record(f"Syscall count: {derived} ({source})")
        return derived

    def trace_path(self):
        self._check_open()
        if self.tracefs_path:
            path = Path(self.tracefs_path)
            return path / "enabled_functions" if path.is_dir() else path
        for path in (Path("/sys/kernel/tracing/enabled_functions"), Path("/sys/kernel/debug/tracing/enabled_functions")):
            if path.exists():
                return path
        raise UnavailableError("enabled_functions not found; mount tracefs or supply --tracefs")

    def close(self):
        if not self._closed:
            self._closed = True
            self._resources.close()

    def __enter__(self):
        self._check_open()
        return self

    def __exit__(self, *exc):
        self.close()
