"""Technique implementations depend on the session, never device/file offsets."""
import json
import logging
import re
import struct
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM
from elftools.common.exceptions import ELFError

from .errors import HunterError, MemoryReadError, UnavailableError
from .results import Finding, ScanResult, ScanStatus

logger = logging.getLogger(__name__)
MODULE_START = 0xFFFFFFFFC0000000
MODULE_END = 0xFFFFFFFFFF000000
PAGE_SIZE = 4096


class Scanner:
    technique = ""

    def _guard(self, session, operation):
        result = ScanResult(self.technique)
        try:
            session.require_platform()
            operation(result)
        except UnavailableError as exc:
            result.status = ScanStatus.UNAVAILABLE
            result.diagnostics.append(str(exc))
        except (HunterError, OSError, ELFError, ValueError) as exc:
            result.status = ScanStatus.PARTIAL if result.coverage.get("compared", 0) else ScanStatus.FAILED
            result.diagnostics.append(str(exc))
            logger.debug("Scan failed", exc_info=True)
        finally:
            result.diagnostics.extend(d for d in session.diagnostics if d not in result.diagnostics)
        return result


class SyscallScanner(Scanner):
    technique = "syscalls"

    def __init__(self, count=None):
        if count is not None and not 1 <= count <= 65536:
            raise ValueError("syscall count must be between 1 and 65536")
        self.count = count

    def scan(self, session):
        def run(result):
            count = session.syscall_count(self.count)
            offset = session.kaslr_offset
            baseline_address = session.baseline_symbols["sys_call_table"].address
            live_address = session.runtime_address("sys_call_table")
            if live_address != baseline_address + offset:
                raise UnavailableError("Runtime syscall table address disagrees with relocation")
            expected = session.baseline.read(baseline_address, count * 8)
            names = {}
            for symbol in session.baseline_symbols.values():
                if symbol.address and (symbol.name.startswith("__x64_sys_") or symbol.name.startswith("sys_")):
                    names.setdefault(symbol.address, symbol.name)
            result.coverage.update(total=count, compared=0, kaslr_offset=offset)
            memory = session.memory
            result.coverage["backend"] = memory.backend
            for number in range(count):
                original = int.from_bytes(expected[number * 8:number * 8 + 8], "little")
                actual = int.from_bytes(memory.read(live_address + number * 8, 8), "little")
                relocated = ((original + offset) & ((1 << 64) - 1)) if original else 0
                result.coverage["compared"] += 1
                if actual != relocated:
                    name = names.get(original, f"syscall_{number}")
                    result.findings.append(Finding("syscall_hook", f"Syscall {name} (#{number}) differs from baseline",
                                                   {"number": number, "name": name, "actual": actual,
                                                    "expected": relocated, "baseline": original}))
            self._scan_dispatcher(session, result, offset)
        return self._guard(session, run)

    def _scan_dispatcher(self, session, result, slide):
        # Alternatives/tracing legitimately patch text. Compare only decoded
        # baseline call/jump sites that transfer directly to syscall handlers.
        symbol = session.baseline_symbols.get("x64_sys_call")
        coverage = {"symbol": "x64_sys_call", "compared": 0}
        result.coverage["dispatcher"] = coverage
        if symbol is None:
            coverage["status"] = "not_present"
            return
        coverage["status"] = "incomplete"
        if not 0 < symbol.size <= 1024 * 1024:
            result.status = ScanStatus.PARTIAL
            result.diagnostics.append("Cannot bound x64_sys_call: missing or invalid ELF symbol size")
            return
        address = symbol.address + slide
        if session.runtime_address("x64_sys_call") != address:
            raise UnavailableError("Runtime x64_sys_call address disagrees with relocation")
        coverage.update(address=address, size=symbol.size,
                        method="baseline direct syscall call/jump targets")
        baseline = session.baseline.read(symbol.address, symbol.size)
        live = session.memory.read(address, symbol.size)
        handlers = {s.address: s.name for s in session.baseline_symbols.values()
                    if s.name.startswith("__x64_sys_") and s.address}
        decoder = Cs(CS_ARCH_X86, CS_MODE_64)
        decoder.detail = True
        decoded = 0
        for instruction in decoder.disasm(baseline, symbol.address):
            decoded += instruction.size
            if (instruction.mnemonic not in ("call", "jmp") or
                    len(instruction.operands) != 1 or
                    instruction.operands[0].type != X86_OP_IMM):
                continue
            target = instruction.operands[0].imm & ((1 << 64) - 1)
            if target not in handlers:
                continue
            coverage["compared"] += 1
            start = instruction.address - symbol.address
            actual_bytes = live[start:start + instruction.size]
            if actual_bytes == instruction.bytes:
                continue
            replacement = next(decoder.disasm(actual_bytes, address + start, count=1), None)
            actual_target = None
            if (replacement is not None and replacement.size == instruction.size and
                    replacement.mnemonic in ("call", "jmp") and
                    len(replacement.operands) == 1 and replacement.operands[0].type == X86_OP_IMM):
                actual_target = replacement.operands[0].imm & ((1 << 64) - 1)
            result.findings.append(Finding(
                "syscall_dispatch_hook",
                f"x64_sys_call transfer to {handlers[target]} differs from baseline",
                {"site": address + start, "offset": start, "name": handlers[target],
                 "expected": (target + slide) & ((1 << 64) - 1), "actual": actual_target,
                 "baseline_bytes": instruction.bytes.hex(), "actual_bytes": actual_bytes.hex(),
                 "actual_instruction": (f"{replacement.mnemonic} {replacement.op_str}"
                                        if replacement else None)}))
        coverage["decoded_bytes"] = decoded
        if decoded != symbol.size:
            result.status = ScanStatus.PARTIAL
            result.diagnostics.append("x64_sys_call baseline could not be fully decoded")
        elif not coverage["compared"]:
            result.status = ScanStatus.PARTIAL
            result.diagnostics.append("No direct syscall handler transfers identified in x64_sys_call")
        else:
            coverage["status"] = "complete"


LINE_RE = re.compile(
    r"^(?P<func>\S+)\s+\((?P<count>\d+)\)\s+(?P<flags>.*?)\s*"
    r"tramp:\s*(?P<tramp>\S+)(?:\s+\((?P<callback>[^)]+)\))?\s*(?:->(?P<resolved>\S+))?"
)


def module_address(value):
    try:
        address = int(value, 16) if value and value.startswith("0x") else 0
    except ValueError:
        return False
    return MODULE_START <= address < MODULE_END


class FtraceScanner(Scanner):
    technique = "ftrace"

    def __init__(self, min_group=3):
        if min_group < 1:
            raise ValueError("min_group must be positive")
        self.min_group = min_group

    def scan(self, session):
        def run(result):
            path = session.trace_path()
            hooks = []
            unparsed = 0
            with open(path) as source:
                for lineno, raw in enumerate(source, 1):
                    line = raw.rstrip("\n")
                    if not line.strip() or line.lstrip().startswith("#"):
                        continue
                    if re.match(r"^\s+direct(?:\([^)]*\))?-->", line):
                        if hooks:
                            hooks[-1]["raw"] += "\n" + line
                        else:
                            unparsed += 1
                        continue
                    match = LINE_RE.match(line)
                    if not match:
                        # Ordinary enabled entries may have no trampoline. They
                        # are valid observations, but not this heuristic's signal.
                        if re.fullmatch(r"\S+\s+\(\d+\)(?:\s+[A-Za-z!# ]*)?", line):
                            continue
                        unparsed += 1
                        logger.debug("Unparsed ftrace line %d: %r", lineno, line)
                        continue
                    hook = match.groupdict()
                    hook["raw"] = line
                    hooks.append(hook)
            groups = defaultdict(list)
            for hook in hooks:
                if module_address(hook["tramp"]) or module_address(hook["callback"]):
                    key = hook["callback"] or hook["resolved"] or hook["tramp"]
                    groups[key].append(hook)
            for key, members in sorted(groups.items()):
                # Duplicate lines do not increase the number of functions.
                if len({h["func"] for h in members}) >= self.min_group:
                    result.findings.append(Finding("ftrace_dispatcher", f"Shared module-space dispatcher {key} hooks {len({h['func'] for h in members})} functions",
                                                   {"dispatcher": key, "hooks": members, "heuristic": True}))
            result.coverage.update(path=str(path), parsed=len(hooks), unparsed=unparsed,
                                   min_group=self.min_group, method="module-space dispatcher grouping")
            if unparsed:
                result.status = ScanStatus.PARTIAL
                result.diagnostics.append(f"{unparsed} unrecognized ftrace lines; coverage is incomplete")
        return self._guard(session, run)


def field_value(blob, field):
    return int.from_bytes(blob[field.offset:field.offset + field.size], "little")


def validate_module(memory, layout, address, target):
    blob = memory.read(address, layout.size)
    state = field_value(blob, layout.state)
    if state not in layout.states:
        return None
    if layout.self_pointer is not None and field_value(blob, layout.self_pointer) != address:
        return None
    name_field = blob[layout.name.offset:layout.name.offset + layout.name.size]
    name, separator, _ = name_field.partition(b"\0")
    erased = not any(name_field)
    if not erased and (not separator or not re.fullmatch(rb"[A-Za-z0-9_]+", name)):
        return None
    next_ptr, prev_ptr = field_value(blob, layout.next), field_value(blob, layout.prev)
    # LIST_POISON includes a configurable POISON_POINTER_DELTA. Its low
    # offsets and common delta identify the pair without per-build constants.
    poisoned = (next_ptr & 0xFFF) == 0x100 and prev_ptr == next_ptr + 0x22
    # Poison values are evidence, not a requirement: list_del_init() leaves a
    # self-link, and a hidden module can preserve plausible list pointers.
    pointer_anomaly = not poisoned and not all(p >= 0xFFFF800000000000 and p % 8 == 0 for p in (next_ptr, prev_ptr))
    self_linked = next_ptr == prev_ptr == address + layout.next.offset
    regions = []
    for region in layout.regions:
        base, size = field_value(blob, region.base), field_value(blob, region.size)
        if size and (not MODULE_START <= base < MODULE_END or base + size > MODULE_END or size > 64 * 1024 * 1024):
            return None
        regions.append({"type": region.name, "base": base, "size": size,
                        "contains_target": bool(base and base <= target < base + size)})
    if not any(r["contains_target"] for r in regions):
        return None
    return {"struct_addr": address, "name": name.decode("ascii") if not erased else f"unknown_{address:x}", "state": layout.states[state],
            "list_next": next_ptr, "list_prev": prev_ptr,
            "name_erased": erased, "list_pointer_anomaly": pointer_anomaly,
            "hidden_from_module_list": poisoned or pointer_anomaly or self_linked,
            "mem": regions, "layout_source": layout.source}


class ModuleScanner(Scanner):
    technique = "module"

    def scan(self, session, address, *, max_back=16 * 1024 * 1024,
             chunk_size=2 * 1024 * 1024, direction="both"):
        if not MODULE_START <= address < MODULE_END:
            raise ValueError("target must be in x86-64 module address space")
        if max_back <= 0 or chunk_size <= 0 or chunk_size > 64 * 1024 * 1024:
            raise ValueError("search budget and chunk size must be positive; chunk size <= 64M")
        if direction not in ("both", "back", "forward"):
            raise ValueError("direction must be both, back, or forward")

        def run(result):
            layout = session.module_layout
            memory = session.memory
            if memory.backend == "lkm_mem" and not memory.fault_contained:
                raise UnavailableError("Loaded lkm_mem lacks fault-contained reads; rebuild and reload the updated helper before sparse searches")
            result.coverage.update(backend=memory.backend, layout_source=layout.source,
                                   bytes_read=0, unreadable_bytes=0, max_bytes_per_direction=max_back,
                                   direction=direction)
            tested = set()
            tail = b""
            previous_end = None

            def readable(start, size):
                try:
                    blob = memory.read(start, size)
                except MemoryReadError:
                    if size <= PAGE_SIZE:
                        boundary = (start // PAGE_SIZE + 1) * PAGE_SIZE
                        if boundary < start + size:
                            yield from readable(start, boundary - start)
                            yield from readable(boundary, start + size - boundary)
                            return
                        result.coverage["unreadable_bytes"] += size
                        return
                    # Page-aligned subdivisions preserve readable neighboring pages.
                    split = ((start + size // 2) // PAGE_SIZE) * PAGE_SIZE
                    if split <= start:
                        split = start + size // 2
                    yield from readable(start, split - start)
                    yield from readable(split, start + size - split)
                else:
                    result.coverage["bytes_read"] += size
                    yield start, blob

            def search(start, size):
                nonlocal tail, previous_end
                for cursor, blob in readable(start, size):
                    if previous_end != cursor:
                        tail = b""
                    combined = tail + blob
                    base = cursor - len(tail)
                    aligned = (-base) % 8
                    end = len(combined) - (len(combined) - aligned) % 8
                    for index, (region_base,) in enumerate(struct.iter_unpack("<Q", combined[aligned:end])):
                        if not MODULE_START <= region_base <= address or address - region_base >= 64 * 1024 * 1024:
                            continue
                        word_offset = aligned + index * 8
                        for region in layout.regions:
                            candidate = base + word_offset - region.base.offset
                            if candidate % 8 or candidate in tested or candidate < MODULE_START:
                                continue
                            if direction == "forward" and candidate < address:
                                continue
                            if direction == "back" and candidate > address:
                                continue
                            if not max(MODULE_START, address - max_back) <= candidate < min(MODULE_END, address + max_back):
                                continue
                            size_offset = word_offset + region.size.offset - region.base.offset
                            if not 0 <= size_offset <= len(combined) - region.size.size:
                                continue
                            size = int.from_bytes(combined[size_offset:size_offset + region.size.size], "little")
                            if not address - region_base < size <= 64 * 1024 * 1024:
                                continue
                            state_offset = candidate - base + layout.state.offset
                            if 0 <= state_offset <= len(combined) - layout.state.size:
                                state = int.from_bytes(combined[state_offset:state_offset + layout.state.size], "little")
                                if state not in layout.states:
                                    continue
                            tested.add(candidate)
                            try:
                                info = validate_module(memory, layout, candidate, address)
                            except MemoryReadError:
                                continue
                            if info:
                                return info
                    tail = combined[-layout.size:]
                    previous_end = cursor + len(blob)
                return None

            # Ascending reads inside each bounded window allow boundary overlap.
            # Include structure-size overlap between windows in either direction.
            back, forward = address, address
            back_limit = max(MODULE_START, address - max_back)
            forward_limit = min(MODULE_END, address + max_back)
            while ((direction != "forward" and back > back_limit) or
                   (direction != "back" and forward < forward_limit)):
                windows = []
                if direction != "forward" and back > back_limit:
                    start = max(back_limit, back - chunk_size)
                    windows.append((start, min(address, back + layout.size) - start))
                    back = start
                if direction != "back" and forward < forward_limit:
                    end = min(forward_limit, forward + chunk_size)
                    start = max(address, forward - layout.size)
                    windows.append((start, end - start))
                    forward = end
                for start, size in windows:
                    info = search(start, size)
                    if info:
                        result.findings.append(Finding("module_owner", f"Module {info['name']} owns {address:#x}", info,
                                                       suspicious=info["hidden_from_module_list"] or info["name_erased"]))
                        return
            result.coverage["candidates_checked"] = len(tested)
            result.diagnostics.append("No owning structure found within the bounded search; this does not establish absence")
            if result.coverage["unreadable_bytes"]:
                result.status = ScanStatus.PARTIAL
        return self._guard(session, run)


def dump_module(session, finding, out_dir):
    """Explicitly dump an owner finding; gaps are zero-filled and recorded."""
    if finding.kind != "module_owner":
        raise ValueError("dump_module requires a module_owner finding")
    info = finding.evidence
    name = info["name"]
    if not re.fullmatch(r"[A-Za-z0-9_]+", name):
        raise ValueError("Unsafe module name")
    output = Path(out_dir) / name
    output.mkdir(parents=True, exist_ok=True)
    manifest = dict(info, dumped_at=datetime.now(timezone.utc).isoformat(), files={}, gaps=[])
    memory = session.memory
    manifest["backend"] = memory.backend
    for region in info["mem"]:
        if not region["base"] or not region["size"]:
            continue
        if not 0 < region["size"] <= 64 * 1024 * 1024:
            raise ValueError("Refusing oversized region")
        if not re.fullmatch(r"[a-zA-Z0-9_]+", region["type"]):
            raise ValueError("Unsafe region name")
        filename = f"{name}.{region['type']}.bin"
        with (output / filename).open("xb") as target:
            offset = 0
            while offset < region["size"]:
                address = region["base"] + offset
                size = min(PAGE_SIZE - address % PAGE_SIZE, region["size"] - offset)
                try:
                    data = memory.read(address, size)
                except MemoryReadError as exc:
                    data = bytes(size)
                    manifest["gaps"].append({"region": region["type"], "address": address,
                                             "offset": offset, "size": size, "reason": str(exc)})
                target.write(data)
                offset += size
        manifest["files"][region["type"]] = filename
    manifest["complete"] = not manifest["gaps"]
    path = output / f"{name}.json"
    with path.open("x") as target:
        json.dump(manifest, target, indent=2)
    return path, manifest
