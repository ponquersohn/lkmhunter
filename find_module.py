"""Given a bare kernel code/data address (e.g. the shared ftrace dispatcher
address ftrace_hunt.py reports), find the owning struct module in memory and
dump its regions to disk for offline analysis.

Why this exists: a rootkit that unlinks itself from the global `modules` list
and /sys/module (Singularity does both) is invisible to `lsmod` and to
find_rootkits.sh's /sys-vs-lsmod diff. But its code still has to live
somewhere in module address space, and anything that calls into it — like the
ftrace dispatcher ftrace_hunt.py finds — points straight at that memory. This
walks from that one address back to the struct module describing it, then
dumps every memory region (.text, .data, .rodata, ...) so you can `strings`,
`objdump -D`, or diff it against a candidate rootkit's own .ko build.

IMPORTANT caveat verified against this kernel (7.3.0-9, via gdb ptype against
the dbgsym vmlinux — see testbed/README.md "Tuning the target" / fetch-symbols):
since Linux ~6.4, a module's `struct module mem[7]` array holds one SEPARATE
allocation per section type (.text, .data, ...) — they are NOT one contiguous
blob the way older kernels laid modules out. So struct module does not sit at
a fixed byte distance "before" a .text address; this script does not assume
adjacency. Instead it scans backward through memory for the structural shape
of struct module itself (state + list_head + name) and only accepts a match
once it's VERIFIED: the candidate's own mem[MOD_TEXT] range must actually
contain the address you gave it. That verification is what makes a match
trustworthy rather than a coincidental byte pattern.

The exact field offsets below are THIS KERNEL's layout (ground-truthed via
gdb, not guessed). Re-derive with:
    gdb -q -batch -ex "ptype /o struct module" -ex "ptype /o struct module_memory" \
        -ex "ptype enum mod_mem_type" testbed/symbols/vmlinux
before trusting this against a different kernel build — pass the new offsets
via --offsets if they differ.

Usage (run as root; needs /proc/kcore + /proc/kallsyms):
    sudo python3 find_module.py 0xffffffffc0c12170
    sudo python3 find_module.py 0xffffffffc0c12170 --max-back 32M --debug
    sudo python3 find_module.py 0xffffffffc0c12170 --out-dir dumps/singularity
"""
import argparse
import json
import logging
import os
import re
import sys
import time

from kernel import KernelImage

logger = logging.getLogger("find_module")

MODULES_VADDR = 0xFFFFFFFFC0000000
MODULES_END = 0xFFFFFFFFFF000000  # generous upper bound on x86-64 module space

# --- struct module layout for kernel 7.3.0-9-generic (gdb-verified) --------
MOD_STATE_OFF = 0
MOD_LIST_OFF = 8          # list_head: next@+0, prev@+8 (relative to MOD_LIST_OFF)
MOD_NAME_OFF = 24
MOD_NAME_LEN = 56
MOD_STRUCT_SIZE = 1280
MOD_MEM_OFF = 320         # struct module_memory mem[7]
MOD_MEM_ENTRY_SIZE = 72   # base@+0 (8), is_rox@+8 (1)+pad, size@+12 (4)
MOD_MEM_COUNT = 7
MEM_TYPE_NAMES = [
    "text", "data", "rodata", "ro_after_init",
    "init_text", "init_data", "init_rodata",
]
MODULE_STATES = ["LIVE", "COMING", "GOING", "UNFORMED"]

# list_del() leaves a poisoned next/prev on kernels without CONFIG_DEBUG_LIST
# (the Ubuntu default). A module whose own .list node shows these values
# unlinked itself from the global `modules` list — i.e. it is hiding from
# lsmod/proc/modules by exactly the technique find_rootkits.sh's /sys-vs-lsmod
# diff is built to catch when a /sys/module trace is left behind, and that a
# self-hiding rootkit (Singularity) specifically avoids leaving.
LIST_POISON1 = 0x100
LIST_POISON2 = 0x122

NAME_RE = re.compile(rb"[A-Za-z0-9_]{1,%d}" % MOD_NAME_LEN)


def parse_addr(s):
    return int(s, 16) if s.lower().startswith("0x") else int(s, 16)


class SegmentReader:
    """Bounded virtual->physical reads against /proc/kcore.

    KernelImage.to_physical() (kernel.py) only checks the lower bound of a
    segment, not the upper one — fine for its original use (resolving a
    handful of known symbols) but not safe for a backward scan across
    megabytes, which can walk past a segment's end into the next one and
    silently compute a wrong physical offset. This re-checks both bounds.
    """

    def __init__(self, image: KernelImage):
        self.image = image
        # (virtual_start, virtual_end, physical_start) tuples, descending.
        self._ranges = []
        for vaddr, seg in image.segments.items():
            self._ranges.append((vaddr, vaddr + seg.memory_size, seg.offset))
        self._ranges.sort(reverse=True)

    def _phys(self, vaddr, length):
        for start, end, phys_start in self._ranges:
            if start <= vaddr and vaddr + length <= end:
                return phys_start + (vaddr - start)
        return None

    def read(self, vaddr, length):
        phys = self._phys(vaddr, length)
        if phys is None:
            return None
        self.image.image.seek(phys)
        data = self.image.image.read(length)
        return data if len(data) == length else None


def looks_like_kernel_or_poison_ptr(val):
    if val in (LIST_POISON1, LIST_POISON2):
        return True, "poisoned (list_del'd / hidden)"
    if val >= 0xFFFF800000000000:
        return True, "kernel pointer"
    return False, "implausible"


def validate_candidate(reader: SegmentReader, struct_addr, target_addr):
    """Read MOD_STRUCT_SIZE bytes at struct_addr and check it is really the
    struct module that owns target_addr. Returns a dict of findings or None."""
    blob = reader.read(struct_addr, MOD_STRUCT_SIZE)
    if blob is None:
        return None

    state = int.from_bytes(blob[MOD_STATE_OFF:MOD_STATE_OFF + 4], "little")
    if state > 3:
        return None

    name_field = blob[MOD_NAME_OFF:MOD_NAME_OFF + MOD_NAME_LEN]
    nul = name_field.find(b"\x00")
    if nul <= 0:
        return None
    name_bytes = name_field[:nul]
    if not NAME_RE.fullmatch(name_bytes):
        return None
    if any(b != 0 for b in name_field[nul:]):
        return None  # not fully NUL-padded -> not really a fixed-size name field
    name = name_bytes.decode("ascii")

    list_next = int.from_bytes(blob[MOD_LIST_OFF:MOD_LIST_OFF + 8], "little")
    list_prev = int.from_bytes(blob[MOD_LIST_OFF + 8:MOD_LIST_OFF + 16], "little")
    next_ok, next_desc = looks_like_kernel_or_poison_ptr(list_next)
    prev_ok, prev_desc = looks_like_kernel_or_poison_ptr(list_prev)
    if not (next_ok and prev_ok):
        return None

    mem_regions = []
    found_target = False
    for i in range(MOD_MEM_COUNT):
        off = MOD_MEM_OFF + i * MOD_MEM_ENTRY_SIZE
        base = int.from_bytes(blob[off:off + 8], "little")
        size = int.from_bytes(blob[off + 12:off + 16], "little")
        contains_target = base != 0 and base <= target_addr < base + size
        if contains_target:
            found_target = True
        mem_regions.append({
            "type": MEM_TYPE_NAMES[i], "base": base, "size": size,
            "contains_target": contains_target,
        })

    if not found_target:
        logger.debug(
            "candidate @ %#x name=%r rejected: target %#x not in any mem[] region",
            struct_addr, name, target_addr,
        )
        return None

    hidden = list_next in (LIST_POISON1, LIST_POISON2) or list_prev in (LIST_POISON1, LIST_POISON2)
    return {
        "struct_addr": struct_addr,
        "name": name,
        "state": MODULE_STATES[state],
        "list_next": list_next, "list_next_desc": next_desc,
        "list_prev": list_prev, "list_prev_desc": prev_desc,
        "hidden_from_module_list": hidden,
        "mem": mem_regions,
    }


def _scan_window(reader, target_addr, start, length):
    """Scan one [start, start+length) window for a struct module owning
    target_addr. Returns the validated result, or None."""
    blob = reader.read(start, length)
    if blob is None:
        logger.debug("  [%#x, %#x) unreadable (segment gap) — skipping", start, start + length)
        return None
    for m in NAME_RE.finditer(blob):
        # name field starts MOD_NAME_OFF bytes into the struct; the struct
        # itself therefore starts this far before the match.
        struct_addr = start + m.start() - MOD_NAME_OFF
        if struct_addr < MODULES_VADDR:
            continue
        result = validate_candidate(reader, struct_addr, target_addr)
        if result:
            return result
    return None


def scan(reader: SegmentReader, target_addr, max_back, chunk_size, direction="both"):
    """Search outward from target_addr for a struct module that owns it.

    struct module and the .text region containing target_addr are SEPARATE
    vmalloc allocations on this kernel's split mem[] layout (see module-level
    docstring) — there is no guarantee the header sits below target_addr, only
    that it sits *somewhere* in module address space. Backward-only search
    (direction="back") matches the classic single-blob mental model and will
    miss a header placed above the target; "both" (the default) checks outward
    in both directions and is the realistic choice on this kernel family.
    """
    back_end = target_addr
    fwd_start = target_addr
    scanned_back = 0
    scanned_fwd = 0
    do_back = direction in ("back", "both")
    do_fwd = direction in ("forward", "both")

    # Each direction gets its own max_back budget — combining them into one
    # shared counter (an earlier version of this function did) halves the
    # effective depth of each direction, which matters here: there is no
    # guarantee the header is close to target_addr at all.
    while do_back or do_fwd:
        if do_back and scanned_back < max_back:
            start = max(MODULES_VADDR, back_end - chunk_size)
            length = back_end - start
            if length <= 0:
                do_back = False
            else:
                logger.debug("scanning backward window [%#x, %#x)", start, back_end)
                result = _scan_window(reader, target_addr, start, length)
                if result:
                    return result
                back_end = start
                scanned_back += length
        elif do_back:
            do_back = False

        if do_fwd and scanned_fwd < max_back:
            end = min(MODULES_END, fwd_start + chunk_size)
            length = end - fwd_start
            if length <= 0:
                do_fwd = False
            else:
                logger.debug("scanning forward window [%#x, %#x)", fwd_start, end)
                result = _scan_window(reader, target_addr, fwd_start, length)
                if result:
                    return result
                fwd_start = end
                scanned_fwd += length
        elif do_fwd:
            do_fwd = False

        if not do_back and not do_fwd:
            break
    return None


def dump_module(image: KernelImage, reader: SegmentReader, info, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    manifest = dict(info)
    manifest["dumped_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    manifest["files"] = {}

    for region in info["mem"]:
        if region["base"] == 0 or region["size"] == 0:
            continue
        if region["size"] > 64 * 1024 * 1024:
            logger.warning(
                "mem[%s] claims %d bytes — refusing to dump (looks corrupt)",
                region["type"], region["size"],
            )
            continue
        fname = f"{info['name']}.{region['type']}.bin"
        path = os.path.join(out_dir, fname)
        logger.info(
            "dumping mem[%s] @ %#x (%d bytes) -> %s",
            region["type"], region["base"], region["size"], path,
        )
        remaining = region["size"]
        addr = region["base"]
        with open(path, "wb") as f:
            while remaining > 0:
                step = min(remaining, 1024 * 1024)
                data = reader.read(addr, step)
                if data is None:
                    logger.warning(
                        "  gap at %#x, writing zero-fill for %d bytes", addr, step,
                    )
                    data = b"\x00" * step
                f.write(data)
                addr += step
                remaining -= step
        manifest["files"][region["type"]] = fname

    manifest_path = os.path.join(out_dir, f"{info['name']}.json")
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)
    logger.info("manifest -> %s", manifest_path)
    return manifest_path


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("address", help="kernel address to search back from, e.g. 0xffffffffc0c12170")
    parser.add_argument("--kcore", default="/proc/kcore")
    parser.add_argument("--kallsyms", default="/proc/kallsyms")
    parser.add_argument("--max-back", default="16M", help="total bytes to scan (per direction; e.g. 16M, 64M)")
    parser.add_argument("--chunk-size", default="2M", help="bytes read per scan window")
    parser.add_argument(
        "--direction", choices=["both", "back", "forward"], default="both",
        help="search direction from the given address (default: both — see module docstring for why)",
    )
    parser.add_argument("--out-dir", default="dumps", help="where to write the memory dump + manifest")
    parser.add_argument("-v", "--debug", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(levelname)s:%(name)s:%(message)s",
    )

    def size(s):
        mult = {"K": 1024, "M": 1024 ** 2, "G": 1024 ** 3}.get(s[-1].upper())
        return int(s[:-1]) * mult if mult else int(s)

    target = parse_addr(args.address)
    max_back = size(args.max_back)
    chunk_size = size(args.chunk_size)

    logger.info("target address: %#x", target)
    image = KernelImage(all_syms_path=args.kallsyms, image_path=args.kcore)
    reader = SegmentReader(image)

    info = scan(reader, target, max_back, chunk_size, direction=args.direction)
    if not info:
        logger.error(
            "no struct module found owning %#x within %d bytes (%s). "
            "Try --max-back larger, or --debug to see what was scanned.",
            target, max_back, args.direction,
        )
        sys.exit(1)

    logger.info("FOUND module %r @ %#x  state=%s", info["name"], info["struct_addr"], info["state"])
    logger.info(
        "  list.next=%#x (%s)  list.prev=%#x (%s)%s",
        info["list_next"], info["list_next_desc"],
        info["list_prev"], info["list_prev_desc"],
        "  <== HIDDEN: unlinked from the global modules list" if info["hidden_from_module_list"] else "",
    )
    for region in info["mem"]:
        if region["base"] == 0:
            continue
        marker = "  <-- target address is here" if region["contains_target"] else ""
        logger.info(
            "  mem[%-13s] base=%#x size=%d%s",
            region["type"], region["base"], region["size"], marker,
        )

    out_dir = os.path.join(args.out_dir, info["name"])
    manifest_path = dump_module(image, reader, info, out_dir)
    print(f"\nDumped '{info['name']}' to {out_dir}/ (manifest: {manifest_path})")


if __name__ == "__main__":
    main()
