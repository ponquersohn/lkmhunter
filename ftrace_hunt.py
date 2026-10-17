"""Detect ftrace-based function hooking (the technique compare_syscalls.py
structurally cannot see).

Why this exists: compare_syscalls.py diffs the *contents* of sys_call_table
against an on-disk kernel image. That catches classic rootkits (Diamorphine)
that overwrite table entries with a pointer into their module. It does NOT
catch rootkits that hook via ftrace (register an ftrace_ops on a function's
own entry trampoline) — the table entry is untouched; the function's
instrumented prologue redirects instead. Singularity (and most modern LKM
rootkits) hook this way.

The signal: every function with a live ftrace_ops gets a line in
/sys/kernel/debug/tracing/enabled_functions, showing a per-function trampoline
stub and the callback it ultimately dispatches to. A legitimate tracer/kprobe
hooks one function, or a handful of related ones. A rootkit that hooks dozens
of semantically unrelated functions (read + kill + getdents + do_syslog +
audit_log_start + bpf_map_update_elem + tcp4_seq_show ...) to implement
file/process/network/log hiding all route through the SAME callback address,
registered from the SAME (usually unloaded-from-lsmod) module. That shared
dispatcher, hit by a wide, unrelated set of functions, is the fingerprint this
module looks for — no symbol resolution of the rootkit itself required.

Usage:
    sudo python3 ftrace_hunt.py
    sudo python3 ftrace_hunt.py --debug
    sudo python3 ftrace_hunt.py --min-group 3   # lower/raise the alarm threshold

Needs root and debugfs/tracefs mounted (mount -t tracefs none /sys/kernel/debug/tracing
if missing — Ubuntu mounts it by default).
"""
import argparse
import logging
import re
import sys
from collections import defaultdict

logger = logging.getLogger("ftrace_hunt")

DEFAULT_PATH = "/sys/kernel/debug/tracing/enabled_functions"
# Same convention as kernel.py / testbed/gdb/syscalls-gdb.py: start of module
# address space on x86-64. A trampoline or callback living here was planted by
# a loaded .ko, not the base kernel image.
MODULES_VADDR = 0xFFFFFFFFC0000000

# One line can be a single-tramp hook:
#   funcname (N) FLAGS \t tramp: 0xSTUB (0xCALLBACK) ->resolved_name+0x.../0x...
# or a direct-call/BPF-trampoline hook, which may wrap to a second line:
#   funcname (N) FLAGS \t tramp: ftrace_regs_caller+0x.../0x...  (call_direct_funcs+...)
#       direct(jmp)-->bpf_trampoline_NNNN+0x.../0x...
LINE_RE = re.compile(
    r"^(?P<func>\S+)\s+\((?P<count>\d+)\)\s+(?P<flags>.*?)\s*"
    r"tramp:\s*(?P<tramp>\S+)(?:\s+\((?P<callback>\S+)\))?\s*(?:->(?P<resolved>\S+))?"
)
HEX_RE = re.compile(r"^0x[0-9a-fA-F]+$")


class FtraceHook:
    def __init__(self, func, tramp, callback, resolved, raw):
        self.func = func
        self.tramp = tramp          # per-function trampoline stub (always module-space if hooked)
        self.callback = callback    # the shared dispatcher/handler this tramp jumps to
        self.resolved = resolved    # symbol name the callback resolves to, if any
        self.raw = raw

    @property
    def dispatch_key(self):
        """What to group hooks by: the real handler, falling back to the
        trampoline's own address when there is nothing else to key on."""
        return self.callback or self.resolved or self.tramp


def parse_enabled_functions(path=DEFAULT_PATH):
    """Yields FtraceHook for every function with a live ftrace hook.

    Lines we can't parse are logged at debug and skipped rather than raising —
    this file's exact format has drifted across kernel versions, and a parse
    miss should degrade to "saw fewer hooks," never crash the hunt.
    """
    try:
        f = open(path, "r")
    except OSError as e:
        logger.error(
            "cannot read %s (%s). Needs root, and tracefs mounted "
            "(mount -t tracefs none /sys/kernel/debug/tracing).",
            path, e,
        )
        return
    with f:
        for lineno, line in enumerate(f, 1):
            line = line.rstrip("\n")
            if not line or line.startswith("\t"):
                # continuation line (e.g. "\tdirect(jmp)-->...") — not a new hook
                logger.debug("line %d: continuation/skip: %r", lineno, line)
                continue
            m = LINE_RE.match(line)
            if not m:
                logger.debug("line %d: unparsed: %r", lineno, line)
                continue
            logger.debug("line %d: parsed %s", lineno, m.groupdict())
            yield FtraceHook(
                func=m.group("func"),
                tramp=m.group("tramp"),
                callback=m.group("callback"),
                resolved=m.group("resolved"),
                raw=line,
            )


def in_module_space(addr_str):
    if not addr_str or not HEX_RE.match(addr_str):
        return False
    return int(addr_str, 16) >= MODULES_VADDR


def hunt(path=DEFAULT_PATH, min_group=3):
    hooks = list(parse_enabled_functions(path))
    logger.info("Parsed %d ftrace hook entries from %s", len(hooks), path)

    module_hooks = [h for h in hooks if in_module_space(h.tramp) or in_module_space(h.callback)]
    logger.info("%d entries have a trampoline/callback in module address space", len(module_hooks))

    groups = defaultdict(list)
    for h in module_hooks:
        groups[h.dispatch_key].append(h)

    suspicious = {k: v for k, v in groups.items() if len(v) >= min_group}

    for key, members in sorted(groups.items(), key=lambda kv: -len(kv[1])):
        level = logging.WARNING if key in suspicious else logging.DEBUG
        logger.log(level, "dispatcher %s used by %d hooked function(s)", key, len(members))
        for h in members:
            logger.log(level, "    %s  tramp=%s", h.func, h.tramp)

    if suspicious:
        total = sum(len(v) for v in suspicious.values())
        logger.warning(
            "SUSPICIOUS: %d dispatcher(s) each hook >= %d unrelated functions "
            "(%d functions total) via module-space trampolines — consistent "
            "with a single rootkit module ftrace-hooking many syscalls/internals.",
            len(suspicious), min_group, total,
        )
        for key, members in suspicious.items():
            names = ", ".join(h.func for h in members[:12])
            more = f", +{len(members) - 12} more" if len(members) > 12 else ""
            logger.warning("  dispatcher %s: %s%s", key, names, more)
    else:
        logger.info(
            "No dispatcher hooks >= %d unrelated functions. "
            "(Isolated single-function hooks from kprobes/BPF/legitimate "
            "tracers are normal and not flagged; raise suspicion only forms "
            "from a handful of hooks or more sharing one dispatcher.)",
            min_group,
        )
    return suspicious


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--path", default=DEFAULT_PATH)
    parser.add_argument(
        "--min-group", type=int, default=3,
        help="flag a dispatcher once it hooks at least this many functions (default 3)",
    )
    parser.add_argument("-v", "--debug", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(levelname)s:%(name)s:%(message)s",
    )

    suspicious = hunt(args.path, args.min_group)
    sys.exit(1 if suspicious else 0)
