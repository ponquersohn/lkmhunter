# gdb helper for walking the live syscall table.
#
#   (gdb) source testbed/gdb/syscalls-gdb.py
#   (gdb) syscalls              # list every syscall slot, symbol-resolved
#   (gdb) syscalls 60           # just the first 60
#   (gdb) syscalls --hooked     # only slots that look redirected into a module
#
# A clean slot points into kernel text (0xffffffff81......) and resolves to a
# <__x64_sys_NAME> symbol. A hooked slot points into module space
# (>= MODULES_VADDR, i.e. 0xffffffffc0......) — that is what this flags.
import gdb

# Start of the module mapping on x86-64. Anything at/above this that a syscall
# slot points to was redirected into a loaded .ko.
MODULES_VADDR = 0xFFFFFFFFC0000000


def _resolve(addr):
    try:
        s = gdb.execute("info symbol 0x%x" % addr, to_string=True).strip()
    except gdb.error:
        return "?"
    return "no symbol" if s.startswith("No symbol") else s


class Syscalls(gdb.Command):
    """List the live kernel syscall table with resolved symbols, flagging
    slots that point into module space (likely hooks).

    Usage: syscalls [N] [--hooked]"""

    def __init__(self):
        super(Syscalls, self).__init__("syscalls", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        args = arg.split()
        hooked_only = "--hooked" in args
        limit = None
        for a in args:
            if a.isdigit():
                limit = int(a)

        try:
            table = gdb.parse_and_eval("sys_call_table")
        except gdb.error:
            print("sys_call_table not found — is vmlinux loaded? (./fetch-symbols.sh)")
            return

        # Derive the entry count from the array type when symbols provide it.
        try:
            n = int(table.type.sizeof // table[0].type.sizeof)
        except (gdb.error, ZeroDivisionError):
            n = 460
        if limit is not None:
            n = min(n, limit)

        flagged = 0
        for i in range(n):
            addr = int(table[i]) & 0xFFFFFFFFFFFFFFFF
            is_hook = addr >= MODULES_VADDR
            if hooked_only and not is_hook:
                continue
            mark = "  <== MODULE space (possible hook!)" if is_hook else ""
            print("[%3d] 0x%016x  %s%s" % (i, addr, _resolve(addr), mark))
            if is_hook:
                flagged += 1

        print("-" * 60)
        if hooked_only and flagged == 0:
            print("No syscall slots point into module space. Table looks clean.")
        else:
            print("%d slot(s) point into module space." % flagged)


Syscalls()
print("[syscalls-gdb] loaded. Try:  syscalls --hooked")
