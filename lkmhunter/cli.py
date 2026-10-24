import argparse
import json
import logging
import sys

from .errors import HunterError
from .results import ScanResult, ScanStatus
from .scanners import FtraceScanner, ModuleScanner, SyscallScanner, dump_module
from .session import KernelSession


def size(value):
    try:
        multiplier = {"K": 1024, "M": 1024**2, "G": 1024**3}.get(value[-1:].upper(), 1)
        count = int(value[:-1] if multiplier != 1 else value, 0) * multiplier
        if count <= 0:
            raise ValueError
        return count
    except (ValueError, TypeError):
        raise argparse.ArgumentTypeError("Expected a positive byte count, optionally suffixed K, M, or G") from None


def address(value):
    try:
        return int(value, 16)
    except ValueError:
        raise argparse.ArgumentTypeError("Expected a hexadecimal kernel address") from None


def common(parser):
    def option(*flags, **kwargs):
        parser.add_argument(*flags, default=argparse.SUPPRESS, **kwargs)
    option("--backend", choices=["auto", "kcore", "lkm_mem"])
    option("--kcore", dest="kcore")
    option("--lkm-mem", dest="lkm_mem")
    option("--kallsyms", dest="kallsyms")
    option("--vmlinux", dest="vmlinux")
    option("--system-map", dest="system_map")
    option("--btf")
    option("--layout", help="Explicit module layout JSON (overrides automatic discovery)")
    option("--tracefs", dest="tracefs", help="Tracefs directory or enabled_functions file")
    option("--kernel-release")
    option("--live-notes", help="Live kernel ELF notes for build ID validation")
    option("--format", choices=["text", "json"])
    option("--json", dest="format", action="store_const", const="json")
    option("-v", "--debug", action="store_true")


def parser():
    root = argparse.ArgumentParser(description="Hunt kernel hooks and recover owning modules")
    common(root)
    commands = root.add_subparsers(dest="command", required=True)
    copy = commands.add_parser("copy", help="Copy vmlinux bytes to a live address through lkm_mem (raw write)")
    common(copy)
    copy.add_argument("address", type=address, help="Live kernel virtual address (hex); source is address minus KASLR slide")
    copy.add_argument("size", type=size, help="Number of bytes, optionally suffixed K, M, or G")
    copy.add_argument("--backup", help="Save original bytes and copy metadata to a new private JSON file")
    scan = commands.add_parser("scan")
    common(scan)
    scanners = scan.add_subparsers(dest="technique", required=True)
    syscall = scanners.add_parser("syscalls", help="Compare live syscall pointers to a matching baseline")
    common(syscall)
    syscall.add_argument("--syscall-count", type=int)
    ftrace = scanners.add_parser("ftrace", help="Group module-space ftrace dispatchers (heuristic)")
    common(ftrace)
    ftrace.add_argument("--min-group", type=int, default=3)
    module = commands.add_parser("module")
    common(module)
    actions = module.add_subparsers(dest="action", required=True)
    for action in ("find", "dump"):
        command = actions.add_parser(action)
        common(command)
        command.add_argument("address", type=address)
        command.add_argument("--max-back", type=size, default=16 * 1024**2,
                             help="Search budget per direction (default: 16M)")
        command.add_argument("--chunk-size", type=size, default=2 * 1024**2)
        command.add_argument("--direction", choices=["both", "back", "forward"], default="both")
        if action == "dump":
            command.add_argument("--out-dir", default="dumps")
    gdb = commands.add_parser("gdb", help="Inspect live kernel memory with local, read-only GDB")
    common(gdb)
    gdb.add_argument("--symbols", choices=["auto", "kallsyms", "vmlinux", "none"], default="auto")
    gdb.add_argument("--export", help="Write a reusable local session instead of launching GDB")
    gdb.add_argument("--gdb-binary", default="gdb")
    gdb.add_argument("--command", dest="gdb_commands", action="append", default=[], help="GDB command to run after connecting (repeatable)")
    gdb.add_argument("--batch", action="store_true")
    server = commands.add_parser("gdb-serve", help="Local stdio adapter used internally by the GDB launcher")
    common(server)
    return root


def render(result, output_format):
    if output_format == "json":
        print(json.dumps(result.to_dict(), indent=2))
        return
    print(f"{result.technique}: {result.status.value}; {len(result.findings)} finding(s)")
    for finding in result.findings:
        print(f"  {finding.summary}")
        print("    " + json.dumps(finding.evidence, sort_keys=True))
    if result.coverage:
        print("Coverage: " + json.dumps(result.coverage, sort_keys=True))
    for diagnostic in result.diagnostics:
        print(diagnostic, file=sys.stderr)


def main(argv=None):
    args = parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if getattr(args, "debug", False) else logging.INFO,
                        format="%(levelname)s:%(name)s:%(message)s")
    session_fields = {"backend", "kcore", "lkm_mem", "kallsyms", "vmlinux", "system_map",
                      "btf", "layout", "tracefs", "kernel_release", "live_notes"}
    kwargs = {key: value for key, value in vars(args).items() if key in session_fields}
    if args.command == "copy":
        from .copy import copy_from_vmlinux
        try:
            if kwargs.get('backend', 'auto') == 'kcore':
                raise ValueError('copy writes through lkm_mem; --backend kcore is not supported')
            kwargs['backend'] = 'lkm_mem'
            with KernelSession.open(**kwargs) as session:
                report = copy_from_vmlinux(session, args.address, args.size, backup=args.backup)
            if getattr(args, 'format', 'text') == 'json':
                print(json.dumps(report, indent=2))
            else:
                print(f"Copied {report['size']} bytes from vmlinux {report['source_address']:#x} "
                      f"to live {report['address']:#x}; readback verified")
            return 0
        except (HunterError, OSError, ValueError) as exc:
            print(f'Copy failed: {exc}', file=sys.stderr)
            return 2
    if args.command in ("gdb", "gdb-serve"):
        from .gdb_bridge import launch_gdb, serve_session
        try:
            with KernelSession.open(**kwargs) as session:
                if args.command == "gdb-serve":
                    serve_session(session)
                    return 0
                return launch_gdb(session, mode=args.symbols,
                                  export=args.export, binary=args.gdb_binary,
                                  commands=args.gdb_commands, batch=args.batch)
        except (HunterError, OSError, ValueError) as exc:
            print(f"GDB inspection failed: {exc}", file=sys.stderr)
            return 2
    technique = getattr(args, "technique", "module")
    try:
        with KernelSession.open(**kwargs) as session:
            if technique == "syscalls":
                result = SyscallScanner(args.syscall_count).scan(session)
            elif technique == "ftrace":
                result = FtraceScanner(args.min_group).scan(session)
            else:
                result = ModuleScanner().scan(session, args.address, max_back=args.max_back,
                                               chunk_size=args.chunk_size, direction=args.direction)
                if args.action == "dump" and result.findings:
                    try:
                        path, manifest = dump_module(session, result.findings[0], args.out_dir)
                    except (HunterError, OSError, ValueError) as exc:
                        result.status = ScanStatus.FAILED
                        result.diagnostics.append(f"Dump failed: {exc}")
                    else:
                        result.coverage["manifest"] = str(path)
                        result.coverage["dump_gaps"] = len(manifest["gaps"])
                        if manifest["gaps"]:
                            result.status = ScanStatus.PARTIAL
                elif args.action == "dump" and not result.findings and result.status == ScanStatus.COMPLETE:
                    result.status = ScanStatus.UNAVAILABLE
                    result.diagnostics.append("Cannot dump: no owner found within search budget")
    except (HunterError, OSError, ValueError) as exc:
        logging.getLogger(__name__).debug("Command failed", exc_info=True)
        result = ScanResult(technique, ScanStatus.FAILED, diagnostics=[str(exc)])
    render(result, getattr(args, "format", "text"))
    return result.exit_code
