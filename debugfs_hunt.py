"""Compare ext4 directory entries with live VFS listings (read-only)."""
import argparse
import contextlib
import logging
import os
from pathlib import Path, PurePosixPath
import subprocess
import tempfile
import time

logger = logging.getLogger("debugfs_hunt")


class BypassLogHandler(logging.Handler):
    """Keep diagnostic paths intact when the rootkit filters pipe writes."""

    def emit(self, record):
        try:
            data = (self.format(record) + "\n").encode(errors="backslashreplace")
            while data:
                written = os.write(0, data)
                if written <= 0:
                    raise OSError("Diagnostic write made no progress")
                data = data[written:]
        except Exception:
            self.handleError(record)


def run_command(command, timeout, **kwargs):
    started = time.monotonic()
    logger.debug("Running command=%r timeout=%ss", command, timeout)
    try:
        result = subprocess.run(command, capture_output=True, text=True,
                                timeout=timeout, check=True, **kwargs)
    except (subprocess.SubprocessError, OSError) as exc:
        logger.error("Command failed after %.3fs: %r", time.monotonic() - started, command)
        logger.debug("Captured stdout=%r stderr=%r", getattr(exc, "stdout", None),
                     getattr(exc, "stderr", None))
        raise
    logger.debug("Command completed in %.3fs: rc=%d stdout=%d chars stderr=%r",
                 time.monotonic() - started, result.returncode, len(result.stdout), result.stderr)
    return result


class Debugfs:
    def __init__(self, device, helper=None, timeout=15):
        self.device = device
        self.helper = helper
        self.timeout = timeout

    def listdir(self, directory):
        # debugfs has its own command parser, independent of shell quoting.
        if any(c in directory for c in '\n\r"\\'):
            raise ValueError(f"Unsupported debugfs path: {directory!r}")
        command = ["debugfs", "-R", f'ls -lp "{directory}"', self.device]
        if self.helper:
            command.insert(0, str(self.helper))
        env = None
        if self.helper:
            env = dict(os.environ, LKMHUNTER_DEBUGFS_DEBUG=(
                "1" if logger.isEnabledFor(logging.DEBUG) else "0"))
        result = run_command(command, self.timeout, env=env)
        entries = []
        for line in result.stdout.splitlines():
            if not line.startswith("/"):
                continue
            entry = parse_entry(line)
            if entry["name"] not in (".", ".."):
                entries.append(entry)
        if not result.stdout.strip() or not any(
                line.startswith("/") for line in result.stdout.splitlines()):
            raise RuntimeError(result.stderr.strip() or "debugfs returned no directory entries")
        logger.debug("Disk directory %r: %d entries", directory, len(entries))
        return entries


def parse_entry(entry):
    fields = entry.split("/")
    if len(fields) < 7 or not fields[2].isdigit():
        raise ValueError(f"Malformed debugfs entry: {entry!r}")
    return {"type": fields[2][:-4], "perm": fields[2], "name": fields[5]}


def hunt(debugfs, directory, mountpoint):
    """Compare each directory once, yielding missing files and directories."""
    pending = [directory]
    directories = 0
    missing = 0
    started = time.monotonic()
    while pending:
        current = pending.pop()
        logger.debug("Scanning directory=%r pending=%d", current, len(pending))
        entries = debugfs.listdir(current)
        live_dir = mountpoint / current.lstrip("/")
        # Descend using raw disk entries even when a directory is hidden in VFS.
        try:
            visible = set(os.listdir(live_dir))
        except FileNotFoundError:
            logger.debug("VFS directory unavailable: %s", live_dir)
            visible = set()
        directories += 1
        logger.debug("Comparing %r: disk=%d entries VFS=%d entries", current,
                     len(entries), len(visible))
        if directories % 100 == 0:
            logger.info("Progress: %d directories, %d missing entries, %d pending, %.1fs",
                        directories, missing, len(pending), time.monotonic() - started)
        for entry in entries:
            path = str(PurePosixPath(current) / entry["name"])
            if entry["name"] not in visible:
                missing += 1
                logger.debug("Missing entry: path=%r mode=%s", path,
                             entry.get("perm", entry["type"]))
                yield path
            if entry["type"] == "04":
                pending.append(path)
    logger.debug("Walk finished: %d directories, %d missing entries in %.3fs",
                 directories, missing, time.monotonic() - started)


@contextlib.contextmanager
def output_helper(enabled):
    if not enabled:
        logger.debug("Output-filter bypass disabled")
        yield None
        return
    if os.uname().machine != "x86_64":
        raise RuntimeError("The output-filter bypass currently requires Linux x86_64")
    source = Path(__file__).resolve().parent / "utils" / "debugfs_output.c"
    with tempfile.TemporaryDirectory(prefix="lkmhunter-debugfs-") as work:
        helper = Path(work) / "debugfs-output"
        logger.debug("Building output helper from %s", source)
        run_command(["cc", "-Wall", "-Wextra", "-O2", str(source), "-o", str(helper)], 30)
        logger.debug("Output helper ready: %s", helper)
        try:
            yield helper
        finally:
            logger.debug("Removing temporary helper directory %s", work)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("device", nargs="?", default="/dev/system/root")
    parser.add_argument("mountpoint", nargs="?", type=Path, default=Path("/mnt"))
    parser.add_argument("--directory", default="/", help="Start at this path inside the filesystem")
    parser.add_argument("-v", "--debug", action="store_true",
                        help="Log scan progress, subprocess details and error tracebacks")
    parser.add_argument("--bypass-output-filter", action="store_true",
                        help="Bypass rootkitd write filter (requires root, cc and ptrace on x86_64)")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("Run as root (for example, sudo python3 debugfs_hunt.py ...)")
    directory = PurePosixPath(args.directory)
    if not directory.is_absolute() or ".." in directory.parts:
        parser.error("--directory must be an absolute filesystem path without '..'")
    # The rootkit also filters the detector's own report when stdout is a pipe.
    # fd 0 is explicitly excluded by its write hook. No stdin is used here.
    if args.bypass_output_filter:
        os.dup2(1, 0)
    handler = BypassLogHandler() if args.bypass_output_filter else logging.StreamHandler()
    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
                        handlers=[handler], force=True)
    logger.info("Starting scan: device=%s mountpoint=%s directory=%s bypass=%s",
                args.device, args.mountpoint, directory, args.bypass_output_filter)

    def report(message):
        data = (message + "\n").encode()
        fd = 0 if args.bypass_output_filter else 1
        while data:
            written = os.write(fd, data)
            if written <= 0:
                raise OSError("Output write made no progress")
            data = data[written:]

    count = 0
    with output_helper(args.bypass_output_filter) as helper:
        debugfs = Debugfs(args.device, helper)
        for path in hunt(debugfs, str(directory), args.mountpoint):
            report(f"Missing entry: {path} under {args.mountpoint}")
            count += 1
    report(f"Scan complete: {count} missing entries")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        logger.error("Scan failed: %s", exc, exc_info=logger.isEnabledFor(logging.DEBUG))
        raise SystemExit(1)
