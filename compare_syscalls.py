"""Compatibility command backed by the shared lkmhunter library."""
import sys

from lkmhunter.cli import main as hunter_main


def main(argv=None):
    return hunter_main(['scan', 'syscalls'] + (sys.argv[1:] if argv is None else list(argv)))


if __name__ == "__main__":
    raise SystemExit(main())
