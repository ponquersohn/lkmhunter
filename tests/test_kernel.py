import pytest

from kernel import KernelImage
from utils import get_running_kernel


def running_kernel_version():
    running_kernel_version = get_running_kernel()
    return running_kernel_version


def running_kernel():
    running_kernel = KernelImage(f"/proc/kallsyms", "/proc/kcore")
    return running_kernel


def base_kernel():
    base_kernel = KernelImage(
        f"/boot/System.map-{running_kernel_version()}", "/home/ponq/vmlinux"
    )
    return base_kernel


def test_kernel_class(running_kernel, base_kernel):
    return


rkernel = running_kernel()
bkernel = base_kernel()

rkernel.load_sys_call_table().print_table()
