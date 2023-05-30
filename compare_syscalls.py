from kernel import KernelImage

import argparse
import os
import logging

logging.basicConfig(level=logging.INFO)
parser = argparse.ArgumentParser(description="Looks for hooked syscalls.")
parser.add_argument("--running_kernel_image", default="/proc/kcore")
parser.add_argument("--running_kernel_sysmap", default="/proc/kallsyms")
parser.add_argument("--loaded_kernel_image", default="work/vmlinux")
parser.add_argument(
    "--loaded_kernel_sysmap", default="/boot/System.map-6.5.0-27-generic"
)

args = parser.parse_args()

running_kernel = KernelImage(
    all_syms_path=args.running_kernel_sysmap, image_path=args.running_kernel_image
)
boot_kernel = KernelImage(
    all_syms_path=args.loaded_kernel_sysmap, image_path=args.loaded_kernel_image
)
offset = running_kernel.calculate_offset(boot_kernel)
running_kernel.load_sys_call_table()
boot_kernel.load_sys_call_table()
# print(boot_kernel.sys_call_table.get_syscall(0))
# print(running_kernel.sys_call_table.get_syscall(0))
running_kernel.compare_syscall_table(boot_kernel)
