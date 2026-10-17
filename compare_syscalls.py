from kernel import KernelImage

import argparse
import os
import sys
import logging

parser = argparse.ArgumentParser(description="Looks for hooked syscalls.")
parser.add_argument("--running_kernel_image", default="/proc/kcore")
parser.add_argument("--running_kernel_sysmap", default="/proc/kallsyms")
parser.add_argument("--loaded_kernel_image", default="work/vmlinux")
parser.add_argument(
    "--loaded_kernel_sysmap", default="/boot/System.map-6.5.0-27-generic"
)
parser.add_argument(
    "-v", "--debug", action="store_true",
    help="verbose debug logging (per-symbol, per-syscall internals)",
)

args = parser.parse_args()

logging.basicConfig(
    level=logging.DEBUG if args.debug else logging.INFO,
    format="%(levelname)s:%(name)s:%(message)s",
)

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
diff = running_kernel.compare_syscall_table(boot_kernel)

# Exit status: 0 = clean, 1 = one or more syscalls look hooked.
sys.exit(1 if diff else 0)
