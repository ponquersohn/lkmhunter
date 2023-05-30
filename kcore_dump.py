import re
import subprocess
import collections
import sys


def hex_print(val, size=4):
    string = val.hex()

    counter = 0
    for i in string:
        if counter == 0:
            print("0x")


# def fix_word(word):


def fix_address(address):
    """Mangling the address to be real.
    0x813f26c0ffffffff shoulb become
    0xffffffff813f26c0
    """
    high_word = (address & 0xFFFFFFFF) << (8 * 4)
    low_word = address >> (8 * 4)
    # print(f"{high_word:x} {low_word:x}")
    ret = high_word | low_word
    # print(f"address: {address:x} converted to {ret:x}")
    return ret


segments = load_kcore_segments()
initrd_offset = calculate_initrd_load_point()
# print(f"initrd offset: {initrd_offset:x}")
fix_address(0x813F26C0FFFFFFFF)

running_kernel_version = get_running_kernel()


running_kernel.calculate_offset(base_kernel)

# with open("/proc/kcore", "rb", 0) as kcore:
#    address = map_to_virtual(segments, 0xFFFFFFFF92A00380)
#    print(f"{address:x}")
#    kcore.seek(address)
#    word = kcore.read(32)
#    print(word.hex(" ", bytes_per_sep=4))
#
""""""
