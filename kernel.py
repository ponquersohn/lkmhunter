import collections
from io import BufferedReader
import re
import subprocess
from base_object import BaseObject

from syscalls import SyscallTable


class KprocSegment(BaseObject):
    def __init__(
        self,
        segment_type=None,
        offset=None,
        virtual_address=None,
        physical_address=None,
        file_size=None,
        memory_size=None,
        flags=None,
        align=None,
    ):
        super().__init__()
        self.segment_type = segment_type
        self.offset = offset
        self.virtual_address = virtual_address
        self.physical_address = physical_address
        self.file_size = file_size
        self.memory_size = memory_size
        self.flags = flags
        self.align = align

    def __str__(self):
        return f"type: {self.segment_type} ,offset: {self.offset:x}, virtual_address: {self.virtual_address:x}, physical_address: {self.physical_address:x}, file_size: {self.file_size:x}, memory_size: {self.memory_size:x}, flags: {self.flags}, align: {self.align:x}"

    @classmethod
    def print_segments(cls, segments):
        for x in segments.values():
            print(x)


class Symbol(BaseObject):
    def __init__(
        self, address=None, physical_address=None, symbol_type=None, symbol_name=None
    ):
        super().__init__()
        self.address = address
        self.symbol_type = symbol_type
        self.symbol_name = symbol_name
        self.physical_address = physical_address


class KernelImage(BaseObject):
    def __init__(self, all_syms_path, image_path, offset=0):
        super().__init__()
        self.all_syms_path = all_syms_path
        self.image_path = image_path
        self.segments = self._load_program_headers()
        self.all_symbols = None
        self.load_all_symbols()

        self.image = open(image_path, "rb")

        self.offset = offset

        self.sys_call_table = None

    def _load_program_headers(self):
        result = subprocess.run(
            ["readelf", "-e", self.image_path], stdout=subprocess.PIPE
        )
        output = result.stdout.decode("utf-8").splitlines()

        segments = {}

        while output:
            line = output.pop(0).strip()
            if line == "Program Headers:":
                break

        output.pop(0)
        output.pop(0)

        while output:
            segment = KprocSegment()

            # we are only interested in the first line:
            first = output.pop(0).strip()
            if first == "":
                break
            second = output.pop(0).strip()
            match = re.search(
                r"(?P<type>[^ ]+)\s+(?P<offset>[^ ]+)\s+(?P<virtual_address>[^ ]+)\s+(?P<physical_address>[^ ]+)",
                first,
            )
            segment.segment_type = match.group("type")
            segment.offset = int(match.group("offset"), base=16)
            segment.virtual_address = int(match.group("virtual_address"), base=16)
            segment.physical_address = int(match.group("physical_address"), base=16)

            match = re.search(
                r"^(?P<file_size>[^ ]+)\s+(?P<mem_size>[^ ]+)\s+((?P<flags>.+))?\s+(?P<align>[^ ]+)$",
                second,
            )

            segment.file_size = int(match.group("file_size"), base=16)
            segment.memory_size = int(match.group("mem_size"), base=16)
            segment.flags = match.group("flags")
            segment.align = int(match.group("align"), base=16)

            segments[segment.virtual_address] = segment

        self.segments = collections.OrderedDict(sorted(segments.items(), reverse=True))
        return self.segments

    def to_physical(self, address):
        for segment_address in self.segments:
            segment: KprocSegment = self.segments[segment_address]

            relative_address = address - segment_address
            # print(
            #     f"address: {address:x}, segment: {segment_address:x}, offset: {offset:x}, length: {length:x}, relative_address: {relative_address:x}"
            # )
            if segment_address < address:
                return segment.offset + address - segment_address

    def get_symbol(self, name):
        return self.all_symbols[name]

    def load_sys_call_table(self, length=314):
        """Returns the syscall table.

        Args:
            length(int):    The length of the table.
        """
        syscall_table_address: Symbol = self.all_symbols["sys_call_table"]
        sys_call_table = SyscallTable(
            open(self.image_path, "rb"),
            syscall_table_address,
            offset=self.offset,
            length=length,
        )
        self.sys_call_table = sys_call_table

        return sys_call_table

    def calculate_offset(self, kernel_image: "KernelImage"):
        """Helper function used to calculate the offset.

        Uses a known common symbol to calculate the difference. Requires a `KernelImage` as parameter for the comparison.

        Args:
            kernel_image(KernelImage): The kernel to calculate the offset against.
        """
        symbol_to_compare = "sys_call_table"
        this_address = self.get_symbol(symbol_to_compare)
        other_address = kernel_image.get_symbol(symbol_to_compare)
        self.offset = this_address.address - other_address.address
        physical_offset = this_address.physical_address - other_address.physical_address

        self.logger.debug(f"offset: {self.offset:x}")

    def relocate(self, address):
        """Helper function used to relocate the address by provided offset.

        Args:
            address(int): Address.
        """
        return address - self.offset

    def load_all_symbols(self):
        """Loads all symbols from the provided path.

        Can use SystemMap or kallsyms.
        """
        self.all_symbols = {}
        with open(self.all_syms_path, "r") as all_symbols_f:
            for line in all_symbols_f.readlines():
                line = line.strip()
                (address, symbol_type, symbol_name) = line.split(" ")
                address = int(address, base=16)
                symbol = Symbol(
                    address, self.to_physical(address), symbol_type, symbol_name
                )
                # self.logger.debug(f"Loaded symbol: {symbol}")
                self.all_symbols[symbol_name] = symbol

    def compare_syscall_table(self, other: "KernelImage"):
        diff = []
        for my_syscall in self.sys_call_table.iterate():
            other_syscall = other.sys_call_table.get_syscall(my_syscall.number)
            self.logger.debug(my_syscall)
            self.logger.debug(other_syscall)
            if my_syscall.relocated_entry_point != other_syscall.relocated_entry_point:
                self.logger.info(f"Syscall {my_syscall.name} seems hooked.")
                diff.append((my_syscall, other_syscall))
        return diff


if __name__ == "__main__":
    import logging

    logging.basicConfig(level=logging.INFO)
    running_kernel = KernelImage(
        all_syms_path="/proc/kallsyms", image_path="/proc/kcore"
    )

    boot_kernel = KernelImage(
        all_syms_path="/boot/System.map-6.5.0-27-generic", image_path="work/vmlinux"
    )

    offset = running_kernel.calculate_offset(boot_kernel)
    running_kernel.load_sys_call_table()
    boot_kernel.load_sys_call_table()
