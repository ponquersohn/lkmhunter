from dataclasses import dataclass

from elftools.elf.sections import SymbolTableSection

from .errors import MetadataError


@dataclass(frozen=True)
class Symbol:
    name: str
    address: int
    size: int = 0
    kind: str = ""


def read_symbols(path, *, include_modules=False):
    symbols = {}
    with open(path) as source:
        for line in source:
            fields = line.split()
            if len(fields) < 3:
                continue
            try:
                address = int(fields[0], 16)
            except ValueError:
                continue
            # Module symbols may shadow core names; do not use them as anchors.
            name = fields[2]
            if len(fields) > 3 and fields[3].startswith("["):
                if not include_modules:
                    continue
                name = f"{fields[3].strip('[]')}__{name}"
            symbol = Symbol(name, address, kind=fields[1])
            if symbol.name not in symbols or not symbols[symbol.name].address:
                symbols[symbol.name] = symbol
    return symbols


def elf_symbols(elf):
    result = {}
    for section in elf.iter_sections():
        if isinstance(section, SymbolTableSection):
            for entry in section.iter_symbols():
                if entry.name and entry["st_shndx"] != "SHN_UNDEF":
                    symbol = Symbol(entry.name, entry["st_value"], entry["st_size"], entry["st_info"]["type"])
                    if symbol.name not in result or symbol.size:
                        result[symbol.name] = symbol
    return result


def relocation(live, baseline):
    anchors = ("_stext", "_text", "startup_64", "sys_call_table", "_etext", "init_task")
    offsets = {
        name: live[name].address - baseline[name].address
        for name in anchors if name in live and name in baseline
        and live[name].address and baseline[name].address
    }
    if not offsets:
        raise MetadataError("No nonzero common relocation anchors; check kallsyms visibility and baseline")
    if len(set(offsets.values())) != 1:
        raise MetadataError(f"Inconsistent KASLR anchors; baseline may not match: {offsets}")
    return next(iter(offsets.values())), offsets
