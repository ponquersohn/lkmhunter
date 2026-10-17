"""Normalize BTF and DWARF into the small amount of layout data we need."""
import json
import subprocess
from dataclasses import asdict, dataclass

from .errors import MetadataError


@dataclass(frozen=True)
class Field:
    offset: int
    size: int


@dataclass(frozen=True)
class RegionLayout:
    name: str
    base: Field
    size: Field


@dataclass
class ModuleLayout:
    size: int
    state: Field
    name: Field
    next: Field
    prev: Field
    regions: list[RegionLayout]
    states: dict[int, str]
    source: str
    self_pointer: Field | None = None

    def validate(self):
        if not 1 <= self.size <= 1024 * 1024 or not self.regions or not self.states:
            raise MetadataError("Invalid module layout size, regions, or states")
        fields = [self.state, self.name, self.next, self.prev] + [f for r in self.regions for f in (r.base, r.size)]
        if self.self_pointer is not None:
            if self.self_pointer.size != 8:
                raise MetadataError("Unsupported module self pointer")
            fields.append(self.self_pointer)
        for field in fields:
            if field.offset < 0 or field.size <= 0 or field.offset + field.size > self.size:
                raise MetadataError("Module field lies outside the structure")
        if self.next.size != 8 or self.prev.size != 8 or not 2 <= self.name.size <= 256:
            raise MetadataError("Unsupported module pointer or name layout")
        for region in self.regions:
            if region.base.size != 8 or region.size.size not in (4, 8):
                raise MetadataError("Unsupported module region fields")
        return self

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_file(cls, path):
        with open(path) as source:
            data = json.load(source)
        try:
            layout = cls(
                size=data["size"], state=Field(**data["state"]), name=Field(**data["name"]),
                next=Field(**data["next"]), prev=Field(**data["prev"]),
                regions=[RegionLayout(r["name"], Field(**r["base"]), Field(**r["size"])) for r in data["regions"]],
                states={int(k): v for k, v in data["states"].items()}, source=f"layout:{path}",
                self_pointer=Field(**data["self_pointer"]) if data.get("self_pointer") else None,
            )
            return layout.validate()
        except (KeyError, TypeError, ValueError) as exc:
            raise MetadataError(f"Invalid layout file {path}: {exc}") from exc


class TypeGraph:
    WRAPPERS = {"TYPEDEF", "CONST", "VOLATILE", "RESTRICT", "TYPE_TAG"}

    def __init__(self, types, source):
        self.types = {t["id"]: t for t in types}
        self.source = source

    @classmethod
    def from_btf(cls, path):
        try:
            result = subprocess.run(
                ["bpftool", "-j", "btf", "dump", "file", str(path), "format", "raw"],
                capture_output=True, text=True, check=True, timeout=60,
            )
            return cls(json.loads(result.stdout)["types"], f"btf:{path}")
        except (OSError, subprocess.SubprocessError, ValueError, KeyError) as exc:
            detail = getattr(exc, "stderr", None) or str(exc)
            raise MetadataError(f"Cannot read BTF from {path}; install bpftool or supply local DWARF/layout: {detail[:2000]}") from exc

    @classmethod
    def from_dwarf(cls, elf, source):
        if not elf.has_dwarf_info():
            raise MetadataError(f"No DWARF in {source}")
        types = []
        dwarf = elf.get_dwarf_info()
        kinds = {
            "DW_TAG_structure_type": "STRUCT", "DW_TAG_union_type": "UNION",
            "DW_TAG_array_type": "ARRAY", "DW_TAG_pointer_type": "PTR",
            "DW_TAG_base_type": "INT", "DW_TAG_enumeration_type": "ENUM",
            "DW_TAG_typedef": "TYPEDEF", "DW_TAG_const_type": "CONST",
            "DW_TAG_volatile_type": "VOLATILE", "DW_TAG_restrict_type": "RESTRICT",
            "DW_TAG_variable": "VAR",
        }
        for cu in dwarf.iter_CUs():
            for die in cu.iter_DIEs():
                if die.tag not in kinds:
                    continue
                attrs = die.attributes
                def value(name, default=None):
                    attr = attrs.get(name)
                    return attr.value if attr else default
                def reference(item):
                    ref = item.get_DIE_from_attribute("DW_AT_type") if "DW_AT_type" in item.attributes else None
                    return ref.offset + 1 if ref else 0
                name = value("DW_AT_name", b"(anon)")
                record = {"id": die.offset + 1, "kind": kinds[die.tag],
                          "name": name.decode(errors="replace"), "type_id": reference(die)}
                record["size"] = value("DW_AT_byte_size", 8 if record["kind"] == "PTR" else 0)
                children = list(die.iter_children()) if die.has_children else []
                if record["kind"] in ("STRUCT", "UNION"):
                    members = []
                    for child in children:
                        if child.tag != "DW_TAG_member":
                            continue
                        ca = child.attributes
                        offset = ca.get("DW_AT_data_member_location")
                        offset = offset.value if offset else 0
                        if not isinstance(offset, int) or "DW_AT_bit_size" in ca:
                            continue
                        member_name = ca.get("DW_AT_name")
                        members.append({"name": member_name.value.decode() if member_name else "(anon)",
                                        "type_id": reference(child), "bits_offset": offset * 8})
                    record["members"] = members
                if record["kind"] == "ARRAY":
                    count = 1
                    dimensions = [c for c in children if c.tag == "DW_TAG_subrange_type"]
                    for child in dimensions:
                        ca = child.attributes
                        if "DW_AT_count" in ca:
                            dimension = ca["DW_AT_count"].value
                        elif "DW_AT_upper_bound" in ca:
                            dimension = ca["DW_AT_upper_bound"].value + 1 - (ca["DW_AT_lower_bound"].value if "DW_AT_lower_bound" in ca else 0)
                        else:
                            dimension = 0
                        count *= dimension if isinstance(dimension, int) else 0
                    record["nr_elems"] = count if dimensions else 0
                if record["kind"] == "ENUM":
                    record["values"] = [{"name": c.attributes["DW_AT_name"].value.decode(),
                                         "val": c.attributes["DW_AT_const_value"].value}
                                        for c in children if c.tag == "DW_TAG_enumerator"]
                types.append(record)
        return cls(types, f"dwarf:{source}")

    def resolve(self, type_id):
        seen = set()
        while type_id in self.types and type_id not in seen:
            seen.add(type_id)
            record = self.types[type_id]
            if record["kind"] not in self.WRAPPERS:
                return record
            type_id = record["type_id"]
        raise MetadataError(f"Unresolvable type {type_id} in {self.source}")

    def named(self, name, kind):
        candidates = [t for t in self.types.values() if t.get("name") == name and t["kind"] == kind]
        for candidate in candidates:
            if candidate.get("members") or candidate.get("values") or kind == "VAR":
                return candidate
        raise MetadataError(f"Missing {kind} {name} in {self.source}")

    def sizeof(self, record):
        record = self.resolve(record["id"])
        if record["kind"] == "ARRAY":
            return record["nr_elems"] * self.sizeof(self.resolve(record["type_id"]))
        if record["kind"] == "PTR":
            return 8
        return record.get("size", 0)

    def member(self, record, name):
        for member in record.get("members", []):
            if member["name"] == name:
                if member["bits_offset"] % 8 or member.get("bitfield_size", 0):
                    raise MetadataError(f"Unsupported bitfield {name}")
                target = self.resolve(member["type_id"])
                return Field(member["bits_offset"] // 8, self.sizeof(target)), target
        raise MetadataError(f"Missing member {record.get('name')}.{name}")

    def array_count(self, name):
        # DWARF can contain incomplete extern declarations before the complete
        # definition. Inspect all declarations rather than accepting a zero count.
        for variable in self.types.values():
            if variable.get("name") != name or variable["kind"] != "VAR":
                continue
            array = self.resolve(variable["type_id"])
            if (array["kind"] == "ARRAY" and array.get("nr_elems", 0) > 0
                    and self.sizeof(self.resolve(array["type_id"])) == 8):
                return array["nr_elems"]
        raise MetadataError(f"No complete array of 8-byte entries for {name} in {self.source}")

    def module_layout(self):
        module = self.named("module", "STRUCT")
        state, state_type = self.member(module, "state")
        name, name_type = self.member(module, "name")
        if name_type["kind"] != "ARRAY":
            raise MetadataError("module.name is not an array")
        link, link_type = self.member(module, "list")
        next_field, _ = self.member(link_type, "next")
        prev_field, _ = self.member(link_type, "prev")
        regions = []
        if any(m["name"] == "mem" for m in module.get("members", [])):
            memory, array = self.member(module, "mem")
            if array["kind"] != "ARRAY" or not 1 <= array["nr_elems"] <= 64:
                raise MetadataError("Unsupported module.mem array")
            entry = self.resolve(array["type_id"])
            stride = self.sizeof(entry)
            base, _ = self.member(entry, "base")
            size, _ = self.member(entry, "size")
            enum = self.named("mod_mem_type", "ENUM")
            names = {v["val"]: v["name"].removeprefix("MOD_").lower() for v in enum["values"]}
            for index in range(array["nr_elems"]):
                if index not in names:
                    raise MetadataError(f"No module memory type name for index {index}")
                offset = memory.offset + index * stride
                regions.append(RegionLayout(names[index], Field(offset + base.offset, base.size), Field(offset + size.offset, size.size)))
        else:
            for region_name in ("core", "init"):
                region, region_type = self.member(module, f"{region_name}_layout")
                base, _ = self.member(region_type, "base")
                size, _ = self.member(region_type, "size")
                regions.append(RegionLayout(region_name, Field(region.offset + base.offset, base.size), Field(region.offset + size.offset, size.size)))
        states = {v["val"]: v["name"].removeprefix("MODULE_STATE_") for v in state_type.get("values", [])}
        self_pointer = None
        if any(m["name"] == "mkobj" for m in module.get("members", [])):
            kobject, kobject_type = self.member(module, "mkobj")
            reference, _ = self.member(kobject_type, "mod")
            self_pointer = Field(kobject.offset + reference.offset, reference.size)
        return ModuleLayout(self.sizeof(module), state, name,
                            Field(link.offset + next_field.offset, next_field.size),
                            Field(link.offset + prev_field.offset, prev_field.size),
                            regions, states, self.source, self_pointer).validate()
