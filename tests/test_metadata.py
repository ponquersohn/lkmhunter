import json
import shutil
import subprocess

import pytest

from lkmhunter import KernelSession, MetadataError
from lkmhunter.memory import ElfMemory
from lkmhunter.metadata import ModuleLayout, TypeGraph


@pytest.fixture
def types():
    return [
        {'id': 1, 'kind': 'INT', 'name': 'char', 'size': 1},
        {'id': 2, 'kind': 'INT', 'name': 'unsigned long', 'size': 8},
        {'id': 3, 'kind': 'INT', 'name': 'unsigned int', 'size': 4},
        {'id': 4, 'kind': 'ARRAY', 'type_id': 1, 'nr_elems': 32},
        {'id': 5, 'kind': 'PTR', 'type_id': 1},
        {'id': 6, 'kind': 'STRUCT', 'name': 'list_head', 'size': 16,
         'members': [{'name': 'next', 'type_id': 5, 'bits_offset': 0},
                     {'name': 'prev', 'type_id': 5, 'bits_offset': 64}]},
        {'id': 7, 'kind': 'ENUM', 'name': 'module_state', 'size': 4,
         'values': [{'name': 'MODULE_STATE_LIVE', 'val': 0}]},
        {'id': 8, 'kind': 'STRUCT', 'name': 'module_memory', 'size': 16,
         'members': [{'name': 'base', 'type_id': 5, 'bits_offset': 0},
                     {'name': 'size', 'type_id': 3, 'bits_offset': 64}]},
        {'id': 9, 'kind': 'ARRAY', 'type_id': 8, 'nr_elems': 2},
        {'id': 10, 'kind': 'ENUM', 'name': 'mod_mem_type', 'size': 4,
         'values': [{'name': 'MOD_TEXT', 'val': 0}, {'name': 'MOD_DATA', 'val': 1}]},
        {'id': 11, 'kind': 'STRUCT', 'name': 'module', 'size': 88,
         'members': [{'name': 'state', 'type_id': 7, 'bits_offset': 0},
                     {'name': 'list', 'type_id': 6, 'bits_offset': 64},
                     {'name': 'name', 'type_id': 4, 'bits_offset': 192},
                     {'name': 'mem', 'type_id': 9, 'bits_offset': 448}]},
    ]


def test_btf_layout_is_derived_and_round_trips(types, tmp_path):
    layout = TypeGraph(types, 'fixture').module_layout()
    assert layout.size == 88
    assert layout.name.offset == 24
    assert layout.regions[1].base.offset == 72
    assert layout.regions[1].size.offset == 80
    assert layout.states == {0: 'LIVE'}
    path = tmp_path / 'layout.json'
    path.write_text(json.dumps(layout.to_dict()))
    restored = ModuleLayout.from_file(path)
    assert restored.regions == layout.regions
    with KernelSession(layout=path) as session:
        assert session.module_layout.source.startswith('layout:')


def test_legacy_core_init_layout(types):
    module = types[-1]
    module['size'] = 88
    module['members'][-1:] = [
        {'name': 'core_layout', 'type_id': 8, 'bits_offset': 448},
        {'name': 'init_layout', 'type_id': 8, 'bits_offset': 576},
    ]
    layout = TypeGraph(types, 'fixture').module_layout()
    assert [r.name for r in layout.regions] == ['core', 'init']


def test_rejects_missing_or_out_of_bounds_layout(types):
    types[-1]['size'] = 10
    with pytest.raises(MetadataError, match='outside'):
        TypeGraph(types, 'fixture').module_layout()
    with pytest.raises(MetadataError, match='Missing'):
        TypeGraph([], 'fixture').module_layout()


def test_missing_btf_uses_dwarf_layout(types):
    with KernelSession(btf=None) as session:
        session.__dict__['dwarf'] = TypeGraph(types, 'dwarf:fixture')
        assert session.module_layout.source == 'dwarf:fixture'
        assert any('BTF disabled' in diagnostic for diagnostic in session.diagnostics)


def test_dwarf_extracts_actual_compiler_layout_and_syscall_count(tmp_path):
    if not shutil.which('cc'):
        pytest.skip('C compiler not installed')
    source = tmp_path / 'types.c'
    source.write_text('''
    enum module_state { MODULE_STATE_LIVE, MODULE_STATE_GOING };
    enum mod_mem_type { MOD_TEXT, MOD_DATA };
    struct list_head { void *next; void *prev; };
    struct module_memory { void *base; unsigned int size; };
    struct module;
    struct module_kobject { void *kobj; struct module *mod; };
    struct module { enum module_state state; struct list_head list; char name[32]; struct module_memory mem[2]; struct module_kobject mkobj; };
    struct module module_instance;
    enum mod_mem_type enum_instance;
    void *sys_call_table[451];
    int main(void) { return module_instance.state; }
    ''')
    binary = tmp_path / 'types'
    subprocess.run(['cc', '-g', '-O0', '-fno-eliminate-unused-debug-types', str(source), '-o', str(binary)], check=True)
    with ElfMemory(binary) as image:
        graph = TypeGraph.from_dwarf(image.elf, binary)
        layout = graph.module_layout()
        assert layout.size == 104
        assert layout.name.offset == 24
        assert layout.regions[1].size.offset == 80
        assert layout.self_pointer.offset == 96
        assert graph.array_count('sys_call_table') == 451
        notes = b''.join(s.data() for s in image.elf.iter_segments() if s['p_type'] == 'PT_NOTE')
    live_notes = tmp_path / 'notes'
    live_notes.write_bytes(notes)
    # Type layout discovery from an exactly identified image must not require
    # runtime symbol visibility or calculating a relocation it does not use.
    with KernelSession(vmlinux=binary, live_notes=live_notes, kallsyms=tmp_path / 'missing', btf=None) as session:
        assert session.module_layout.size == 104
