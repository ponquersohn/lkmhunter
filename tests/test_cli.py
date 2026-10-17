import importlib
import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

from lkmhunter.cli import main, parser


def test_legacy_imports_are_side_effect_free():
    with patch('lkmhunter.cli.KernelSession.open') as opening:
        for name in ['compare_syscalls', 'ftrace_hunt', 'find_module']:
            importlib.import_module(name)
        opening.assert_not_called()


def test_json_status_and_exit_codes(tmp_path, capsys):
    trace = tmp_path / 'trace'
    trace.write_text('')
    assert main(['scan', 'ftrace', '--path', str(trace), '--json']) == 0
    assert json.loads(capsys.readouterr().out)['status'] == 'complete'
    trace.unlink()
    assert main(['scan', 'ftrace', '--path', str(trace), '--json']) == 2
    assert json.loads(capsys.readouterr().out)['status'] == 'failed'


def test_common_options_and_old_syscall_arguments():
    args = parser().parse_args(['--backend', 'kcore', 'scan', '--debug', 'syscalls',
                               '--loaded_kernel_image', '/image', '--running_kernel_sysmap', '/symbols'])
    assert args.backend == 'kcore'
    assert args.vmlinux == '/image'
    assert args.kallsyms == '/symbols'
    assert args.debug


def test_wrappers_use_same_cli(tmp_path):
    trace = tmp_path / 'trace'
    trace.write_text('')
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run([sys.executable, str(root / 'ftrace_hunt.py'), '--path', str(trace), '--json'],
                            capture_output=True, text=True, cwd=tmp_path)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)['status'] == 'complete'
