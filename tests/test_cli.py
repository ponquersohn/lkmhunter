import json
import subprocess
import sys
from pathlib import Path

from lkmhunter.cli import main, parser


def test_json_status_and_exit_codes(tmp_path, capsys):
    trace = tmp_path / 'trace'
    trace.write_text('')
    assert main(['scan', 'ftrace', '--tracefs', str(trace), '--json']) == 0
    assert json.loads(capsys.readouterr().out)['status'] == 'complete'
    trace.unlink()
    assert main(['scan', 'ftrace', '--tracefs', str(trace), '--json']) == 2
    assert json.loads(capsys.readouterr().out)['status'] == 'failed'


def test_common_options_and_syscall_arguments():
    args = parser().parse_args(['--backend', 'kcore', 'scan', '--debug', 'syscalls',
                               '--vmlinux', '/image', '--kallsyms', '/symbols'])
    assert args.backend == 'kcore'
    assert args.vmlinux == '/image'
    assert args.kallsyms == '/symbols'
    assert args.debug


def test_module_entry_point(tmp_path):
    trace = tmp_path / 'trace'
    trace.write_text('')
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run([sys.executable, '-m', 'lkmhunter', 'scan', 'ftrace', '--tracefs', str(trace), '--json'],
                            capture_output=True, text=True, cwd=root)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)['status'] == 'complete'
