import json
import subprocess
import sys
from pathlib import Path

from lkmhunter.cli import main, parser, render
from lkmhunter.results import Finding, ScanResult


def test_text_addresses_are_hex_and_json_remains_numeric(capsys):
    evidence = {"site": 0xffffffff81000000, "actual": 0xffffffffc0be6010,
                "expected": 0xffffffff81200000, "offset": 2274,
                "actual_bytes": "e8795de90a", "actual_instruction": "call 0xffffffffc0be6010"}
    result = ScanResult("syscalls", findings=[Finding("hook", "Changed call", evidence)],
                        coverage={"dispatcher": {"address": evidence["site"], "size": 7000}})
    render(result, "text")
    output = capsys.readouterr().out
    displayed = json.loads(output.splitlines()[2].strip())
    for key in ("site", "actual", "expected"):
        assert displayed[key] == hex(evidence[key])
    assert displayed["offset"] == 2274
    assert displayed["actual_bytes"] == evidence["actual_bytes"]
    assert displayed["actual_instruction"] == evidence["actual_instruction"]
    coverage = json.loads(output.split("Coverage: ")[1])
    assert coverage["dispatcher"] == {"address": hex(evidence["site"]), "size": 7000}
    render(result, "json")
    assert json.loads(capsys.readouterr().out)["findings"][0]["evidence"] == evidence


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
