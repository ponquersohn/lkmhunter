import tempfile
import unittest
import subprocess
from unittest.mock import patch
from pathlib import Path

from debugfs_hunt import hunt, parse_entry, run_command, Debugfs


class HuntTests(unittest.TestCase):
    def test_descends_into_hidden_directory_and_reports_its_file(self):
        class Disk:
            def listdir(self, path):
                return {
                    '/': [{'name': 'hidden', 'type': '04'},
                          {'name': 'visible', 'type': '10'}],
                    '/hidden': [{'name': 'payload.ko', 'type': '10'}],
                }[path]

        with tempfile.TemporaryDirectory() as root:
            Path(root, 'visible').touch()
            self.assertEqual(list(hunt(Disk(), '/', Path(root))),
                             ['/hidden', '/hidden/payload.ko'])

    def test_parses_ext4_directory_entry(self):
        self.assertEqual(parse_entry('/1004579/040775/1000/1000/Singularity//'),
                         {'name': 'Singularity', 'type': '04', 'perm': '040775'})

    def test_rejects_malformed_entry(self):
        with self.assertRaises(ValueError):
            parse_entry('/unexpected/output')

    def test_subprocess_failure_logs_captured_diagnostics(self):
        failure = subprocess.CalledProcessError(1, ['debugfs'],
                                               output='partial output', stderr='device error')
        with patch('debugfs_hunt.subprocess.run', side_effect=failure):
            with self.assertLogs('debugfs_hunt', level='DEBUG') as logs:
                with self.assertRaises(subprocess.CalledProcessError):
                    run_command(['debugfs'], 15)
        self.assertIn('partial output', '\n'.join(logs.output))
        self.assertIn('device error', '\n'.join(logs.output))

    def test_debug_enables_helper_diagnostics(self):
        result = subprocess.CompletedProcess([], 0, '/2/040755/0/0/.//\n', '')
        with patch('debugfs_hunt.subprocess.run', return_value=result) as run:
            with self.assertLogs('debugfs_hunt', level='DEBUG'):
                self.assertEqual(Debugfs('/dev/test', helper='/tmp/helper').listdir('/'), [])
        self.assertEqual(run.call_args.kwargs['env']['LKMHUNTER_DEBUGFS_DEBUG'], '1')


if __name__ == '__main__':
    unittest.main()
