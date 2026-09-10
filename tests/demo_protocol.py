"""Exercise fixture startup and cleanup without requiring a Windows scanner."""
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from demo import DemoHost


class Protocol(unittest.TestCase):
    def start(self, source, **options):
        created = []
        popen = subprocess.Popen

        def spawn(*args, **kwargs):
            process = popen(*args, **kwargs)
            created.append(process)
            return process

        def check_cleanup():
            for process in created:
                self.assertIsNotNone(process.poll(), 'Fixture process leaked.')
                self.assertTrue(process.stdin.closed)
                self.assertTrue(process.stdout.closed)

        self.addCleanup(check_cleanup)
        with patch('demo.subprocess.Popen', side_effect=spawn):
            host = DemoHost([sys.executable, '-u', '-c', source], **options)
        self.addCleanup(host.close)
        return host

    def test_early_exit_reports_code(self):
        with self.assertRaisesRegex(RuntimeError, r'exit code 7 \(0x00000007\)'):
            self.start('import sys; sys.exit(7)')

    def test_stderr_is_reported_including_unterminated_line(self):
        with self.assertRaisesRegex(RuntimeError, 'LoadLibrary failed: 193.*exit code 9'):
            self.start("import sys; sys.stderr.write('LoadLibrary failed: 193'); sys.exit(9)")

    def test_invalid_ready_record_is_reported(self):
        with self.assertRaisesRegex(RuntimeError, 'failed during startup'):
            self.start("print('[1, 2, 3]')")

    def test_timeout_terminates_and_closes_fixture(self):
        with self.assertRaisesRegex(RuntimeError, 'did not respond within'):
            self.start('import sys; sys.stdin.read()', timeout=0.05)

    def test_command_failure_reports_output(self):
        host = self.start("import sys\nprint('{\"pid\":123}')\n"
                          "sys.stdin.readline()\n"
                          "print('VirtualProtect failed: 5', file=sys.stderr)\nsys.exit(11)")
        with self.assertRaisesRegex(RuntimeError, 'VirtualProtect failed: 5.*exit code 11'):
            host.command('patch')

    def test_ready_commands_and_clean_shutdown(self):
        host = self.start("import sys\nprint('{\"pid\":123}')\n"
                          "for line in sys.stdin:\n"
                          "    if line.strip() == 'quit': break\n"
                          "    print('ok')\n")
        self.assertEqual(host.info['pid'], 123)
        host.command('patch')
        host.command('restore')


if __name__ == '__main__':
    unittest.main(verbosity=2)
