"""End-to-end CLI regression tests, standard library only."""
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile
import unittest
from fixtures import make_pe

EXE = str(Path(sys.argv.pop(1)).resolve())


class CLI(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source = self.root / 'sample.exe'
        self.source.write_bytes(make_pe())

    def tearDown(self):
        self.temp.cleanup()

    def call(self, *args, status=0):
        result = subprocess.run([EXE, *map(str, args)], capture_output=True,
                                text=True, encoding='utf-8', timeout=30)
        self.assertEqual(result.returncode, status, result.stdout + result.stderr)
        return result

    def inspect(self, status=0):
        return json.loads(self.call('inspect', self.source, '--json', '-', status=status).stdout)

    def test_full_inspection(self):
        result = self.inspect()
        kinds = {r['kind'] for r in result['rows']}
        self.assertTrue({'headers', 'sections', 'imports', 'exports', 'tls',
                         'relocations', 'resources', 'certificates', 'coverage'} <= kinds)
        digest = next(r for r in result['rows'] if r['name'] == 'SHA-256')['detail']
        self.assertEqual(digest, hashlib.sha256(self.source.read_bytes()).hexdigest())
        self.assertFalse(result['failed'] or result['limited'])
        self.assertEqual(sum(r['size'] for r in result['rows'] if r['kind'] == 'coverage'),
                         self.source.stat().st_size)
        self.assertEqual(len([r for r in result['rows'] if r['kind'] == 'imports']), 4)

    def test_summary_preserves_report(self):
        out = self.root / 'report.json'
        self.call('inspect', self.source, '--summary', '--json', out)
        self.assertEqual(json.loads(out.read_text())['rows'], self.inspect()['rows'])

    def test_identical_diff(self):
        result = json.loads(self.call('diff', self.source, self.source, '--json', '-').stdout)
        self.assertEqual(result['counts'][1], 0)

    def test_changed_file_same_entropy(self):
        other = self.root / 'other.exe'
        data = bytearray(self.source.read_bytes())
        data[0x1808], data[0x1809] = data[0x1809], data[0x1808]
        other.write_bytes(data)
        result = json.loads(self.call('diff', self.source, other, '--json', '-', status=3).stdout)
        self.assertTrue(any(r['name'] == 'file-content' for r in result['rows']))

    def test_html_cannot_execute_input(self):
        data = bytearray(self.source.read_bytes())
        payload = b'</script><script>globalThis.INJECTED=1</script>'
        data[0x782:0x782 + len(payload) + 1] = payload + b'\0'
        self.source.write_bytes(data)
        html = self.root / 'report.html'
        self.call('inspect', self.source, '--html', html, '--summary')
        text = html.read_text()
        raw = re.search(r'<script id="payload" type="application/json">\s*(.*?)</script>',
                        text, re.S).group(1)
        decoded = json.loads(raw)
        self.assertTrue(any('</script>' in r['name'] for r in decoded['rows']))
        self.assertNotIn('</script>', raw)

    def test_terminal_controls(self):
        data = bytearray(self.source.read_bytes())
        data[0x188:0x190] = b'\x1b[31mTXT'
        self.source.write_bytes(data)
        result = self.call('inspect', self.source, '--no-color')
        self.assertNotIn('\x1b', result.stdout)
        self.assertIn('\\x1b', result.stdout)

    def test_unicode_paths(self):
        new = self.root / 'résumé-分析.exe'
        self.source.rename(new)
        result = json.loads(self.call('inspect', new, '--json', '-').stdout)
        self.assertEqual(result['subject'], str(new))

    def test_truncated_pe(self):
        self.source.write_bytes(b'MZ')
        result = self.inspect(status=1)
        self.assertEqual(result['counts'][3], 1)

    def test_ambiguous_sections(self):
        data = bytearray(self.source.read_bytes())
        struct.pack_into('<I', data, 0x1b0 + 12, 0x1000)
        self.source.write_bytes(data)
        result = self.inspect(status=1)
        self.assertTrue(any(r['name'] == 'sections.overlap' for r in result['rows']))
        self.assertTrue(result['counts'][4])

    def test_reject_output_alias(self):
        before = self.source.read_bytes()
        self.call('inspect', self.source, '--json', self.source, status=2)
        self.assertEqual(before, self.source.read_bytes())

    def test_existing_report_is_preserved(self):
        target = self.root / 'existing.json'
        target.write_text('keep me')
        self.call('inspect', self.source, '--json', target, status=1)
        self.assertEqual(target.read_text(), 'keep me')

    def test_arguments(self):
        for args in [('scan', '-1'), ('scan', '0'), ('scan', '4294967296'),
                     ('inspect',), ('scan', '--all', '123'), ('scan', '12', '--reference', 'x'),
                     ('inspect', self.source, '--module', 'x'), ('inspect', self.source, '--unknown')]:
            self.call(*args, status=2)
        self.assertEqual(self.call('--version').stdout.strip(), '1.1.0')

    def test_platform_failure_is_explicit(self):
        if os.name == 'nt':
            return
        result = json.loads(self.call('scan', '1', '--json', '-', status=1).stdout)
        self.assertEqual(result['rows'][0]['name'], 'platform')


if __name__ == '__main__':
    unittest.main(verbosity=2)
