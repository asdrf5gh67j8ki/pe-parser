"""Windows-only regression: controlled self-modification, imports and unreadable pages."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from demo import DemoHost

EXE, HOST, DLL = (str(Path(x).resolve()) for x in sys.argv[1:4])
sys.argv[1:4] = []


class Live(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.host = DemoHost([HOST, DLL])
        cls.addClassCleanup(cls.host.close)
        cls.info = cls.host.info

    def command(self, text):
        self.host.command(text)

    def scan(self, *extra):
        result = subprocess.run([EXE, 'scan', str(self.info['pid']), '--module', Path(DLL).name,
                                 '--reference', DLL, '--json', '-', *map(str, extra)],
                                capture_output=True, text=True, encoding='utf-8', timeout=60)
        self.assertIn(result.returncode, (0, 1, 3), result.stderr)
        data = json.loads(result.stdout)
        self.assertFalse(data['failed'] or data['limited'])
        self.assertTrue(any(r['kind'] == 'reference' and r['status'] == 'info' for r in data['rows']))
        module_bases = {r['address'] for r in data['rows'] if r['kind'] == 'modules' and r['status'] == 'info'}
        self.assertFalse([r for r in data['rows'] if r['name'] == 'image.unlisted' and r['address'] in module_bases],
                         'An enumerated module allocation was reported as unlisted.')
        return data['rows']

    def test_inspection_sequence(self):
        rows = self.scan()
        patches = [r for r in rows if r['kind'] == 'patches']
        self.assertFalse(patches, json.dumps(patches, indent=2))
        comparison = [r for r in rows if r['kind'] == 'comparison' and r['name'] == '.pstest']
        self.assertTrue(comparison, 'Executable test section is missing.')
        self.assertTrue(any(r['kind'] == 'iat' and r['name'] == 'GetTickCount' for r in rows))
        self.command('patch')
        with tempfile.TemporaryDirectory() as directory:
            rows = self.scan('--dump', directory)
            patch = int(self.info['patch'], 16)
            self.assertTrue(any(r['kind'] == 'patches' and int(r['address'], 16) == patch for r in rows))
            self.assertTrue(any(r['kind'] == 'hooks' and 'mov rax' in r['name'] for r in rows))
            self.assertTrue(any(r['name'] == 'pe-like.non-image' for r in rows))
            maps = list(Path(directory).glob('*.map.json'))
            self.assertTrue(maps)
            for path in maps:
                m = json.loads(path.read_text())
                raw = Path(str(path).replace('.map.json', '.bin'))
                self.assertEqual(raw.stat().st_size, m['stored'])
                self.assertEqual(sum(c['requested'] for c in m['chunks']), m['stored'])
        self.command('iat')
        rows = self.scan()
        self.assertTrue(any(r['kind'] == 'iat' and r['name'] == 'GetTickCount' and r['status'] == 'review' for r in rows))
        self.command('noaccess')
        rows = self.scan()
        self.assertTrue(any(r['kind'] == 'comparison' and r['name'] == 'unreadable' for r in rows))
        self.command('restore')
        rows = self.scan()
        self.assertFalse(any(r['kind'] == 'patches' for r in rows))


if __name__ == '__main__':
    unittest.main(verbosity=2)
