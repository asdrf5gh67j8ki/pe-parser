"""Windows GUI smoke test: real HWNDs, worker, filtering, selection and export."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from fixtures import make_pe


def main():
    executable = Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory(prefix='pe-gui-') as directory:
        root = Path(directory)
        source, output = root / 'résumé-分析.pe', root / 'result.json'
        source.write_bytes(make_pe())
        subprocess.run([str(executable), '--smoke', str(source), str(output)], check=True, timeout=60)
        result = json.loads(output.read_text(encoding='utf-8'))
        assert result['subject'] == str(source)
        assert any(row['name'] == 'ImageBase' for row in result['rows'])
        assert len([row for row in result['rows'] if row['kind'] == 'imports']) == 4
        assert not result['failed'] and not result['limited']
    print('Windows GUI worker, virtual rows, search, selection, group collapse, Unicode input and export passed.')


if __name__ == '__main__': main()
