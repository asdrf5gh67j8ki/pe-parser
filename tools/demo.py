"""Run the controlled Windows demo and save before/after/unreadable reports."""
import argparse
import json
from pathlib import Path
import queue
import subprocess
import tempfile
import threading


class DemoHost:
    """Own the fixture process and turn EOF/startup failures into useful errors."""

    def __init__(self, command, timeout=15):
        self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT, text=True, encoding='utf-8',
                                        errors='replace', bufsize=1)
        self.lines = queue.Queue()
        self.ready = False
        self.thread = threading.Thread(target=self._read, daemon=True)
        self.thread.start()
        try:
            line = self._line(timeout)
            try:
                self.info = json.loads(line)
                if not isinstance(self.info, dict) or type(self.info.get('pid')) is not int:
                    raise ValueError('Expected a JSON object with an integer pid.')
            except ValueError as error:
                raise RuntimeError(f'Demo host failed during startup: {line.strip()!r}; '
                                   f'{self._status()}.') from error
            self.ready = True
        except Exception:
            self.close()
            raise

    def _read(self):
        try:
            for line in self.process.stdout:
                self.lines.put(line)
        finally:
            self.lines.put(None)

    def _status(self):
        try:
            code = self.process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            return 'process is still running'
        return f'exit code {code} (0x{code & 0xffffffff:08X})'

    def _line(self, timeout):
        try:
            line = self.lines.get(timeout=timeout)
        except queue.Empty as error:
            raise RuntimeError(f'Demo host did not respond within {timeout:g}s; '
                               f'{self._status()}.') from error
        if line is None:
            raise RuntimeError(f'Demo host closed its output; {self._status()}.')
        return line

    def command(self, text):
        try:
            self.process.stdin.write(text + '\n')
            self.process.stdin.flush()
        except OSError as error:
            raise RuntimeError(f'Demo host could not receive {text!r}; {self._status()}.') from error
        reply = self._line(15).strip()
        if reply != 'ok':
            raise RuntimeError(f'Demo host rejected {text!r}: {reply!r}; {self._status()}.')

    def close(self):
        try:
            if self.ready and self.process.poll() is None:
                try:
                    self.process.stdin.write('restore\nquit\n')
                    self.process.stdin.flush()
                    self.process.wait(timeout=10)
                except (OSError, subprocess.TimeoutExpired):
                    pass
        finally:
            if self.process.poll() is None:
                self.process.kill()
            self.process.wait()
            self.thread.join()
            self.process.stdin.close()
            self.process.stdout.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bin', type=Path, default=Path.cwd())
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    binary = args.bin.resolve()
    output = (args.output or Path(tempfile.mkdtemp(prefix='pe-analyzer-demo-'))).resolve()
    output.mkdir(parents=True, exist_ok=True)
    exe, host, dll = (binary / name for name in ('pe-analyzer.exe', 'demo_host.exe', 'demo_module.dll'))
    if not all(path.is_file() for path in (exe, host, dll)):
        parser.error('--bin must contain pe-analyzer.exe, demo_host.exe, and demo_module.dll')
    session = DemoHost([str(host), str(dll)])
    try:
        info = session.info
        command = session.command
        def scan(label):
            print(f'\n{label}: inspecting the controlled test process...', flush=True)
            result = subprocess.run([str(exe), 'scan', str(info['pid']), '--module', dll.name,
                                     '--reference', str(dll), '--summary',
                                     '--html', str(output / (label + '.html')),
                                     '--json', str(output / (label + '.json'))], timeout=90)
            if result.returncode not in (0, 1, 3):
                raise RuntimeError('Scanner could not run.')
            data = json.loads((output / (label + '.json')).read_text(encoding='utf-8'))
            if data['failed'] or data['limited']:
                raise RuntimeError('Scan exceeded a resource limit.')
            return data['rows']
        before = scan('01-before')
        if any(row['kind'] == 'patches' for row in before):
            raise RuntimeError('Unexpected baseline differences. Inspect 01-before.html.')
        if not any(row['kind'] == 'comparison' and row['name'] == '.pstest' for row in before):
            raise RuntimeError('The test section was not inspected.')
        command('patch')
        command('iat')
        after = scan('02-after')
        if not any(row['kind'] == 'patches' and int(row['address'], 16) == int(info['patch'], 16) for row in after):
            raise RuntimeError('The controlled patch was not reported.')
        command('noaccess')
        unreadable = scan('03-unreadable')
        if not any(row['kind'] == 'comparison' and row['name'] == 'unreadable' for row in unreadable):
            raise RuntimeError('The unreadable test page was not reported.')
        command('restore')
        print(f'\nDemo verified. Open {output / "02-after.html"}')
        print('Also compare 01-before.html and 03-unreadable.html.')
    finally:
        session.close()


if __name__ == '__main__':
    main()
