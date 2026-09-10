"""Deterministic synthetic PE file; it is for parsing, never execution."""
import struct
from pathlib import Path


def make_pe():
    data = bytearray(0x1810)
    def w16(off, n): struct.pack_into('<H', data, off, n)
    def w32(off, n): struct.pack_into('<I', data, off, n)
    def w64(off, n): struct.pack_into('<Q', data, off, n)
    def put(off, value): data[off:off + len(value)] = value
    def directory(index, rva, size):
        w32(0x108 + index * 8, rva)
        w32(0x10c + index * 8, size)
    put(0, b'MZ'); w32(60, 0x80); put(0x80, b'PE\0\0')
    w16(0x84, 0x8664); w16(0x86, 3); w16(0x94, 240); w16(0x96, 0x2022)
    w16(0x98, 0x20b); w32(0xa8, 0x1000); w64(0xb0, 0x180000000)
    w32(0xb8, 0x1000); w32(0xbc, 0x200); w32(0xd0, 0x5000)
    w32(0xd4, 0x400); w16(0xdc, 3); w16(0xde, 0x160); w32(0x104, 16)
    for i, (name, va, size, raw, flags) in enumerate([
        (b'.text', 0x1000, 0x200, 0x400, 0x60000020),
        (b'.rdata', 0x2000, 0x1000, 0x600, 0x40000040),
        (b'.reloc', 0x4000, 0x200, 0x1600, 0x42000040),
    ]):
        h = 0x188 + i * 40
        put(h, name); w32(h + 8, size); w32(h + 12, va)
        w32(h + 16, size); w32(h + 20, raw); w32(h + 36, flags)
    put(0x400, b'\x90\x90\xc3')
    w64(0x440, 0x180001100)
    directory(1, 0x2000, 40)
    w32(0x600, 0x2080); w32(0x60c, 0x2040); w32(0x610, 0x2100)
    put(0x640, b'KERNEL32.dll\0')
    symbols = [b'GetTickCount', b'GetCurrentProcessId', b'CloseHandle', b'GetLastError']
    for i, name in enumerate(symbols):
        w64(0x680 + 8 * i, 0x2180 + 0x30 * i)
        w64(0x700 + 8 * i, 0x2180 + 0x30 * i)
        put(0x782 + 0x30 * i, name + b'\0')
    directory(0, 0x2300, 0xc0)
    w32(0x910, 1); w32(0x914, 2); w32(0x918, 2)
    w32(0x91c, 0x2360); w32(0x920, 0x2370); w32(0x924, 0x2380)
    w32(0x960, 0x1000); w32(0x964, 0x1010)
    w32(0x970, 0x2390); w32(0x974, 0x23a0); w16(0x980, 0); w16(0x982, 1)
    put(0x990, b'demo_target\0'); put(0x9a0, b'demo_helper\0')
    directory(9, 0x2400, 40); w64(0xa18, 0x180002480); w64(0xa80, 0x180001000)
    directory(5, 0x4000, 24)
    w32(0x1600, 0x1000); w32(0x1604, 12); w16(0x1608, 0xa040)
    w32(0x160c, 0x2000); w32(0x1610, 12); w16(0x1614, 0xa418); w16(0x1616, 0xa480)
    directory(2, 0x2500, 128)
    w16(0xb0e, 1); w32(0xb10, 10); w32(0xb14, 0x80000018)
    w16(0xb26, 1); w32(0xb28, 1); w32(0xb2c, 0x80000030)
    w16(0xb3e, 1); w32(0xb40, 1033); w32(0xb44, 72)
    w32(0xb48, 0x2600); w32(0xb4c, 16); put(0xc00, b'pe analyzer test')
    directory(4, 0x1800, 16)
    w32(0x1800, 16); w16(0x1804, 0x200); w16(0x1806, 2)
    put(0x1808, b'SYNTHETC')
    return data


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    original = make_pe()
    (args.output / 'sample.pe').write_bytes(original)
    changed = bytearray(original)
    struct.pack_into('<I', changed, 0x188 + 36, 0xe0000020)
    changed[0x410:0x415] = b'\xe9\x10\x00\x00\x00'
    (args.output / 'changed.pe').write_bytes(changed)
    print(f'Wrote synthetic parsing fixtures to {args.output}. Do not execute them.')
