"""VG-21 tool: encode (compress) and decode (restore).

Run ``python main.py`` and pick 1 or 2. Encoding uses the VG-21X archiver from
``encoder.py`` (a portfolio that always includes Brotli q11, so the archive is
never larger than the best q11 stream); decoding uses ``decoder.py`` and needs no
options, because every archive describes itself.
"""
from __future__ import annotations

from pathlib import Path

from decoder import decode_path
from encoder import EFFORT_BEST, EFFORT_FAST, encode_path


def _ask_path(prompt: str):
    raw = input(prompt).strip().strip('"')
    return Path(raw).expanduser() if raw else None


def _ask_output(default_hint: str):
    raw = input(f'Output path (Enter for {default_hint}): ').strip().strip('"')
    return Path(raw).expanduser() if raw else None


def _ask_effort():
    raw = input('Mode - [b]est ratio or [f]ast (Enter for best): ').strip().lower()
    return EFFORT_FAST if raw.startswith('f') else EFFORT_BEST


def _encode() -> None:
    source = _ask_path('\nPath to the file or folder you want to compress: ')
    if source is None:
        print('No path given; nothing changed.')
        return
    if not source.exists():
        print(f'Encoding failed: path not found: {source}')
        return
    destination = _ask_output(f'{source.name}.v21x')
    effort = _ask_effort()
    print('\nCompressing...')
    try:
        archive, stats = encode_path(source, destination, effort)
    except (OSError, ValueError, RuntimeError) as error:
        print(f'Encoding failed: {error}')
        return

    print(f'\nEncoding complete: {archive}')
    if 'files' in stats:
        print(f'Files:        {stats["files"]:,}')
    if stats.get('duplicates'):
        print(f'Duplicates:   {stats["duplicates"]:,} '
              f'({stats["dup_saved"]:,} bytes stored once)')
    raw = stats.get('raw') or source.stat().st_size
    saved = raw - stats['ours']
    print(f'Raw size:     {raw:,} bytes')
    print(f'Archive size: {stats["ours"]:,} bytes')
    if raw:
        print(f'Result:       {100.0 * saved / raw:.1f}% {"smaller" if saved >= 0 else "larger"}')
    if stats.get('winner'):
        print(f'Recipe:       {stats["winner"]}')
    if not saved:
        print('Note:         this data is already compressed or incompressible,')
        print('              so it was stored unchanged - no lossless gain exists.')


def _decode() -> None:
    source = _ask_path('\nPath to the .v21x archive: ')
    if source is None:
        print('No path given; nothing changed.')
        return
    destination = _ask_output('the name stored in the archive')
    print('\nDecompressing...')
    try:
        restored = decode_path(source, destination)
    except (OSError, ValueError) as error:
        print(f'Decoding failed: {error}')
        return
    kind = 'folder' if restored.is_dir() else 'file'
    print(f'\nDecoding complete: {restored} ({kind} restored)')


def main() -> None:
    print('=' * 52)
    print('                 VG-21 TOOL')
    print('            lossless encode / decode')
    print('=' * 52)
    while True:
        print('\n1. Encode  (compress a file or folder to .v21x)')
        print('2. Decode  (restore a .v21x archive)')
        print('0. Exit')
        choice = input('\nWhat do you want to do? [1/2/0]: ').strip() or '1'
        if choice == '0':
            print('Goodbye!')
            return
        if choice == '1':
            _encode()
        elif choice == '2':
            _decode()
        else:
            print('Invalid option: choose 1, 2 or 0.')


if __name__ == '__main__':
    try:
        main()
    except (EOFError, KeyboardInterrupt):
        print('\nCancelled.')
