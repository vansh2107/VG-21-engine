"""VG-21 decoder: VG-21X archives, plus the older VG-21C + Base95 pipeline.

``decode_path`` is what ``main.py`` uses: it restores an archive, file or
folder, without needing to know which recipes the encoder chose.
"""
from __future__ import annotations

from pathlib import Path

from vg21c_codec import (decompress as vg21c_decompress,
                         X_DIR_MAGIC as DIR_MAGIC, X_MAGIC as MAGIC,
                         xg_unpack as vg21x_unpack, xg_unpack_file as vg21x_unpack_file,
                         xg_unpack_folder as vg21x_unpack_folder)

BASE95_ALPHABET = "".join(chr(i) for i in range(32, 127))
BASE = len(BASE95_ALPHABET)
MODE_RAW = 1
MODE_VG21C = 2
BLOCK_BYTES = 78
BLOCK_CHARS = 95


def base95_decode(text: str) -> bytes:
    """Decode printable Base95 text produced by base95_encode."""
    if not text:
        raise ValueError("Encoded data is empty.")
    remainder = ord(text[-1]) - 32
    if not 0 <= remainder < BLOCK_BYTES:
        raise ValueError("Invalid final length marker.")
    encoded_blocks = text[:-1]
    if len(encoded_blocks) % BLOCK_CHARS:
        raise ValueError("Invalid Base95 encoded length.")
    if remainder and not encoded_blocks:
        raise ValueError("Invalid partial-block marker.")

    result = bytearray()
    for pos in range(0, len(encoded_blocks), BLOCK_CHARS):
        chars = encoded_blocks[pos:pos + BLOCK_CHARS]
        number = 0
        for offset, char in enumerate(chars):
            value = ord(char) - 32
            if not 0 <= value < BASE:
                raise ValueError(f"Invalid Base95 character at position {pos + offset}.")
            number = number * BASE + value
        if number >= 1 << (8 * BLOCK_BYTES):
            raise ValueError("Invalid Base95 block value.")
        result.extend(number.to_bytes(BLOCK_BYTES, "big"))

    if remainder:
        del result[-(BLOCK_BYTES - remainder):]
    return bytes(result)


def decode_bytes(encoded: str) -> bytes:
    """Decode Base95 framing, then use the matching VG-21C decoder if needed."""
    framed = base95_decode(encoded)
    if not framed:
        raise ValueError("Missing mode marker.")
    mode, payload = framed[0], framed[1:]
    if mode == MODE_RAW:
        return payload
    if mode == MODE_VG21C:
        try:
            return vg21c_decompress(payload)
        except Exception as error:
            raise ValueError("Invalid or corrupted VG-21C payload.") from error
    raise ValueError(f"Unknown VG-21 mode: {mode}")


def decode_text(encoded: str) -> str:
    return decode_bytes(encoded).decode("utf-8")


def decode_file(input_path: str, output_path: str) -> None:
    with open(input_path, "r", encoding="ascii", newline="") as file:
        encoded = file.read()
    decoded = decode_bytes(encoded)
    with open(output_path, "wb") as file:
        file.write(decoded)
    print("\nDecoding completed successfully.")
    print(f"Encoded size: {len(encoded):,} characters")
    print(f"Decoded size: {len(decoded):,} bytes")
    print(f"Output saved: {output_path}")


def is_vg21x(blob: bytes) -> bool:
    """True when the bytes are a VG-21X archive (file or folder)."""
    return blob.startswith((MAGIC, DIR_MAGIC))


def decode_data(stream: bytes) -> bytes:
    """Restore one VG-21X file stream."""
    return vg21x_unpack(stream)


def _free_name(destination: Path) -> Path:
    """Never restore on top of something that already exists."""
    if not destination.exists():
        return destination
    name = destination.name
    candidate = destination.parent / ('%s (restored)' % name)
    n = 2
    while candidate.exists():
        candidate = destination.parent / ('%s (restored %d)' % (name, n))
        n += 1
    return candidate


def decode_path(path, output_path=None) -> Path:
    """Restore a ``.v21x`` archive and return where it landed.

    Folders come back with their original structure; a folder is never merged
    into an existing one, and a file never overwrites one.
    """
    path = Path(path).expanduser()
    if not path.is_file():
        raise FileNotFoundError('Archive not found: %s' % path)
    blob = path.read_bytes()
    if not is_vg21x(blob):
        raise ValueError('not a VG-21X archive: %s' % path)
    destination = Path(output_path).expanduser() if output_path else path.parent / (path.stem or 'restored')
    if blob.startswith(DIR_MAGIC):
        if output_path is None:
            destination = _free_name(destination)
        return vg21x_unpack_folder(blob, destination)
    if output_path is None:
        destination = _free_name(destination)
    return vg21x_unpack_file(blob, destination)


if __name__ == "__main__":
    source = input("Enter encoded TXT path: ").strip().strip('"')
    destination = input("Enter decoded output file path: ").strip().strip('"')
    try:
        decode_file(source, destination)
    except Exception as error:
        print(f"Decoding failed: {error}")
