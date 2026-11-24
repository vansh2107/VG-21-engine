"""VG-21 encoder: VG-21X archives, plus the older VG-21C + Base95 pipeline.

``encode_path`` is what ``main.py`` uses: it compresses a file or a folder into
one self-describing archive (see ``vg21c_codec.py`` for the recipes).
``encode_bytes``/``encode_text``/``encode_file`` remain the printable-Base95
wrapper around VG-21C.
"""
from __future__ import annotations

from pathlib import Path

from vg21c_codec import (DEFAULT_PROFILE, compress as vg21c_compress,
                         X_EFFORT_BEST as EFFORT_BEST, X_EFFORT_FAST as EFFORT_FAST,
                         xg_pack as vg21x_pack, xg_pack_file as vg21x_pack_file,
                         xg_pack_folder as vg21x_pack_folder)

BASE95_ALPHABET = "".join(chr(i) for i in range(32, 127))
BASE = len(BASE95_ALPHABET)
MODE_RAW = 1
MODE_VG21C = 2
BLOCK_BYTES = 78
BLOCK_CHARS = 95


def base95_encode(data: bytes) -> str:
    """Encode bytes as printable Base95 using 78-byte / 95-character blocks."""
    output: list[str] = []
    for start in range(0, len(data), BLOCK_BYTES):
        block = data[start:start + BLOCK_BYTES].ljust(BLOCK_BYTES, b"\x00")
        number = int.from_bytes(block, "big")
        chars = [" "] * BLOCK_CHARS
        for i in range(BLOCK_CHARS - 1, -1, -1):
            number, remainder = divmod(number, BASE)
            chars[i] = BASE95_ALPHABET[remainder]
        if number:
            raise ValueError("Base95 block overflow.")
        output.append("".join(chars))

    # Final character stores original final-block length modulo 78.
    output.append(chr(32 + (len(data) % BLOCK_BYTES)))
    return "".join(output)


def encode_bytes(data: bytes, profile: str = DEFAULT_PROFILE) -> str:
    """Use VG-21C when it reduces the payload; otherwise preserve raw bytes."""
    compressed = vg21c_compress(data, profile=profile)
    if len(compressed) < len(data):
        mode, payload = MODE_VG21C, compressed
        selected = "VG-21C"
    else:
        mode, payload = MODE_RAW, data
        selected = "RAW (VG-21C did not reduce the payload)"

    framed = bytes([mode]) + payload
    encoded = base95_encode(framed)
    print("\n--- VG-21 Compression Report ---")
    print(f"Original size:       {len(data):,} bytes")
    print(f"VG-21C output size:  {len(compressed):,} bytes")
    print(f"Selected mode:      {selected}")
    print(f"Mode + payload:     {len(framed):,} bytes")
    print(f"Final Base95 size:  {len(encoded):,} characters")
    if data:
        print(f"Final chars/original byte: {len(encoded) / len(data):.4f}")
    return encoded


def encode_text(text: str, profile: str = DEFAULT_PROFILE) -> str:
    return encode_bytes(text.encode("utf-8"), profile=profile)


def encode_file(input_path: str, output_path: str, profile: str = DEFAULT_PROFILE) -> None:
    with open(input_path, "rb") as file:
        original = file.read()
    encoded = encode_bytes(original, profile=profile)
    with open(output_path, "w", encoding="ascii", newline="") as file:
        file.write(encoded)
    print("\nEncoding completed successfully.")
    print(f"Original size: {len(original):,} bytes")
    print(f"Encoded size:  {len(encoded):,} characters")
    print(f"Output saved:  {output_path}")


def encode_data(data: bytes, effort: str = EFFORT_BEST) -> tuple[bytes, dict]:
    """Compress raw bytes into a VG-21X stream; returns (stream, stats)."""
    return vg21x_pack(data, effort)


def encode_path(path, output_path=None, effort: str = EFFORT_BEST,
                progress=None) -> tuple[Path, dict]:
    """Compress a file or folder into a ``.v21x`` archive.

    Folders keep their structure and store identical files once. Returns
    ``(archive_path, stats)``; the archive is self-describing, so restoring it
    needs nothing but ``decoder.decode_path``.
    """
    path = Path(path).expanduser()
    if not path.exists():
        raise FileNotFoundError('Path not found: %s' % path)
    if path.is_dir():
        blob, stats = vg21x_pack_folder(path, effort, progress=progress)
    elif path.is_file():
        blob, stats = vg21x_pack_file(path, effort)
    else:
        raise ValueError('Choose a regular file or directory.')
    destination = (Path(output_path).expanduser() if output_path
                   else path.with_name(path.name + '.v21x'))
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(blob)
    if destination.stat().st_size != len(blob):
        raise RuntimeError('the archive was not written completely: %s' % destination)
    return destination, stats


if __name__ == "__main__":
    source = input("Enter input file path: ").strip().strip('"')
    destination = input("Enter output TXT path: ").strip().strip('"')
    try:
        encode_file(source, destination)
    except Exception as error:
        print(f"Encoding failed: {error}")
