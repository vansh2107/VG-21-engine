"""VG-21 encoder: VG-21C compression followed by printable Base95 encoding."""
from __future__ import annotations

from vg21c_codec import compress as vg21c_compress

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


def encode_bytes(data: bytes) -> str:
    """Use VG-21C when it reduces the payload; otherwise preserve raw bytes."""
    compressed = vg21c_compress(data)
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


def encode_text(text: str) -> str:
    return encode_bytes(text.encode("utf-8"))


def encode_file(input_path: str, output_path: str) -> None:
    with open(input_path, "rb") as file:
        original = file.read()
    encoded = encode_bytes(original)
    with open(output_path, "w", encoding="ascii", newline="") as file:
        file.write(encoded)
    print("\nEncoding completed successfully.")
    print(f"Original size: {len(original):,} bytes")
    print(f"Encoded size:  {len(encoded):,} characters")
    print(f"Output saved:  {output_path}")


if __name__ == "__main__":
    source = input("Enter input file path: ").strip().strip('"')
    destination = input("Enter output TXT path: ").strip().strip('"')
    try:
        encode_file(source, destination)
    except Exception as error:
        print(f"Encoding failed: {error}")
