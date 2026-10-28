"""VG-21 decoder matching encoder.py's VG-21C + Base95 pipeline."""
from __future__ import annotations

from vg21c_codec import decompress as vg21c_decompress

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


if __name__ == "__main__":
    source = input("Enter encoded TXT path: ").strip().strip('"')
    destination = input("Enter decoded output file path: ").strip().strip('"')
    try:
        decode_file(source, destination)
    except Exception as error:
        print(f"Decoding failed: {error}")
