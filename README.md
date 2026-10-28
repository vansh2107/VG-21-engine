# VG-21 & VG-21C — Experimental Compression and Encoding Toolkit

> **Status: Experimental / research project.** VG-21C is a work in progress. Results are workload-dependent and do not establish that it universally outperforms Brotli or other established compressors.

VG-21 is a personal project exploring lossless data compression, printable text encoding, reversible data formats, and benchmark-driven iteration. It grew from experiments with compact encodings and a Brotli-based baseline into VG-21C, an evolving compression engine that tests multiple candidate representations and selects a result according to its implementation's size criteria.

The repository currently brings together two related components:

- **VG-21C** — the compression/decompression engine (`vg21c_codec.py`).
- **VG-21 Codec** — a wrapper that applies VG-21C, adds a mode marker, and encodes the resulting bytes as printable Base95 text (`encoder.py`, `decoder.py`, and `main.py`).

This README documents the project's journey, current design, benchmark evidence, limitations, and ways to reproduce basic tests.

---

## Contents

- [Project goals](#project-goals)
- [The journey so far](#the-journey-so-far)
- [How the current pipeline works](#how-the-current-pipeline-works)
- [Repository files](#repository-files)
- [Requirements and setup](#requirements-and-setup)
- [Run the VG-21 Codec wrapper](#run-the-vg-21-codec-wrapper)
- [Run VG-21C on its own](#run-vg-21c-on-its-own)
- [Use the Python API](#use-the-python-api)
- [Benchmark snapshot](#benchmark-snapshot)
- [Testing and reproducibility](#testing-and-reproducibility)
- [Known limitations](#known-limitations)
- [Roadmap](#roadmap)
- [Contributing and feedback](#contributing-and-feedback)
- [License and third-party components](#license-and-third-party-components)

## Project goals

The project explores several questions:

1. Can a portfolio of reversible transforms and compression candidates improve results on particular kinds of files?
2. Can a codec safely choose between a compressed payload and the original bytes when compression does not help?
3. What are the costs of converting binary output into printable text?
4. Can compression experiments be evaluated with repeatable tests rather than isolated best-case examples?
5. How should a custom format handle framing, integrity checks, invalid data, and compatibility between versions?

The goal is to learn, measure, and improve—not to claim universal superiority without evidence.

## The journey so far

### 1. Exploring compact encodings

The early experiments investigated ways to represent data using printable characters and compared different encodings and block sizes. The project adopted the name **VG-21**, later using **VG-21C** for its compression-engine work.

A key lesson from this phase was that encoding and compression are different operations. A text-safe representation can be useful for transport or storage, but it normally adds overhead compared with the underlying binary payload.

### 2. Establishing a baseline

Brotli quality 11 was used as an important comparison point and as part of an early compression pipeline. The initial approach was intentionally practical: compress when the result is smaller, otherwise keep the original bytes.

That baseline provided a reference against which later ideas could be tested. It also made one principle clear: an algorithm should not be credited with a compression win merely because it successfully round-trips data.

### 3. Building VG-21C through iterations

VG-21C evolved through multiple experimental versions. Version **v0.10** was retained as an earlier best-known reference point during development. Subsequent iterations explored additional reversible representations and candidate-selection strategies, with the goal of avoiding regressions while improving performance on a frozen set of test inputs.

**v0.24 — “Endgame”** is the current experimental engine bundled with this wrapper. It includes native VG-21C representations and optional candidates based on standard-library compressors and Brotli-assisted approaches. Candidate selection and the framing/integrity logic are implemented in the bundled engine. This is a description of the current experimental implementation, not a claim that every candidate wins on every input.

### 4. Connecting the engine to the VG-21 Codec

The current wrapper uses this pipeline:

```text
Original bytes
    ↓
VG-21C v0.24 compression attempt
    ↓
Choose VG-21C payload if it is smaller; otherwise keep raw bytes
    ↓
Add a mode byte
    ↓
Base95 encoding (78 bytes → 95 printable characters per block)
    ↓
Printable text output
```

Decoding reverses these steps. The mode marker tells the decoder whether the payload contains raw bytes or a VG-21C-compressed stream.

### 5. Moving toward reproducible evaluation

The project has included round-trip checks and a small benchmark corpus. The next important step is to make all benchmark inputs, commands, versions, settings, and output measurements easy for another person to reproduce. The current results should be treated as preliminary evidence, not a standardized benchmark suite.

## How the current pipeline works

### VG-21C compression engine

The bundled engine exposes `compress(data: bytes) -> bytes` and `decompress(blob: bytes) -> bytes`. It evaluates multiple representations and compression candidates, and uses its own framing and validation mechanisms. Some candidates rely on standard-library compressors; Brotli may also be used internally when the optional `brotli` package is available.

### Raw fallback

At the wrapper level, `encoder.py` compares the VG-21C output size with the original input size. If the VG-21C result is not smaller, it stores the original bytes instead. This avoids forcing an expansion from the outer compression choice, but the subsequent Base95 layer can still make the final text much larger than the original binary input.

### Base95 text encoding

The wrapper maps binary blocks to printable ASCII characters. The current implementation uses **78 input bytes per block and 95 output characters per block**, followed by a final-block length marker. This is the mapping inherited from the supplied implementation; it is not a claim that the overall encoded output is smaller than binary data.

For this reason, benchmark at least these three sizes separately:

1. Original input bytes.
2. VG-21C binary output bytes (or raw fallback payload).
3. Final Base95 text character count.

Do not compare a binary compressor's output size with a text-encoded result without clearly stating which layer is being measured.

## Repository files

| File | Purpose |
|---|---|
| `vg21c_codec.py` | Bundled VG-21C v0.24 engine; provides compression and decompression functions and a standalone interactive mode. |
| `encoder.py` | Compresses with VG-21C when smaller, adds a mode marker, and applies Base95 encoding. |
| `decoder.py` | Decodes Base95 and dispatches to raw-byte handling or VG-21C decompression. |
| `main.py` | Interactive menu for text and file encoding/decoding. |
| `README.md` | Project overview, history, setup, evidence, and limitations. |

Keep the Python files together in the same directory unless you deliberately update the import paths.

## Requirements and setup

- Python 3.10 or newer is recommended.
- The bundled engine uses Python's standard library and can optionally use Brotli if the package is installed.
- Brotli is an optional internal candidate dependency; the outer wrapper no longer directly calls `brotli.compress(..., quality=11)`.

Clone or download the repository, then open a terminal in the project directory.

```bash
python --version
```

Optional Brotli installation:

```bash
python -m pip install brotli
```

If Brotli is not installed, the engine may skip candidates that require it. Exact results can therefore differ depending on the environment and installed dependencies.

## Run the VG-21 Codec wrapper

Start the interactive menu:

```bash
python main.py
```

The menu supports:

1. Encode text.
2. Decode text.
3. Encode a file into a printable text file.
4. Decode a previously encoded text file back to bytes.
0. Exit.

When encoding a file, keep the encoded output as text and use the decoder to reconstruct the original file. Always verify important files after decoding, for example by comparing hashes.

## Run VG-21C on its own

VG-21C can be used without the Base95 wrapper. To start its built-in interactive interface:

```bash
python vg21c_codec.py
```

The bundled engine's standalone interface prompts for compression or decompression and a file or folder path. This mode uses VG-21C's own file format; it is separate from the outer VG-21 Base95 text format.

You can also call the engine functions directly from another Python script:

```python
from pathlib import Path
from vg21c_codec import compress, decompress

source = Path("example.bin").read_bytes()
packed = compress(source)
restored = decompress(packed)

assert restored == source
print(f"Input:      {len(source):,} bytes")
print(f"VG-21C:     {len(packed):,} bytes")
print(f"Round trip: {restored == source}")
```

The direct API's output is a binary VG-21C stream. Do not pass it to the Base95 decoder unless it has first been wrapped using the matching VG-21 encoder.

## Use the Python API

The outer wrapper exposes functions that can be imported into another Python script:

```python
from encoder import encode_text, encode_bytes
from decoder import decode_text, decode_bytes

message = "VG-21 experimental codec"
encoded = encode_text(message)
restored = decode_text(encoded)
assert restored == message

original = b"binary payload\x00\x01"
encoded_text = encode_bytes(original)
restored_bytes = decode_bytes(encoded_text)
assert restored_bytes == original
```

`encode_bytes` returns a Python string containing printable Base95 text. `decode_bytes` returns the reconstructed bytes. `encode_text` and `decode_text` use UTF-8 for text conversion.

## Benchmark snapshot

The v0.24 development report recorded the following size differences against its listed Brotli reference outputs on a small, frozen corpus. **Positive values mean the VG-21C output was larger; negative values mean it was smaller.** These are historical development measurements and have not been independently reproduced by every user or environment.

| Input | Recorded size difference | Interpretation |
|---|---:|---|
| PDF | +8 bytes | Slightly larger |
| TAR | +8 bytes | Slightly larger |
| Random data | −4 bytes | Raw fallback; not evidence of a genuine compression advantage |
| Repetitive text | +8 bytes | Slightly larger |
| Python source | −599 bytes | Smaller on this sample |
| English text | +1 byte | Slightly larger |
| JSON | −192 bytes | Smaller on this sample |
| ZIP archive | −1,221 bytes | Smaller on this sample; archive-specific result |

The reported net difference across these eight cases was **1,991 bytes smaller** for the tested VG-21C outputs in that particular corpus. This aggregate is not a universal performance claim, and the random-data result should not be interpreted as a real compression win because raw fallback was involved.

### How to interpret these results

- The corpus is small and cannot represent every file type or dataset.
- A difference of a few bytes may be sensitive to framing, headers, settings, or version differences.
- Already-compressed formats such as ZIP are not representative of general-purpose compressibility.
- The engine may use Brotli internally, so these results do not establish Brotli independence.
- The outer Base95 wrapper adds overhead and should be measured separately from the engine.
- Fair comparisons require the same input bytes, well-documented settings, exact output-size definitions, and verified decompression.

**Current conclusion:** the experiments show workload-dependent results and provide leads for further investigation. They do not prove that VG-21C consistently beats Brotli Q11 or any other compressor across general workloads.

## Testing and reproducibility

At the time this wrapper was assembled, the following checks were recorded as passing:

- Python compilation of the engine and wrapper files.
- Base95 raw round trips at boundary lengths including 0, 1, 77, 78, 79, and 256 bytes, plus repetitive and random samples.
- Full wrapper round trips for empty data, short text, repetitive content, and random bytes.
- A sample repetitive input compressed by VG-21C before Base95 encoding.

These are development checks, not a substitute for a comprehensive automated test suite. Before relying on this format for important data, add and run tests for large inputs, malformed and truncated streams, corrupted blocks, Unicode edge cases, and cross-version compatibility.

For a benchmark report suitable for independent review, record:

- Input file names, byte sizes, and SHA-256 hashes.
- Exact versions and settings of VG-21C, Python, Brotli, and all other compressors.
- Whether output size includes headers, checksums, framing, or text encoding.
- Compression and decompression times, peak memory if possible, and whether the output round-trips exactly.
- Multiple representative samples per category, not just one hand-picked file.

## Known limitations

1. **Experimental format:** the binary and text formats may change between versions. Do not assume long-term compatibility without versioned format specifications and fixtures.
2. **Legacy compatibility:** the wrapper uses mode value `2` for VG-21C. Older wrapper files that used mode `2` for Brotli are not compatible with this decoder without a migration or version-aware decoder.
3. **Base95 overhead:** printable text output can be much larger than the source binary, especially for small files. The Base95 layer is an encoding, not a compression stage.
4. **Optional dependency:** installing Brotli can change which internal candidates are available and can change results.
5. **No universal superiority claim:** performance depends on file type, content, implementation, and settings.
6. **Security and robustness:** this is not yet presented as a hardened format for untrusted input. Treat unknown encoded files cautiously and test error handling before production use.
7. **No production guarantee:** do not use it as the sole storage or backup mechanism for irreplaceable data without independent backups and extensive validation.

## Roadmap

- [ ] Turn round-trip and malformed-input checks into an automated test suite.
- [ ] Add a reproducible benchmark runner and machine-readable results.
- [ ] Report compression ratio, final encoded size, speed, and memory separately.
- [ ] Expand the corpus with diverse text, source code, JSON, CSV, logs, documents, archives, images, and high-entropy data.
- [ ] Add format/version documentation and test fixtures for compatibility.
- [ ] Improve validation and error handling for corrupted or truncated inputs.
- [ ] Compare results against established compressors under matched conditions.
- [ ] Investigate whether any performance gains remain when internal Brotli-assisted candidates are disabled.
- [ ] Publish tagged releases only after tests and benchmark artifacts are reproducible.

## Contributing and feedback

Issues, reproducible bug reports, benchmark suggestions, and careful technical reviews are welcome. When reporting a result, include the input category, file size, environment, commands, relevant dependency versions, and whether decompression reproduced the original bytes exactly. Avoid uploading private or copyrighted test files; small synthetic or freely redistributable samples are preferable.

## License and third-party components

No license is asserted by this README. Before making the repository public, choose and add an appropriate license for the code you own, and review the terms and notices for any third-party code or components included in the repository. The optional Brotli package and Python's standard-library modules are separate dependencies with their own licensing terms.

---

**VG-21 / VG-21C is an ongoing experiment in compression, encoding, and measurement.** The project's next milestone is not simply another version number; it is a cleaner, independently reproducible evaluation that shows where the approach works, where it does not, and why.
