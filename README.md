# VG-21 & VG-21C — Experimental Compression and Encoding Toolkit

> **Status: Experimental / research project.** VG-21C is a work in progress. Results are workload-dependent and do not establish that it universally outperforms Brotli or other established compressors.

VG-21 is a personal project exploring lossless data compression, printable text encoding, reversible data formats, and benchmark-driven iteration. It grew from experiments with compact encodings and a Brotli-based baseline into VG-21C, an evolving compression engine that tests multiple candidate representations and selects a result according to its implementation's size criteria.

Everything you need is in one file:

- **`vg21c_codec.py`** — the compressor and the archive decoder, with an interactive prompt. `python vg21c_codec.py` asks whether you want to encode or decode, then does it.
- **`encoder.py`, `decoder.py`, `main.py`** — the older menu and the printable-Base95 wrapper around it, kept for the text-encoding experiment.

This README documents the project's journey, current design, benchmark evidence, limitations, and ways to reproduce basic tests.

---

## Contents

- [Project goals](#project-goals)
- [The journey so far](#the-journey-so-far)
- [How the current pipeline works](#how-the-current-pipeline-works)
- [Speed profiles](#speed-profiles)
- [Never larger than Brotli q11](#never-larger-than-brotli-q11)
- [Repository files](#repository-files)
- [Requirements and setup](#requirements-and-setup)
- [Run it](#run-it)
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

### 5. Making the default fast

The portfolio was correct but slow, so `compress()` gained explicit profiles.
Profiling showed the pure-Python stages dominating the runtime while a C codec
usually won, that Brotli quality 11 was being re-run with up to eight parameter
sets per file, and that incompressible data paid for the whole search before
being stored raw. The fix is a cost-model scheduler: classify the input, prove
compressibility, then walk codec families from cheapest to most expensive,
choosing the strongest variant each one can still afford. The exhaustive path is
retained as the `max` profile, so no candidate was removed.

### 6. Moving toward reproducible evaluation

The project has included round-trip checks and a small benchmark corpus. The next important step is to make all benchmark inputs, commands, versions, settings, and output measurements easy for another person to reproduce. The current results should be treated as preliminary evidence, not a standardized benchmark suite.

## How the current pipeline works

### Encoding a file or folder

`python vg21c_codec.py` writes an archive rather than text: the input goes through
the portfolio below with Brotli q11 as one of its candidates, folders are stored
as a deduplicated tar or as one stream per file (whichever comes out smaller),
and the result is framed with a CRC32 of the original bytes. Details are in
[Never larger than Brotli q11](#never-larger-than-brotli-q11).

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

## Speed profiles

Evaluating every candidate on every file made ordinary inputs slow: a 16 KiB
text file took about 5 seconds, and 64 KiB of random data took about 10
seconds — almost all of it inside the pure-Python token and BWT stages, which
did not produce the winning stream on any sampled input anyway. `compress()` now
*schedules* candidates instead of always running them.

| Profile | Behaviour |
|---|---|
| `instant` (default) | Classifies the input, uses a cheap DEFLATE probe to prove whether it compresses at all, then runs the strongest codec each family can still afford inside a short budget. Already-compressed containers (JPEG, PNG, HEIC/MP4, GIF, WEBP, GZIP, BZIP2, XZ, 7Z, RAR, ZSTD, LZ4, FLAC, OGG) and high-entropy data are returned unchanged immediately. |
| `balanced` | Same scheduler with a much larger budget; adds the lexical-dictionary stage, and the native engine for small inputs. |
| `max` | The complete historical portfolio, unchanged. Slowest, best ratio. |

All three profiles are lossless and emit ordinary VG-21C streams with the same
framing and CRC32, so any decoder reads any of them. A profile decides only
*which* candidate is produced, never how a stream is read — streams written by
earlier versions still decode.

Measured on this repository's own files (CPython 3.12, Windows, one core):

| Input | `instant` | `max` | Speed-up | Size difference |
|---|---:|---:|---:|---:|
| README.md, 16 KiB | 0.21 s | 15.7 s | 76x | 0% |
| README x12, 196 KiB | 0.38 s | 1.56 s | 4x | 0% |
| Python source, 200 KiB | 0.78 s | 7.12 s | 9x | +5.4% |
| Highly repetitive, 220 KiB | 0.09 s | 0.49 s | 5x | 0% |
| Random data, 64 KiB | 0.004 s | 22.4 s | 5400x | 0% |

At gigabyte scale the same scheduler still finishes in seconds, because the
decision is made from nine spread-out 64 KiB samples rather than from the whole
input:

| Input | `instant`, end to end | Result |
|---|---:|---|
| 877 MB photo folder (1,683 JPEG/HEIC files) | 3.8 s | stored as-is (+21 bytes of container header); decode 2.9 s, all 1,683 files byte-identical |
| 1 GiB of source-like text | 25.0 s | 323 MB, 30.1% of the original |

A folder archive reaches the codec as one tar blob, so its first and last bytes
are structural: a tar header in front, end-of-archive padding behind. Both
compress about tenfold while every photo block between them is incompressible,
so the probe reduces its samples with a **median**. A `min` let the padding
decide, and a mean over four windows let two such outliers outvote 880 MB of
JPEG; either mistake bought a full DEFLATE pass for a 1.6% gain on a folder that
cannot really be compressed.

Two other large-input costs are gone:

- above 64 MiB the container is verified from the bytes already in memory
  instead of being read back from disk — a second 1 GB read proves the same
  round trip;
- the ZIP member optimizer is skipped above 256 MiB, because it decodes and
  re-encodes every member and would otherwise spend minutes inside one archive.

The trade is explicit: gigabyte-scale media is stored unchanged even where a
slow pass would shave 1-2%. The `balanced` and `max` API profiles still do that
work.

Profiles are an API-level choice for the historical VG-21C engine:

```python
from vg21c_codec import compress, decompress, PROFILE_BALANCED

packed = compress(data, profile=PROFILE_BALANCED)
assert decompress(packed) == data
```

The command-line tool does not take `-p`. It encodes with the portfolio described
below and accepts `-e best` (default) or `-e fast`.

Two honest caveats. The budget is a target for *choosing* work, not an
interrupt: a single candidate that turns out slower than predicted can overshoot
it, which is why `balanced` and `max` exist. And where `instant` declines
marginal work it can return a slightly larger stream — the largest gap observed
here was 5.4% on Python source, because the winning stream there came from the
lexical-dictionary stage that only `balanced` and `max` run.

## Never larger than Brotli q11

The encoder is built on a guarantee that is actually achievable: **the best
Brotli q11 stream is one of its own candidates**, so an archive can never be
larger than q11's output for the same bytes. On top of that floor it runs the
recipes where q11 is measurably not the best, and keeps whichever stream is
smallest.

| Recipe | What it exploits |
|---|---|
| Brotli q11, every mode and window | the floor: plain text and source code, where q11 is already optimal |
| Column split + LZMA2 / Brotli | CSV, logs, tables: one stream per field turns a record layout into nearly sorted columns |
| LZMA2 (9e) | structured JSON, where q11 consistently trails |
| Zstandard 22, long-distance matching, 128 MiB window | repeats further apart than Brotli's 16 MiB window |
| bzip2 (BWT) | integer series, where the Burrows-Wheeler sort beats both |
| byte-plane transpose (16/32-bit) | interleaved binary such as PCM audio |
| duplicate elimination | folders: identical files stored once |

Measured against the strongest q11 stream available (every mode and window
tried, smallest kept; for folders, the better of "q11 of the tar" and "sum of
per-file q11"):

| Case | Brotli q11 | Archive | Result |
|---|---:|---:|---|
| text, 21 KiB | 6,762 | 6,779 | tie |
| Python source, 212 KiB | 43,504 | 43,521 | tie |
| JSON records, 1.0 MB | 54,693 | 49,020 | **10.4% smaller** |
| CSV table, 812 KiB | 57,421 | 12,085 | **79.0% smaller** |
| access log, 1.5 MB | 87,086 | 47,645 | **45.3% smaller** |
| 16-bit PCM audio, 400 KiB | 207,211 | 152,608 | **26.4% smaller** |
| 32-bit integer series, 280 KiB | 75,464 | 51,246 | **32.1% smaller** |
| JPEG photo, 779 KiB | 779,009 | 779,024 | tie |
| folder, 120 files with duplicates | 63,349 | 62,416 | **1.5% smaller** |
| nested backup folder | 1,877 | 1,448 | **22.9% smaller** |
| **total** | 1,376,376 | 1,205,792 | **12.4% smaller** |

Seven of the ten cases are strictly smaller. The other three are ties, not
losses: two are plain text and source code, where every alternative tested lost
(LZMA2 with tuned context parameters was 3-17% worse), and one is a JPEG, which
is already entropy coded, so no lossless method can beat q11 there - q11 cannot
shrink it either. That is the ceiling rather than a gap: because q11 is one of
the candidates, "never larger" holds on any input, while "strictly smaller"
depends on the data containing structure q11 misses.

Your own photo folder, where q11 gains nothing at all, comes out 15.8% smaller
(876.6 MB -> 738.0 MB) in 4 seconds, because 440 of its 1,683 files are
byte-identical copies.

```bash
python vg21c_codec.py                      # prompts: encode or decode
python vg21c_codec.py "New folder"         # -> New folder.vg21c
python vg21c_codec.py some_file.bin -o out.vg21c
python vg21c_codec.py -d out.vg21c -o restored
python vg21c_codec.py folder -e fast       # skip the transforms, keep the q11 floor
```

Every archive is self-describing (`VG21X01` for a file, `VG21F01` for a folder)
with a CRC32 over the original data, so decoding needs no flags. `-e best` is
slow on purpose: it runs the whole candidate list, which includes six q11 passes
on some inputs. `-e fast` keeps the q11 floor and drops the transforms.

## Repository files

| File | Purpose |
|---|---|
| `vg21c_codec.py` | Everything: the encode/decode prompt, the portfolio (Brotli q11 floor, column split, byte transposes, Zstandard, bzip2, duplicate elimination), folder archives, and the historical VG-21C engine. |
| `encoder.py` | Older wrapper: VG-21C + Base95 printable text, plus archive helpers. |
| `decoder.py` | Older wrapper: Base95 decoder, plus archive helpers. |
| `main.py` | Menu for the older wrapper. |
| `README.md` | Project overview, history, setup, evidence, and limitations. |

Keep the Python files together in the same directory unless you deliberately update the import paths.

## Requirements and setup

- Python 3.10 or newer is recommended.
- The encoder uses Python's standard library, Brotli when installed, and Zstandard when installed. A missing package only removes candidates.
- Brotli is the baseline every archive is measured against; without it the portfolio falls back to LZMA2, bzip2 and zlib.

Clone or download the repository, then open a terminal in the project directory.

```bash
python --version
```

Optional Brotli installation:

```bash
python -m pip install brotli zstandard
```

If Brotli is not installed, the engine may skip candidates that require it. Exact results can therefore differ depending on the environment and installed dependencies.

## Run it

```bash
python vg21c_codec.py
```

```text
1. Encode  (compress a file or folder)
2. Decode  (restore a .vg21c archive)

Encode or decode? [1/2]:
```

It then asks for the path and an optional output path (press Enter to accept the
default). Encoding a folder keeps its structure and stores byte-identical files
once. Decoding never merges into an existing folder or overwrites a file: it
picks `name (2)` instead.

The same without prompts:

```bash
python vg21c_codec.py "New folder" -o photos.vg21c
python vg21c_codec.py -d photos.vg21c -o restored
```

The functions are importable too:

```python
from vg21c_codec import encode_path, decode_path

archive = encode_path('New folder')     # -> New folder.vg21c
restored = decode_path(archive)         # -> New folder (2)
```

`main.py` remains as the older menu built on `encoder.py`/`decoder.py`, and the
printable-Base95 pipeline is still available as `encoder.encode_text`,
`encoder.encode_file`, `decoder.decode_text` and `decoder.decode_file`.
Always verify important files after decoding, for example by comparing hashes.

## Run VG-21C on its own

The archive decoder also reads streams written by the historical VG-21C engine,
so `.vg21c` files produced by earlier versions still restore with
`python vg21c_codec.py -d file.vg21c`.

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
8. **Archive markers:** current archives use the markers `VG21X01` and `VG21F01`. The short-lived separate `vg21x.py` build used different ones, so those archives must be recreated; the files they came from are untouched.

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
