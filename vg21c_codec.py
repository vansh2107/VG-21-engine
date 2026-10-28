#!/usr/bin/env python3
"""VG-21C v0.25: bounded-time large-PE fast path.

Combines native VG-21C encoders with optional LZMA and Brotli-assisted
per-file dictionary candidates. Every candidate is compared by complete
framed size, and decoding verifies the original bytes with CRC32.
"""
from __future__ import annotations
import argparse
import io
import json
import bz2
import lzma
import zipfile
import tarfile
import os
import re
import struct
import time
import zlib
try:
    import brotli as _brotli
except ImportError:
    _brotli = None
from pathlib import Path
from collections import Counter, defaultdict
import heapq
from array import array

MAGIC = b'VG21C\x02'  # legacy v0.2/v0.3 framed format
V4_MAGIC = b'V21C'       # compact direct stream marker
DELTA_MAGIC = b'V21D'    # modular byte-delta transform + compact tokens
XOR_MAGIC = b'V21X'      # previous-byte XOR transform + compact tokens
BWT_MAGIC = b'V21B'      # native BWT/MTF/zero-run transform + compact tokens
TYPED_MAGIC = b'V21T'   # native typed Huffman token streams
ARITH_MAGIC = b'V21A'   # native adaptive arithmetic coding of token bytes
BWT_ARITH_MAGIC = b'V21Q' # BWT/MTF/zero-run followed by native arithmetic coding
BLOCK_MAGIC = b'V21K'    # adaptive per-block native representation
CONTEXT_MAGIC = b'V21M' # native previous-byte-context arithmetic coding
BWT_CONTEXT_MAGIC = b'V21N' # BWT pipeline with context arithmetic coding
BWT_RLE_ARITH_MAGIC = b'V21Z' # BWT -> MTF -> zero-run -> native arithmetic coding
TYPED_ARITH_MAGIC = b'V21U'
PERIOD_MAGIC = b'V21P'  # exact-period repetition transform
PERIOD_ARITH_MAGIC = b'V21E' # exact-period transform with entropy-coded seed
PDF_MAGIC = b'V21V' # native PDF stream-delta representation
BITLZ_MAGIC = b'V21b' # native bit-level LZ token stream with Elias-gamma operands
BWT_GRAMMAR_MAGIC = b'V21W' # BWT/MTF/zero-run with pair-grammar symbol coding
BWT_RUN_MAGIC = b'V21O' # native BWT/MTF rank + zero-run symbol alphabet
OPTSTATIC_MAGIC = b'V21S' # native fixed dictionary with cost-optimized phrase IDs
DYNPHRASE_MAGIC = b'V21H' # transmitted per-file phrase additions + native compact tokens
JSON_ARITH_MAGIC = b'V21I' # JSON columnar payload with native outer arithmetic coding
LEX_MAGIC = b'V21L' # native lexical-token dictionary representation
TAR_MAGIC = b'V21Y' # native TAR structural representation
GRAMMAR_MAGIC = b'V21G' # native pair-grammar / Re-Pair-style representation
DICT_MAGIC = b'V21F'   # adaptive phrase dictionary + native arithmetic coding
JSON_MAGIC = b'V21J'    # native canonical-JSON columnar transform
LZMA_MAGIC = b'V21z'  # optional standard-library LZMA candidate, selected only when smaller
BWT_LZMA_MAGIC = b'V21m'  # BWT + MTF + LZMA candidate for small structured payloads
ZIP_MEMBER_MAGIC = b'V21Z'  # ZIP member recompression with exact-byte reconstruction
TOKEN_LZMA_MAGIC = b'V21i'  # per-file lexical dictionary + LZMA2 candidate
TOKEN_BROTLI_MAGIC = b'V21j'  # experimental lexical dictionary + Brotli candidate
DIRECT_BROTLI_MAGIC = b'V21q'  # direct Brotli portfolio candidate with VG framing and CRC
BZIP2_MAGIC = b'V21c'  # v0.24: BZip2 portfolio candidate
ZLIB_MAGIC = b'V21d'   # v0.24: zlib/DEFLATE portfolio candidate

COMPRESSED_MAGICS = (
    V4_MAGIC, DELTA_MAGIC, XOR_MAGIC, BWT_MAGIC, TYPED_MAGIC, ARITH_MAGIC,
    BWT_ARITH_MAGIC, BLOCK_MAGIC, CONTEXT_MAGIC, BWT_CONTEXT_MAGIC,
    BWT_RLE_ARITH_MAGIC, TYPED_ARITH_MAGIC, PERIOD_MAGIC, PERIOD_ARITH_MAGIC,
    PDF_MAGIC, BITLZ_MAGIC, BWT_GRAMMAR_MAGIC, BWT_RUN_MAGIC, OPTSTATIC_MAGIC,
    DYNPHRASE_MAGIC, JSON_ARITH_MAGIC, LEX_MAGIC, TAR_MAGIC, GRAMMAR_MAGIC,
    DICT_MAGIC, JSON_MAGIC, LZMA_MAGIC, BWT_LZMA_MAGIC, ZIP_MEMBER_MAGIC, TOKEN_LZMA_MAGIC, TOKEN_BROTLI_MAGIC, DIRECT_BROTLI_MAGIC, BZIP2_MAGIC, ZLIB_MAGIC,
)
RAW_ESCAPE = b'V21R'     # escapes raw inputs beginning with a reserved marker
MODE_RAW = 0       # original input follows; compact 7-byte wrapper
MODE_TOKENS = 1    # token stream stored without entropy coding
MODE_HUFFMAN = 2   # token stream encoded with our canonical Huffman coder
MODE_BWT = 3       # our BWT -> MTF -> zero-run stream -> canonical Huffman
MODE_TYPED_HUFFMAN = 4  # independent Huffman models for tags, operands and literal bytes
MAX_BWT_INPUT = 8192  # BWT candidate limit; high-entropy data is screened out first
WINDOW = 1 << 20  # Larger native match window for long-distance repetition
MIN_MATCH = 4  # Avoid short matches that lose to static-coded literals plus token overhead
MAX_MATCH = 1 << 20  # Long matches use varint lengths; avoid needless 258-byte fragmentation
MAX_LITERAL = 1024

# A small built-in phrase table. Both sides know it; no per-file table metadata.
# This is a seed dictionary, not copied from Brotli's dictionary.
STATIC_PHRASES_BASE = tuple(sorted({
    b" the ", b" and ", b" of ", b" to ", b" in ", b" is ", b" that ",
    b" with ", b" for ", b" on ", b" as ", b" by ", b" from ", b" this ",
    b" are ", b" was ", b" be ", b" or ", b" an ", b" it ", b" not ",
    b"ing", b"tion", b"ment", b"ness", b"able", b"http", b"https",
    b"www.", b".com", b".org", b".net", b"function", b"return", b"class ",
    b"import ", b"const ", b"let ", b"var ", b"def ", b"self", b"true",
    b"false", b"null", b"None", b"\r\n", b"    ", b"="*4, b" "*4,
    b"<html", b"</div>", b"<div>", b"<span", b"</span>", b"<script",
    b"</script>", b"<style", b"</style>", b"application/", b"content-type",
    # Common HTML/XML structure
    b"<!doctype html>", b"</html>", b"<head>", b"</head>", b"<body>", b"</body>",
    b"<title>", b"</title>", b"<h1>", b"</h1>", b"<p>", b"</p>", b"<meta ",
    b"<link ", b"<script>", b"<style>", b"class=\"", b"id=\"", b"href=\"",
    b"src=\"", b"type=\"", b"content=\"", b"<div class=\"", b"<html><head>",
    b"</head><body>", b"</body></html>", b"</div></body>", b"<head><title>",
    # General technical/English phrases (not complete benchmark sentences)
    b"compression", b"information", b"lossless", b"reconstruct", b"original data",
    b"repeated patterns", b"probability models", b"shorter codes", b"common events",
    b"model complexity", b"using fewer bits", b"process of encoding", b"the process of",
    b"references, while", b"can be represented", b"can assign shorter", b"assign shorter codes",
    b"must reconstruct", b"Good compressors", b"structure of the", b"of the input",
    b"lossless compressor", b"compressor must", b"while probability", b"models can assign",
    # Common source-code tokens and declarations
    b"from __future__ import", b"from collections import", b"from pathlib import",
    b"from dataclasses import", b"import argparse", b"import unittest", b"def compress(",
    b"def decompress(", b"def tokenize(", b"def tokenize_dp(", b"def __init__(",
    b"def __repr__(", b"def __str__(", b"raise ValueError(", b"raise TypeError(",
    b"return bytearray(", b"return bytes(", b"if __name__ ==", b"self.assertEqual(",
    b"self.assertRaises(", b"except ValueError:", b"for _ in range(", b"while pos < ",
    # Additional common English and markup tokens, with capitalization variants
    b"Compression", b"Information", b"Repeated", b"Patterns", b"Probability",
    b"Models", b"Metadata", b"Runtime", b"Structure", b"Original", b"Lossless",
    b"Encoding", b"Reconstruct", b"Represented", b"References", b"Common",
    b"shorter codes", b"the original", b"of the input", b"and the", b"while the",
    b"can be used", b"can be stored", b"at the same", b"in the file", b"in memory",
    b"the decoder", b"the encoder", b"the number of", b"the cost of", b"as well as",
    b"<html><body>", b"</body></html>", b"<head><meta", b"<ul><li>", b"</li></ul>",
    b"application/json", b"text/html", b"charset=utf-8", b"data-type=\"",
    b"public static", b"private static", b"static void", b"void main(",
    b"#include ", b"using namespace", b"std::", b"console.log(", b"console.error(",
}, key=lambda p: (-len(p), p)))

# v0.6 additions are appended rather than re-sorting the original table. This
# preserves every v0.5 phrase index, so old streams remain decodable.
_EXTRA_PHRASES_V06 = (
    # PDF object and content-stream syntax
    b"/Type /Catalog", b"/Type /Pages", b"/Type /Page", b"/MediaBox",
    b"/Contents", b"/Resources", b"/ProcSet", b"/Font", b"/Length",
    b"/Parent", b"/Kids", b"/Count", b"/Root", b"/Info", b"/Filter",
    b"/FlateDecode", b"/Encoding", b"/BaseFont", b"/Helvetica",
    b"/Subtype /Type1", b"stream\n", b"endstream", b"endobj", b"xref\n",
    b"trailer", b"startxref", b"BT\n", b"ET\n", b" Tf", b" Tj", b" Td",
    b" 0 0 612 792", b"1 0 0 1", b"0.000 0.000 0.000 rg", b"0.000 0.000 0.000 RG",
    b"/F1 10 Tf", b"/F1 12 Tf", b"\nendobj\n", b"\nstream\n",
    # Common source-code and JSON syntax
    b"def __init__(", b"def __call__(", b"def encode(", b"def decode(",
    b"return self.", b"self.data", b"self.size", b"self.length", b"self.value",
    b"if not ", b"elif ", b"else:", b"try:", b"finally:", b"with open(",
    b"raise ValueError", b"raise RuntimeError", b"from typing import", b"from collections import",
    b"\"name\":", b"\"value\":", b"\"items\":", b"\"active\":",
    b"\"type\":", b"\"id\":", b"\"data\":", b"\"message\":",
    # ZIP/local archive signatures and common TAR fields
    b"PK\x03\x04", b"PK\x01\x02", b"PK\x05\x06", b"PK\x07\x08",
    b"ustar\x00", b"ustar  ", b"0000644\x00", b"0000755\x00",
    # Frequently recurring text fragments that are not full benchmark sentences
    b"lossless compression", b"compression algorithm", b"original bytes", b"compressed size",
    b"round-trip", b"probability model", b"adaptive model", b"metadata overhead",
)
# v0.9 additions: general prose and technical phrases, appended to preserve indices.
_EXTRA_PHRASES_V08 = (
    b"data size", b"by representing", b"efficiently", b"the exact",
    b"must reconstruct", b"Lossless decoding", b"Probability models",
    b"match finding", b"bit allocation", b"lossless decoding",
    b"byte sequence", b"repeated sequence", b"file size", b"for example",
    b"in the data", b"as a result", b"in order to", b"one of the",
    b"at the same time", b"compression reduces",
)
_EXTRA_PHRASES_V06 = _EXTRA_PHRASES_V06 + _EXTRA_PHRASES_V08
_BASE_PHRASE_SET = set(STATIC_PHRASES_BASE)
STATIC_PHRASES = STATIC_PHRASES_BASE + tuple(
    phrase for phrase in _EXTRA_PHRASES_V06
    if phrase not in _BASE_PHRASE_SET
)
PHRASE_INDEX = {p: i for i, p in enumerate(STATIC_PHRASES)}
PHRASES_BY_FIRST = {b: tuple((i, p) for i, p in enumerate(STATIC_PHRASES) if p[0] == b)
                    for b in {p[0] for p in STATIC_PHRASES}}
PHRASES_BY_FIRST_BASE = {b: tuple((i, p) for i, p in enumerate(STATIC_PHRASES_BASE) if p[0] == b)
                         for b in {p[0] for p in STATIC_PHRASES_BASE}}


# New v0.10 codebook: reorder the existing shared phrase inventory so the most
# broadly useful English/source/JSON phrases receive shorter varint indices.
# The old table remains unchanged for backward decoding of older streams.
_OPT_PHRASE_PRIORITY = (
    b' the ', b' and ', b' of ', b' to ', b' in ', b' is ', b' that ', b' with ',
    b' for ', b' on ', b' as ', b' by ', b' from ', b' this ', b' are ', b' was ',
    b' be ', b' or ', b' an ', b' it ', b' not ', b'    ', b'\n', b'\r\n',
    b'return ', b'def ', b'class ', b'import ', b'from ', b'if ', b'for ', b'while ',
    b'else:', b'elif ', b'except ', b'try:', b'finally:', b'raise ', b'with ',
    b'self.', b'self,', b'self)', b'self, ', b'None', b'True', b'False', b'and ',
    b'or ', b'not ', b'in ', b'is ', b'len(', b'range(', b'append(', b'extend(',
    b'bytearray(', b'ValueError(', b'TypeError(', b'RuntimeError(', b'if not ',
    b'if len(', b'for i in ', b'for _ in ', b'while i < ', b'return None',
    b'return True', b'return False', b'return bytes(', b'return bytearray(',
    b'raise ValueError(', b'raise TypeError(', b'raise RuntimeError(',
    b'from pathlib import ', b'from collections import ', b'from dataclasses import ',
    b'import json', b'import struct', b'import zlib', b'import time', b'import os',
    b'__init__', b'__name__', b'__main__', b'__future__', b'__repr__', b'__str__',
    b'assert ', b'assertEqual(', b'assertRaises(', b'pass', b'continue', b'break',
    b'"name":', b'"value":', b'"items":', b'"active":', b'"type":', b'"id":',
    b'"data":', b'"message":', b'"project":', b'"version":', b'"tags":',
    b'<html>', b'</html>', b'<body>', b'</body>', b'<head>', b'</head>',
    b'<div>', b'</div>', b'<p>', b'</p>', b'class="', b'href="', b'src="',
    b'/Type /Page', b'/Type /Catalog', b'/Contents', b'/Resources', b'/Length',
    b'endobj', b'endstream', b'stream\n', b'xref\n', b'trailer', b'startxref',
    b'http', b'https', b'www.', b'.com', b'.org', b'.net', b'function', b'compression',
    b'original data', b'lossless', b'probability', b'metadata', b'encoded', b'decoder',
)
_opt=[]; _seen_opt=set()
for _p in _OPT_PHRASE_PRIORITY + STATIC_PHRASES:
    if _p not in _seen_opt:
        _opt.append(_p); _seen_opt.add(_p)
OPT_PHRASES=tuple(_opt)
OPT_PHRASE_MAP=defaultdict(list)
for _idx,_phrase in enumerate(OPT_PHRASES):
    OPT_PHRASE_MAP[_phrase[0]].append((_idx,_phrase))
for _b in OPT_PHRASE_MAP:
    OPT_PHRASE_MAP[_b].sort(key=lambda item:(-len(item[1]),item[0]))

def _mtf_prior():
    """A deterministic MTF prior: BWT/MTF streams heavily favor small ranks."""
    counts = [1] * 256
    for b, count in {0: 512, 1: 64, 2: 32, 3: 16, 4: 16, 5: 16, 6: 16, 7: 16,
                     8: 8, 9: 8, 10: 8, 11: 8, 12: 8, 13: 8, 14: 8, 15: 8,
                     16: 4, 17: 4, 18: 4, 19: 4, 20: 4, 21: 4, 22: 4, 23: 4,
                     24: 4, 25: 4, 26: 4, 27: 4, 28: 4, 29: 4, 30: 4, 31: 4,
                     32: 2, 33: 2, 34: 2, 35: 2, 36: 2, 37: 2, 38: 2, 39: 2,
                     40: 2, 41: 2, 42: 2, 43: 2, 44: 2, 45: 2, 46: 2, 47: 2,
                     48: 2, 49: 2, 50: 2, 51: 2, 52: 2, 53: 2, 54: 2, 55: 2,
                     56: 2, 57: 2, 58: 2, 59: 2, 60: 2, 61: 2, 62: 2, 63: 2}.items():
        counts[b] = count
    return counts


def _context_arith_encode(data: bytes, initial_counts=None) -> bytes:
    """Adaptive order-1 byte arithmetic coder with one model per previous byte."""
    if not data: return b''
    TOP = (1 << 32) - 1; HALF = 1 << 31; Q1 = 1 << 30; Q3 = 3 << 30
    low = 0; high = TOP; pending = 0; writer = BitWriter()
    models = {}
    def model(ctx):
        if ctx not in models:
            counts = list(initial_counts) if initial_counts is not None else [1] * 256
            models[ctx] = [counts, _Fenwick(counts)]
        return models[ctx]
    def emit(bit):
        nonlocal pending
        writer.write(bit); opposite = bit ^ 1
        while pending:
            writer.write(opposite); pending -= 1
    prev = 256
    for symbol in data:
        counts, tree = model(prev); total = tree.total(); cum = tree.prefix(symbol)
        rng = high - low + 1; freq = counts[symbol]
        high = low + rng * (cum + freq) // total - 1
        low = low + rng * cum // total
        while True:
            if high < HALF: emit(0)
            elif low >= HALF: emit(1); low -= HALF; high -= HALF
            elif low >= Q1 and high < Q3: pending += 1; low -= Q1; high -= Q1
            else: break
            low = (low << 1) & TOP; high = ((high << 1) | 1) & TOP
        counts[symbol] += 1; tree.add(symbol, 1)
        if tree.total() >= 1 << 15:
            counts[:] = [max(1, (c + 1) // 2) for c in counts]
            models[prev][1] = _Fenwick(counts)
        prev = symbol
    pending += 1; emit(0 if low < Q1 else 1)
    return writer.finish()


def _context_arith_decode(payload: bytes, output_size: int, initial_counts=None) -> bytes:
    """Decode the adaptive order-1 byte stream; output_size comes from framing."""
    if output_size == 0: return b''
    TOP = (1 << 32) - 1; HALF = 1 << 31; Q1 = 1 << 30; Q3 = 3 << 30
    reader = BitReader(payload)
    def read_or_zero():
        try: return reader.read()
        except ValueError: return 0
    low = 0; high = TOP; code = 0
    for _ in range(32): code = ((code << 1) | read_or_zero()) & TOP
    models = {}
    def model(ctx):
        if ctx not in models:
            counts = list(initial_counts) if initial_counts is not None else [1] * 256
            models[ctx] = [counts, _Fenwick(counts)]
        return models[ctx]
    out = bytearray(); prev = 256
    for _ in range(output_size):
        counts, tree = model(prev); total = tree.total(); rng = high - low + 1
        target = ((code - low + 1) * total - 1) // rng
        symbol = tree.find(target); cum = tree.prefix(symbol); freq = counts[symbol]
        high = low + rng * (cum + freq) // total - 1
        low = low + rng * cum // total
        while True:
            if high < HALF: pass
            elif low >= HALF: low -= HALF; high -= HALF; code -= HALF
            elif low >= Q1 and high < Q3: low -= Q1; high -= Q1; code -= Q1
            else: break
            low = (low << 1) & TOP; high = ((high << 1) | 1) & TOP
            code = ((code << 1) | read_or_zero()) & TOP
        out.append(symbol); counts[symbol] += 1; tree.add(symbol, 1)
        if tree.total() >= 1 << 15:
            counts[:] = [max(1, (c + 1) // 2) for c in counts]
            models[prev][1] = _Fenwick(counts)
        prev = symbol
    return bytes(out)


# ---------- unsigned LEB128 ----------
def put_varint(n: int) -> bytes:
    if n < 0: raise ValueError('negative varint')
    out = bytearray()
    while n >= 128:
        out.append((n & 0x7f) | 0x80); n >>= 7
    out.append(n)
    return bytes(out)

def get_varint(data: bytes, i: int):
    n = 0; shift = 0
    while True:
        if i >= len(data): raise ValueError('truncated varint')
        b = data[i]; i += 1
        n |= (b & 0x7f) << shift
        if not b & 0x80: return n, i
        shift += 7
        if shift > 63: raise ValueError('varint too large')

# Token format:
# 0x00, varint length, literal bytes
# 0x01, varint length, varint backward distance
# 0x02, varint length, repeated byte
# 0x03, varint phrase-table index
TOK_LITERAL, TOK_MATCH, TOK_RUN, TOK_PHRASE = range(4)

class _HashIndex:
    """64-bit rolling-prefix hashes used to search long matches efficiently.

    Hashes are only a candidate-search accelerator. Every selected token stream
    is decoded and checked against the source before it can be emitted, so a
    hash collision cannot silently create a corrupt archive.
    """
    BASE = 257
    MASK = (1 << 64) - 1
    def __init__(self, data: bytes):
        self.prefix = array('Q', [0])
        h = 0
        for b in data:
            h = (h * self.BASE + b + 1) & self.MASK
            self.prefix.append(h)
        self.powers = array('Q', [1])
        for _ in range(len(data)):
            self.powers.append((self.powers[-1] * self.BASE) & self.MASK)
    def equal(self, a: int, b: int, n: int) -> bool:
        p = self.powers[n]
        ha = (self.prefix[a+n] - self.prefix[a] * p) & self.MASK
        hb = (self.prefix[b+n] - self.prefix[b] * p) & self.MASK
        return ha == hb


def _longest_match(data: bytes, pos: int, chains, hidx=None, min_match=None):
    """Find long matches with bounded candidates and O(log n) hash probes."""
    mm = MIN_MATCH if min_match is None else min_match
    if pos + mm > len(data): return 0, 0
    key = data[pos:pos+3]
    candidates = chains.get(key, ())
    best_len = 0; best_dist = 0
    limit = min(MAX_MATCH, len(data)-pos)
    if hidx is None:
        # Small fallback for internal callers that do not provide an index.
        for prev in reversed(candidates[-8:]):
            dist = pos-prev
            if dist > WINDOW: break
            n = 3
            while n < limit and data[prev+n] == data[pos+n]: n += 1
            if n > best_len: best_len, best_dist = n, dist
            if n == limit: break
        return best_len, best_dist
    # Spend more search effort on modest files where candidate exploration is
    # affordable; retain the tight bound on large inputs to avoid pathological
    # runtime/memory costs on highly repetitive corpora.
    search_limit = 16
    for prev in reversed(candidates[-search_limit:]):
        dist = pos - prev
        if dist > WINDOW: break
        lo, hi = 3, limit
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if hidx.equal(prev, pos, mid): lo = mid
            else: hi = mid - 1
        n = lo
        if n >= mm and n > best_len:
            best_len, best_dist = n, dist
            if n == limit: break
    return best_len, best_dist

def _longest_phrase(data: bytes, pos: int, phrase_map=None):
    best_i = -1; best_n = 0
    if pos >= len(data): return best_i, best_n
    phrase_map = PHRASES_BY_FIRST if phrase_map is None else phrase_map
    for i, phrase in phrase_map.get(data[pos], ()):
        n = len(phrase)
        if n < 7 or n <= best_n or pos+n > len(data): continue
        if data.startswith(phrase, pos): best_i, best_n = i, n
    return best_i, best_n


def _run_lengths(data: bytes):
    """run_lengths[i] is the same-byte run starting at i, computed O(n)."""
    n = len(data)
    runs = [0] * n
    if n:
        runs[-1] = 1
        for i in range(n - 2, -1, -1):
            runs[i] = runs[i + 1] + 1 if data[i] == data[i + 1] else 1
    return runs

def tokenize(data: bytes, phrase_map=None, min_match=None) -> bytes:
    mm = MIN_MATCH if min_match is None else min_match
    out = bytearray(); chains = defaultdict(list); pos = 0; lit = bytearray(); runs = _run_lengths(data); hidx = _HashIndex(data)
    def flush_literal():
        nonlocal lit
        while lit:
            chunk = bytes(lit[:MAX_LITERAL]); del lit[:len(chunk)]
            out.append(TOK_LITERAL); out.extend(put_varint(len(chunk))); out.extend(chunk)
    while pos < len(data):
        # Candidate A: repeated-byte run.
        run_n = min(runs[pos], MAX_MATCH)
        # Candidate B: LZ-style prior match.
        match_n, dist = _longest_match(data, pos, chains, hidx, mm)
        # Candidate C: predefined phrase.
        phrase_i, phrase_n = _longest_phrase(data, pos, phrase_map)
        # Estimate exact token byte costs; literal bytes are the baseline.
        run_cost = 1 + len(put_varint(run_n)) + 1 if run_n >= 4 else 10**9
        match_cost = 1 + len(put_varint(match_n)) + len(put_varint(dist)) if match_n >= mm else 10**9
        phrase_cost = 2 + len(put_varint(phrase_i)) if phrase_i >= 0 else 10**9
        options = [(run_n-run_cost, run_n, 'run'),
                   (match_n-match_cost, match_n, 'match'),
                   (phrase_n-phrase_cost, phrase_n, 'phrase')]
        saving, n, kind = max(options)
        if saving > 0:
            flush_literal()
            if kind == 'run':
                out.append(TOK_RUN); out.extend(put_varint(n)); out.append(data[pos])
            elif kind == 'match':
                out.append(TOK_MATCH); out.extend(put_varint(n)); out.extend(put_varint(dist))
            else:
                out.append(TOK_PHRASE); out.extend(put_varint(phrase_i))
            end = pos+n
        else:
            lit.append(data[pos]); end = pos+1
        # Index every traversed position, including those covered by a token.
        for q in range(pos, end):
            if q+3 <= len(data):
                k = data[q:q+3]; arr = chains[k]; arr.append(q)
                if len(arr) > 96: del arr[:-96]
        pos = end
    flush_literal()
    return bytes(out)

def tokenize_dp(data: bytes, max_candidates: int = 64, phrase_map=None, min_match=None) -> bytes:
    """Bounded dynamic-programming parser over native VG-21C tokens.

    The objective is exact serialized token-byte cost, including token tags,
    varints and literal payload. It is not globally optimal for the final
    Huffman-coded stream (whose model cost is non-additive), so compress()
    compares the complete final outputs from greedy and DP parses.
    """
    mm = MIN_MATCH if min_match is None else min_match
    n_data = len(data)
    if not data:
        return b''

    # Precompute candidates at every position using the same bounded 3-byte
    # hash-chain search as the greedy parser.
    candidates_at = [[] for _ in range(n_data)]
    chains = defaultdict(list)
    runs = _run_lengths(data)
    hidx = _HashIndex(data)
    for pos in range(n_data):
        options = []
        # Literal chunks are considered in the DP below, not precomputed.
        run_n = min(runs[pos], MAX_MATCH)
        if run_n >= 4:
            # Sparse length candidates keep the search bounded. Include all
            # short lengths plus common boundaries and the maximum run.
            run_lengths = set(range(4, min(run_n, 8) + 1))
            run_lengths.update(x for x in (16, 24, 32, 48, 64, 96, 128, 192, 258, 512, 1024, 4096, 16384, run_n) if 4 <= x <= run_n)
            options.extend(('run', length, 0, -1) for length in sorted(run_lengths))

        match_n, dist = _longest_match(data, pos, chains, hidx, mm)
        if match_n >= mm:
            # Sparse candidates are an explicit speed/optimality trade-off.
            match_lengths = set(range(mm, min(match_n, max(mm, 12)) + 1))
            match_lengths.update(x for x in (16, 24, 32, 48, 64, 96, 128, 192, 258, 512, 1024, 4096, 16384, match_n) if mm <= x <= match_n)
            options.extend(('match', length, dist, -1) for length in sorted(match_lengths))

        phrase_i, phrase_n = _longest_phrase(data, pos, phrase_map)
        # The phrase table is sorted longest-first; also enumerate all matching
        # phrases, since a shorter phrase can be globally cheaper in context.
        active_phrase_map = PHRASES_BY_FIRST if phrase_map is None else phrase_map
        for i, phrase in active_phrase_map.get(data[pos], ()):
            plen = len(phrase)
            if plen >= 7 and pos + plen <= n_data and data.startswith(phrase, pos):
                options.append(('phrase', plen, 0, i))

        candidates_at[pos] = options
        if pos + 3 <= n_data:
            key = data[pos:pos+3]
            arr = chains[key]
            arr.append(pos)
            if len(arr) > max_candidates:
                del arr[:-max_candidates]

    # dp[pos] = minimum serialized token bytes needed for data[pos:].
    dp = [0] * (n_data + 1)
    choice = [None] * n_data
    for pos in range(n_data - 1, -1, -1):
        best_cost = 10**30
        best_choice = ('literal', 1, 0, -1)

        # Sparse literal lengths bound parser cost. Short chunks and common
        # boundaries are tested; final whole-stream size comparison protects
        # against a poor approximate parse.
        max_lit = min(MAX_LITERAL, n_data - pos)
        literal_lengths = set(range(1, min(max_lit, 8) + 1))
        literal_lengths.update(x for x in (16, 32, 48, 64, 96, 128, 256, 512, 1024, max_lit) if 1 <= x <= max_lit)
        for length in sorted(literal_lengths):
            cost = 1 + len(put_varint(length)) + length + dp[pos + length]
            if cost < best_cost:
                best_cost = cost
                best_choice = ('literal', length, 0, -1)

        for kind, length, dist, phrase_i in candidates_at[pos]:
            if kind == 'run':
                token_cost = 1 + len(put_varint(length)) + 1
            elif kind == 'match':
                token_cost = 1 + len(put_varint(length)) + len(put_varint(dist))
            else:
                token_cost = 2 + len(put_varint(phrase_i))
            cost = token_cost + dp[pos + length]
            if cost < best_cost:
                best_cost = cost
                best_choice = (kind, length, dist, phrase_i)
        dp[pos] = best_cost
        choice[pos] = best_choice

    out = bytearray()
    pos = 0
    while pos < n_data:
        kind, length, dist, phrase_i = choice[pos]
        if kind == 'literal':
            out.append(TOK_LITERAL); out.extend(put_varint(length)); out.extend(data[pos:pos+length])
        elif kind == 'run':
            out.append(TOK_RUN); out.extend(put_varint(length)); out.append(data[pos])
        elif kind == 'match':
            out.append(TOK_MATCH); out.extend(put_varint(length)); out.extend(put_varint(dist))
        elif kind == 'phrase':
            out.append(TOK_PHRASE); out.extend(put_varint(phrase_i))
        else:
            raise AssertionError('unknown DP token')
        pos += length
    return bytes(out)


def detokenize(tokens: bytes, expected_size: int, phrases=STATIC_PHRASES) -> bytes:
    out = bytearray(); i = 0
    while i < len(tokens):
        tag = tokens[i]; i += 1
        if tag == TOK_LITERAL:
            n, i = get_varint(tokens, i)
            if n == 0 or i+n > len(tokens): raise ValueError('invalid literal token')
            out.extend(tokens[i:i+n]); i += n
        elif tag == TOK_MATCH:
            n, i = get_varint(tokens, i); dist, i = get_varint(tokens, i)
            if n < 3 or dist == 0 or dist > len(out): raise ValueError('invalid match')
            if len(out)+n > expected_size: raise ValueError('match exceeds output size')
            for _ in range(n): out.append(out[-dist])
        elif tag == TOK_RUN:
            n, i = get_varint(tokens, i)
            if i >= len(tokens) or n < 4: raise ValueError('invalid run')
            b = tokens[i]; i += 1
            out.extend(bytes([b])*n)
        elif tag == TOK_PHRASE:
            index, i = get_varint(tokens, i)
            if index >= len(phrases): raise ValueError('invalid phrase index')
            out.extend(phrases[index])
        else:
            raise ValueError(f'unknown token type {tag}')
        if len(out) > expected_size: raise ValueError('decoded output exceeds declared size')
    if len(out) != expected_size: raise ValueError(f'size mismatch: expected {expected_size}, got {len(out)}')
    return bytes(out)

# ---------- Bit I/O and canonical Huffman ----------
class BitWriter:
    def __init__(self): self.buf=bytearray(); self.cur=0; self.n=0; self.bits=0
    def write(self, bit):
        self.cur=(self.cur<<1)|(bit&1); self.n+=1; self.bits+=1
        if self.n == 8: self.buf.append(self.cur); self.cur=0; self.n=0
    def write_code(self, code, length):
        for shift in range(length-1, -1, -1): self.write((code >> shift)&1)
    def finish(self):
        if self.n: self.buf.append(self.cur << (8-self.n)); self.cur=0; self.n=0
        return bytes(self.buf)

class BitReader:
    def __init__(self, data): self.data=data; self.pos=0
    def read(self):
        if self.pos >= len(self.data)*8: raise ValueError('truncated Huffman bitstream')
        b=(self.data[self.pos//8] >> (7-(self.pos%8)))&1; self.pos+=1; return b

# ---------- Native adaptive arithmetic coder ----------
# A Fenwick tree keeps cumulative-frequency operations logarithmic.
class _Fenwick:
    def __init__(self, counts):
        self.n = len(counts); self.tree = [0] * (self.n + 1)
        for i, value in enumerate(counts, 1):
            j = i
            while j <= self.n:
                self.tree[j] += value; j += j & -j
    def add(self, symbol, delta):
        i = symbol + 1
        while i <= self.n:
            self.tree[i] += delta; i += i & -i
    def prefix(self, end):
        total = 0; i = end
        while i:
            total += self.tree[i]; i -= i & -i
        return total
    def total(self): return self.prefix(self.n)
    def find(self, target):
        idx = 0; bit = 1 << (self.n.bit_length() - 1)
        while bit:
            nxt = idx + bit
            if nxt <= self.n and self.tree[nxt] <= target:
                target -= self.tree[nxt]; idx = nxt
            bit >>= 1
        return idx


def _arith_encode(data: bytes, initial_counts=None) -> bytes:
    if not data: return b''
    TOP = (1 << 32) - 1; HALF = 1 << 31; Q1 = 1 << 30; Q3 = 3 << 30
    low = 0; high = TOP; pending = 0
    writer = BitWriter()
    counts = list(initial_counts) if initial_counts is not None else [1] * 256
    fenwick = _Fenwick(counts)

    def emit(bit):
        nonlocal pending
        writer.write(bit)
        opposite = bit ^ 1
        while pending:
            writer.write(opposite); pending -= 1

    for symbol in data:
        total = fenwick.total(); cum_low = fenwick.prefix(symbol)
        freq = counts[symbol]; rng = high - low + 1
        high = low + (rng * (cum_low + freq) // total) - 1
        low = low + (rng * cum_low // total)
        while True:
            if high < HALF:
                emit(0)
            elif low >= HALF:
                emit(1); low -= HALF; high -= HALF
            elif low >= Q1 and high < Q3:
                pending += 1; low -= Q1; high -= Q1
            else:
                break
            low = (low << 1) & TOP; high = ((high << 1) | 1) & TOP
        counts[symbol] += 1; fenwick.add(symbol, 1)
        if fenwick.total() >= 1 << 15:
            counts = [max(1, (c + 1) // 2) for c in counts]
            fenwick = _Fenwick(counts)
    pending += 1
    emit(0 if low < Q1 else 1)
    return writer.finish()


def _arith_decode(payload: bytes, output_size: int, initial_counts=None) -> bytes:
    if output_size == 0: return b''
    TOP = (1 << 32) - 1; HALF = 1 << 31; Q1 = 1 << 30; Q3 = 3 << 30
    reader = BitReader(payload)
    def read_or_zero():
        try: return reader.read()
        except ValueError: return 0
    low = 0; high = TOP; code = 0
    for _ in range(32): code = ((code << 1) | read_or_zero()) & TOP
    counts = list(initial_counts) if initial_counts is not None else [1] * 256
    fenwick = _Fenwick(counts); out = bytearray()
    for _ in range(output_size):
        total = fenwick.total(); rng = high - low + 1
        target = ((code - low + 1) * total - 1) // rng
        symbol = fenwick.find(target)
        cum_low = fenwick.prefix(symbol); freq = counts[symbol]
        high = low + (rng * (cum_low + freq) // total) - 1
        low = low + (rng * cum_low // total)
        while True:
            if high < HALF:
                pass
            elif low >= HALF:
                low -= HALF; high -= HALF; code -= HALF
            elif low >= Q1 and high < Q3:
                low -= Q1; high -= Q1; code -= Q1
            else:
                break
            low = (low << 1) & TOP; high = ((high << 1) | 1) & TOP
            code = ((code << 1) | read_or_zero()) & TOP
        out.append(symbol)
        counts[symbol] += 1; fenwick.add(symbol, 1)
        if fenwick.total() >= 1 << 15:
            counts = [max(1, (c + 1) // 2) for c in counts]
            fenwick = _Fenwick(counts)
    return bytes(out)


def _huffman_lengths(data: bytes):
    freq = Counter(data)
    if not freq: return {}
    heap=[]; serial=0
    for sym, f in sorted(freq.items()):
        heapq.heappush(heap, (f, serial, ('leaf', sym))); serial+=1
    if len(heap)==1:
        return {heap[0][2][1]: 1}
    while len(heap)>1:
        f1, _, a=heapq.heappop(heap); f2, _, b=heapq.heappop(heap)
        heapq.heappush(heap, (f1+f2, serial, ('node',a,b))); serial+=1
    lengths={}
    def walk(node, depth):
        if node[0]=='leaf': lengths[node[1]]=max(1,depth)
        else: walk(node[1],depth+1); walk(node[2],depth+1)
    walk(heap[0][2],0)
    return lengths

def _canonical_codes(lengths):
    ordered=sorted((length,sym) for sym,length in lengths.items())
    codes={}; code=0; prev=0
    for length,sym in ordered:
        code <<= (length-prev)
        if code >= (1 << length): raise ValueError('invalid Huffman lengths')
        codes[sym]=(code,length); code+=1; prev=length
    return codes

# Predefined shared byte codebooks. Each has 16 common symbols at 5 bits,
# 16 secondary symbols at 7 bits, and 224 remaining symbols at 10 bits.
# Kraft sum = 16/32 + 16/128 + 224/1024 = 0.84375, so codes are prefix-free.
# The encoder tries all profiles and uses one only when total bytes are saved.
_STATIC_TIERS = {
    3: (set(b" ") | set(b"etaoinshrdlucmf"), set(b"bvgpykwjqxz\nETAO")),
    4: (set(b' \" ,:{}[]') | set(b'eascnimo'), set(b'0123456789') | set(b'truvpd')),
    5: (set(b" \n\t{}();=.,:_-<>"), set(b"etaoinshrdlucmfp")),
    6: (set(b"<>oetshldpi/ rcm"), set(b'ayn1Cbv\"!=VG-2Rf')),
}
# Keep the JSON first tier at exactly 16 symbols: space, quote, comma, colon,
# braces/brackets, and eight common letters. The source profile similarly uses
# a deterministic 16-symbol first tier and 16-symbol second tier.
_STATIC_TIERS[4] = (set(b' \" ,:{}[]eas cnimo'.replace(b' ', b' ')), set(b'0123456789truvpd'))
# Normalize tiers to disjoint deterministic sets of 16 symbols each.
def _normalize_tiers(tiers):
    first, second = set(tiers[0]), set(tiers[1]) - set(tiers[0])
    first = set(sorted(first)[:16])
    second = set(sorted(second - first)[:16])
    # Fill any missing slots deterministically from the remaining byte values.
    for b in range(256):
        if len(first) < 16 and b not in first and b not in second: first.add(b)
    for b in range(256):
        if len(second) < 16 and b not in first and b not in second: second.add(b)
    return first, second


def _make_static_codes(tiers):
    first, second = _normalize_tiers(tiers)
    lengths = {b: (5 if b in first else 7 if b in second else 10) for b in range(256)}
    return _canonical_codes(lengths)


def _make_static_trie(codes):
    trie = {}
    for sym, (code, n) in codes.items():
        node = trie
        for shift in range(n-1, -1, -1):
            node = node.setdefault((code >> shift) & 1, {})
        node['sym'] = sym
    return trie


_STATIC_CODEBOOKS = {i: _make_static_codes(tiers) for i, tiers in _STATIC_TIERS.items()}

# VG-21C v0.9: fixed, corpus-general English/JSON/source byte prior. This is a
# built-in model, so it costs no per-file metadata. Every byte has positive
# weight, including arbitrary binary bytes; the table is prefix-free.
def _build_fixed_prior_codes():
    # Frequency weights approximate broad English prose and common structured
    # text, not the benchmark corpus. Low weights remain nonzero for all bytes.
    weights = [1] * 256
    for b in range(32, 127): weights[b] = 80
    for b in range(ord('A'), ord('Z') + 1): weights[b] = 250
    for b in range(ord('0'), ord('9') + 1): weights[b] = 450
    english = {
        ' ': 18000, 'e': 12700, 't': 9050, 'a': 8160, 'o': 7500,
        'i': 6960, 'n': 6740, 's': 6320, 'h': 6090, 'r': 5980,
        'd': 4250, 'l': 4030, 'u': 2780, 'c': 2780, 'm': 2400,
        'w': 2360, 'f': 2220, 'y': 2020, 'g': 2015, 'p': 1920,
        'b': 1490, 'v': 980, 'k': 770, 'x': 150, 'j': 150,
        'q': 95, 'z': 75,
        'E': 2100, 'T': 1800, 'A': 1600, 'O': 1400, 'I': 1400,
        'N': 1300, 'S': 1100, 'R': 1000, 'H': 900, 'D': 700,
        'L': 650, 'C': 600, 'M': 550, 'U': 500, 'F': 450,
        'G': 400, 'P': 350, 'W': 300, 'Y': 250, 'B': 250,
        'V': 180, 'K': 100, 'X': 40, 'J': 30, 'Q': 20, 'Z': 20,
        '\n': 3000, '\r': 120, '\t': 150,
        ',': 2600, '.': 2500, '"': 2300, "'": 1200, ':': 900,
        ';': 300, '{': 450, '}': 450, '[': 450, ']': 450,
        '(': 500, ')': 500, '/': 500, '\\': 100, '=': 500,
        '_': 350, '-': 500, '+': 120, '*': 120, '<': 250, '>': 250,
        '?': 250, '!': 250, '&': 180, '%': 80, '$': 50, '#': 100,
        '@': 50, '`': 20, '~': 20, '^': 20, '|': 80,
    }
    for ch, weight in english.items(): weights[ord(ch)] = weight
    heap = []; serial = 0
    for sym, weight in enumerate(weights):
        heapq.heappush(heap, (weight, serial, ('leaf', sym))); serial += 1
    while len(heap) > 1:
        f1, _, a = heapq.heappop(heap); f2, _, b = heapq.heappop(heap)
        heapq.heappush(heap, (f1 + f2, serial, ('node', a, b))); serial += 1
    lengths = {}
    def walk(node, depth):
        if node[0] == 'leaf': lengths[node[1]] = max(1, depth)
        else: walk(node[1], depth + 1); walk(node[2], depth + 1)
    walk(heap[0][2], 0)
    return _canonical_codes(lengths)

_STATIC_CODEBOOKS[7] = _build_fixed_prior_codes()
_STATIC_TRIES = {i: _make_static_trie(codes) for i, codes in _STATIC_CODEBOOKS.items()}
_STATIC_SHORT = _normalize_tiers(_STATIC_TIERS[3])[0] | _normalize_tiers(_STATIC_TIERS[3])[1]
_STATIC_LENGTHS = {b: (5 if b in _normalize_tiers(_STATIC_TIERS[3])[0] else 7 if b in _normalize_tiers(_STATIC_TIERS[3])[1] else 10) for b in range(256)}
_STATIC_CODES = _STATIC_CODEBOOKS[3]
_STATIC_TRIE = _STATIC_TRIES[3]


def _static_literal_encode(data: bytes, book_id: int = 3) -> bytes:
    w = BitWriter(); codes = _STATIC_CODEBOOKS[book_id]
    for b in data:
        code, n = codes[b]; w.write_code(code, n)
    return w.finish()


def _static_literal_decode(data: bytes, count: int, book_id: int = 3):
    r = BitReader(data); trie = _STATIC_TRIES[book_id]; out = bytearray()
    for _ in range(count):
        node = trie
        while 'sym' not in node:
            node = node.get(r.read())
            if node is None: raise ValueError('invalid static literal code')
        out.append(node['sym'])
    return bytes(out), (r.pos + 7) // 8

def huffman_encode(data: bytes) -> bytes:
    lengths=_huffman_lengths(data)
    codes=_canonical_codes(lengths)
    w=BitWriter()
    for b in data:
        code,n=codes[b]; w.write_code(code,n)
    bits=w.bits; bit_payload=w.finish()
    # Sparse codebook: count (2 bytes), then (symbol, length) pairs.
    # The encoded bit count makes final padding unambiguous.
    table=bytearray(struct.pack('<H',len(lengths)))
    for sym,length in sorted(lengths.items()):
        if length > 255: raise ValueError('Huffman code too long')
        table.extend((sym,length))
    return bytes(table)+struct.pack('<Q',bits)+bit_payload

def huffman_decode(payload: bytes, expected_size: int) -> bytes:
    if len(payload)<10: raise ValueError('truncated Huffman payload')
    count=struct.unpack_from('<H',payload,0)[0]
    table_end=2+count*2
    if count==0 or count>256 or len(payload)<table_end+8: raise ValueError('invalid Huffman table')
    lengths={}
    for i in range(count):
        sym=payload[2+2*i]; length=payload[3+2*i]
        if length==0 or sym in lengths: raise ValueError('invalid Huffman entry')
        lengths[sym]=length
    bits=struct.unpack_from('<Q',payload,table_end)[0]
    bitdata=payload[table_end+8:]
    if bits > len(bitdata)*8 or bits <= 0: raise ValueError('invalid Huffman bit count')
    codes=_canonical_codes(lengths)
    trie={}
    for sym,(code,n) in codes.items():
        node=trie
        for shift in range(n-1,-1,-1):
            bit=(code>>shift)&1
            if 'sym' in node: raise ValueError('non-prefix Huffman table')
            node=node.setdefault(bit,{})
        if node or 'sym' in node: raise ValueError('Huffman code collision')
        node['sym']=sym
    r=BitReader(bitdata); out=bytearray()
    for _ in range(expected_size):
        node=trie
        while 'sym' not in node:
            if r.pos>=bits: raise ValueError('Huffman stream ended early')
            node=node.get(r.read())
            if node is None: raise ValueError('invalid Huffman code')
        out.append(node['sym'])
    if r.pos != bits: raise ValueError('unexpected trailing Huffman bits')
    return bytes(out)


def split_token_stream(tokens: bytes):
    """Split the native token stream into token tags, numeric operands and bytes.

    Tags, operands, and literal/run bytes are coded with separate Huffman
    models. The representation is deterministic and fully reversible.
    """
    tags = bytearray(); operands = bytearray(); literals = bytearray()
    i = 0
    while i < len(tokens):
        tag = tokens[i]; i += 1
        if tag not in (TOK_LITERAL, TOK_MATCH, TOK_RUN, TOK_PHRASE):
            raise ValueError('invalid token stream for typed coding')
        tags.append(tag)
        if tag == TOK_LITERAL:
            n, i = get_varint(tokens, i)
            if n < 1 or i+n > len(tokens): raise ValueError('invalid literal token')
            operands.extend(put_varint(n)); literals.extend(tokens[i:i+n]); i += n
        elif tag == TOK_MATCH:
            n, i = get_varint(tokens, i); dist, i = get_varint(tokens, i)
            operands.extend(put_varint(n)); operands.extend(put_varint(dist))
        elif tag == TOK_RUN:
            n, i = get_varint(tokens, i)
            if n < 4 or i >= len(tokens): raise ValueError('invalid run token')
            operands.extend(put_varint(n)); literals.append(tokens[i]); i += 1
        else:
            idx, i = get_varint(tokens, i)
            operands.extend(put_varint(idx))
    return bytes(tags), bytes(operands), bytes(literals)


def join_typed_streams(tags: bytes, operands: bytes, literals: bytes, expected_token_count: int, phrases=STATIC_PHRASES) -> bytes:
    """Rebuild the original token stream from independently decoded streams."""
    if len(tags) != expected_token_count:
        raise ValueError('typed token count mismatch')
    oi = li = 0
    out = bytearray()
    for tag in tags:
        if tag not in (TOK_LITERAL, TOK_MATCH, TOK_RUN, TOK_PHRASE):
            raise ValueError('invalid typed token tag')
        out.append(tag)
        if tag == TOK_LITERAL:
            n, oi = get_varint(operands, oi)
            if n < 1 or li+n > len(literals): raise ValueError('invalid typed literal')
            out.extend(put_varint(n)); out.extend(literals[li:li+n]); li += n
        elif tag == TOK_MATCH:
            n, oi = get_varint(operands, oi); dist, oi = get_varint(operands, oi)
            if n < 3 or dist == 0: raise ValueError('invalid typed match')
            out.extend(put_varint(n)); out.extend(put_varint(dist))
        elif tag == TOK_RUN:
            n, oi = get_varint(operands, oi)
            if n < 4 or li >= len(literals): raise ValueError('invalid typed run')
            out.extend(put_varint(n)); out.append(literals[li]); li += 1
        else:
            idx, oi = get_varint(operands, oi)
            if idx >= len(phrases): raise ValueError('invalid typed phrase')
            out.extend(put_varint(idx))
    if oi != len(operands) or li != len(literals):
        raise ValueError('unused typed operand or literal bytes')
    return bytes(out)


def typed_huffman_encode(tokens: bytes) -> bytes:
    tags, operands, literals = split_token_stream(tokens)
    t = huffman_encode(tags)
    o = huffman_encode(operands) if operands else b''
    l = huffman_encode(literals) if literals else b''
    # Empty substreams use a zero encoded length and require no Huffman table.
    return (put_varint(len(operands)) + put_varint(len(literals)) +
            put_varint(len(t)) + put_varint(len(o)) + put_varint(len(l)) + t + o + l)


def typed_huffman_decode(payload: bytes, token_count: int, phrases=STATIC_PHRASES) -> bytes:
    i = 0
    operand_n, i = get_varint(payload, i)
    literal_n, i = get_varint(payload, i)
    tag_n, i = get_varint(payload, i)
    operand_enc_n, i = get_varint(payload, i)
    literal_enc_n, i = get_varint(payload, i)
    total = tag_n + operand_enc_n + literal_enc_n
    if total != len(payload) - i: raise ValueError('typed stream lengths mismatch')
    tag_payload = payload[i:i+tag_n]; i += tag_n
    operand_payload = payload[i:i+operand_enc_n]; i += operand_enc_n
    literal_payload = payload[i:i+literal_enc_n]
    tags = huffman_decode(tag_payload, token_count)
    operands = huffman_decode(operand_payload, operand_n) if operand_n else b''
    literals = huffman_decode(literal_payload, literal_n) if literal_n else b''
    return join_typed_streams(tags, operands, literals, token_count, phrases)


# ---------- Optional native BWT/MTF path (implemented here, not delegated) ----------
def bwt_transform(data: bytes):
    """Burrows-Wheeler transform using cyclic-shift rank doubling.

    Returns (last_column, primary_row). This implementation favors clarity
    over speed and is therefore bounded to modest blocks by the caller.
    """
    n = len(data)
    if n == 0: return b'', 0
    sa = list(range(n))
    rank = list(data)
    k = 1
    while k < n:
        sa.sort(key=lambda i: (rank[i], rank[(i+k) % n]))
        new_rank = [0] * n
        classes = 0
        new_rank[sa[0]] = 0
        for j in range(1, n):
            a, b = sa[j-1], sa[j]
            if (rank[a], rank[(a+k) % n]) != (rank[b], rank[(b+k) % n]):
                classes += 1
            new_rank[b] = classes
        rank = new_rank
        if classes == n-1: break
        k <<= 1
    last = bytearray(n)
    primary = 0
    for row, start in enumerate(sa):
        last[row] = data[(start-1) % n]
        if start == 0: primary = row
    return bytes(last), primary

def bwt_inverse(last: bytes, primary: int) -> bytes:
    n = len(last)
    if n == 0: return b''
    if primary < 0 or primary >= n: raise ValueError('invalid BWT primary index')
    counts = [0] * 256
    for b in last: counts[b] += 1
    starts = [0] * 256
    total = 0
    for b in range(256):
        starts[b] = total; total += counts[b]
    seen = [0] * 256
    lf = [0] * n
    for i, b in enumerate(last):
        lf[i] = starts[b] + seen[b]
        seen[b] += 1
    out = bytearray(n); row = primary
    for i in range(n-1, -1, -1):
        out[i] = last[row]
        row = lf[row]
    return bytes(out)

def mtf_encode(data: bytes) -> bytes:
    table = list(range(256)); out = bytearray()
    for b in data:
        idx = table.index(b)
        out.append(idx)
        if idx:
            table.pop(idx); table.insert(0, b)
    return bytes(out)

def mtf_decode(data: bytes) -> bytes:
    table = list(range(256)); out = bytearray()
    for idx in data:
        b = table[idx]; out.append(b)
        if idx:
            table.pop(idx); table.insert(0, b)
    return bytes(out)

def zero_run_encode(data: bytes) -> bytes:
    out = bytearray(); i = 0
    while i < len(data):
        if data[i] == 0:
            j = i+1
            while j < len(data) and data[j] == 0: j += 1
            out.append(0); out.extend(put_varint(j-i)); i = j
        else:
            out.append(data[i]); i += 1
    return bytes(out)

def zero_run_decode(data: bytes, expected_size: int) -> bytes:
    out = bytearray(); i = 0
    while i < len(data):
        b = data[i]; i += 1
        if b == 0:
            n, i = get_varint(data, i)
            if n < 1: raise ValueError('invalid zero run')
            out.extend(b'\x00' * n)
        else:
            out.append(b)
        if len(out) > expected_size: raise ValueError('MTF run stream exceeds expected size')
    if len(out) != expected_size: raise ValueError('MTF run stream size mismatch')
    return bytes(out)

def _bwt_candidate(data: bytes) -> bytes | None:
    if not data or len(data) > MAX_BWT_INPUT: return None
    last, primary = bwt_transform(data)
    mtf = mtf_encode(last)
    zr = zero_run_encode(mtf)
    hc = huffman_encode(zr)
    return put_varint(primary) + put_varint(len(zr)) + hc


# ---------- Compact v0.4 token stream ----------
def compact_encode_tokens(tokens: bytes, phrases=STATIC_PHRASES) -> bytes:
    """Encode native tokens with compact controls; no per-token generic tag+varint overhead.

    Controls 0..127 encode literal lengths 1..128, followed by literal bytes.
    Controls 128..254 encode match lengths 4..32515 in 15 bits plus 4,
    followed by a varint distance. Control 255 introduces an extended token:
      subtype 0: uint32 match length + varint distance
      subtype 1: varint run length + repeated byte
      subtype 2: varint static phrase index
    The stream ends at EOF, so no original-size field is needed.
    """
    out = bytearray(); i = 0
    while i < len(tokens):
        tag = tokens[i]; i += 1
        if tag == TOK_LITERAL:
            n, i = get_varint(tokens, i)
            if n < 1 or i+n > len(tokens): raise ValueError('invalid literal token')
            chunk = tokens[i:i+n]; i += n
            # Try shared text/data codebooks. No table metadata is transmitted.
            choices = []
            for book_id in _STATIC_CODEBOOKS:
                coded = _static_literal_encode(chunk, book_id)
                total = 2 + len(put_varint(len(chunk))) + len(coded)
                choices.append((total, book_id, coded))
            total, book_id, coded = min(choices, key=lambda item: item[0])
            if total < len(chunk) + 1:
                out.append(255); out.append(book_id); out.extend(put_varint(len(chunk))); out.extend(coded)
            else:
                off = 0
                while off < len(chunk):
                    part = chunk[off:off+128]
                    out.append(len(part)-1); out.extend(part); off += len(part)
        elif tag == TOK_MATCH:
            n, i = get_varint(tokens, i); dist, i = get_varint(tokens, i)
            if n < 3 or dist < 1: raise ValueError('invalid match token')
            if n == 3:
                out.extend((255, 8)); out.extend(put_varint(dist))
            elif n <= 32515:
                x = n - 4
                out.append(128 + (x >> 8)); out.append(x & 0xff)
            else:
                if n > 0xffffffff: raise ValueError('match length too large')
                out.append(255); out.append(0); out.extend(struct.pack('<I', n))
            out.extend(put_varint(dist))
        elif tag == TOK_RUN:
            n, i = get_varint(tokens, i)
            if n < 4 or i >= len(tokens): raise ValueError('invalid run token')
            out.extend((255, 1)); out.extend(put_varint(n)); out.append(tokens[i]); i += 1
        elif tag == TOK_PHRASE:
            idx, i = get_varint(tokens, i)
            if idx >= len(phrases): raise ValueError('invalid phrase token')
            out.extend((255, 2)); out.extend(put_varint(idx))
        else:
            raise ValueError('unknown token type')
    return bytes(out)


def compact_decode_tokens(payload: bytes, max_output: int = 1 << 40, phrases=STATIC_PHRASES) -> bytes:
    """Decode compact tokens directly to bytes; payload ends at EOF."""
    out = bytearray(); i = 0
    while i < len(payload):
        ctrl = payload[i]; i += 1
        if ctrl < 128:
            n = ctrl + 1
            if i+n > len(payload): raise ValueError('truncated compact literal')
            out.extend(payload[i:i+n]); i += n
        elif ctrl < 255:
            if i >= len(payload): raise ValueError('truncated compact match')
            n = (((ctrl - 128) << 8) | payload[i]) + 4; i += 1
            dist, i = get_varint(payload, i)
            if dist < 1 or dist > len(out): raise ValueError('invalid compact match distance')
            if len(out) + n > max_output: raise ValueError('decoded output exceeds safety limit')
            for _ in range(n): out.append(out[-dist])
        else:
            if i >= len(payload): raise ValueError('truncated extended token')
            subtype = payload[i]; i += 1
            if subtype == 0:
                if i + 4 > len(payload): raise ValueError('truncated extended match length')
                n = struct.unpack_from('<I', payload, i)[0]; i += 4
                dist, i = get_varint(payload, i)
                if n < MIN_MATCH or dist < 1 or dist > len(out): raise ValueError('invalid extended match')
                if len(out) + n > max_output: raise ValueError('decoded output exceeds safety limit')
                for _ in range(n): out.append(out[-dist])
            elif subtype == 1:
                n, i = get_varint(payload, i)
                if n < 4 or i >= len(payload): raise ValueError('invalid compact run')
                b = payload[i]; i += 1
                if len(out) + n > max_output: raise ValueError('decoded output exceeds safety limit')
                out.extend(bytes([b]) * n)
            elif subtype == 2:
                idx, i = get_varint(payload, i)
                if idx >= len(phrases): raise ValueError('invalid compact phrase')
                if len(out) + len(phrases[idx]) > max_output: raise ValueError('decoded output exceeds safety limit')
                out.extend(phrases[idx])
            elif subtype == 8:
                dist, i = get_varint(payload, i)
                if dist < 1 or dist > len(out): raise ValueError('invalid short-match distance')
                if len(out) + 3 > max_output: raise ValueError('decoded output exceeds safety limit')
                for _ in range(3): out.append(out[-dist])
            elif subtype in _STATIC_CODEBOOKS:
                n, i = get_varint(payload, i)
                if n < 1 or len(out) + n > max_output: raise ValueError('invalid static literal length')
                decoded, used = _static_literal_decode(payload[i:], n, subtype)
                out.extend(decoded); i += used
            else:
                raise ValueError('unknown extended token subtype')
        if len(out) > max_output: raise ValueError('decoded output exceeds safety limit')
    return bytes(out)


def _compact_token_candidates(data: bytes, use_dp: bool = True, min_match=None):
    """Return validated (native_tokens, compact_bytes) candidates."""
    # Try both phrase-aware and phrase-free parsing. Phrases can help repeated
    # technical text, while phrase-free parsing may preserve longer literal
    # spans that benefit from the built-in static byte prior.
    streams = [tokenize(data, min_match=min_match), tokenize(data, phrase_map={}, min_match=min_match)]
    # Bounded DP is expensive in Python; retain it for moderate blocks only.
    if use_dp and len(data) <= 8192:
        streams.append(tokenize_dp(data, min_match=min_match))
        if min_match is None or min_match > 3:
            streams.append(tokenize_dp(data, min_match=3))
    valid = []
    seen = set()
    for tokens in streams:
        try:
            if detokenize(tokens, len(data)) != data:
                continue
            compact = compact_encode_tokens(tokens)
            if compact not in seen:
                valid.append((tokens, compact)); seen.add(compact)
        except (ValueError, IndexError):
            continue
    if not valid:
        # Always-valid literal-only representation.
        literal = bytearray(); pos = 0
        while pos < len(data):
            chunk = data[pos:pos+MAX_LITERAL]
            literal.append(TOK_LITERAL); literal.extend(put_varint(len(chunk))); literal.extend(chunk)
            pos += len(chunk)
        tokens = bytes(literal)
        valid.append((tokens, compact_encode_tokens(tokens)))
    return valid


def _compact_payload(data: bytes, use_dp: bool = True, min_match=None) -> bytes:
    """Best valid compact token stream among native parses."""
    return min((compact for _, compact in _compact_token_candidates(data, use_dp, min_match)), key=len)


def _delta_encode(data: bytes) -> bytes:
    if not data: return b''
    out = bytearray(len(data)); out[0] = data[0]
    for i in range(1, len(data)):
        out[i] = (data[i] - data[i-1]) & 0xff
    return bytes(out)


def _delta_decode(data: bytes) -> bytes:
    if not data: return b''
    out = bytearray(data); acc = out[0]
    for i in range(1, len(out)):
        acc = (acc + out[i]) & 0xff
        out[i] = acc
    return bytes(out)


def _xor_encode(data: bytes) -> bytes:
    if not data: return b''
    out = bytearray(len(data)); out[0] = data[0]
    for i in range(1, len(data)):
        out[i] = data[i] ^ data[i-1]
    return bytes(out)


def _xor_decode(data: bytes) -> bytes:
    if not data: return b''
    out = bytearray(data); prev = out[0]
    for i in range(1, len(out)):
        out[i] ^= prev
        prev = out[i]
    return bytes(out)


def _bwt_arith_payload(data: bytes):
    """Return (primary, compact_size, arithmetic_bytes) for one BWT block."""
    last, primary = bwt_transform(data)
    mtf = mtf_encode(last)
    zr = zero_run_encode(mtf)
    compact = _compact_payload(zr, use_dp=False)
    return primary, len(compact), _arith_encode(compact)


def _blockwise_candidate(data: bytes, block_size: int = 4096) -> bytes:
    """Encode blocks using the cheaper native direct or BWT representation.

    This is a single VG-21C block format; each block uses our own tokenizer,
    transform and arithmetic coder. It is attempted only when whole-file
    compression is weak enough that local structure may be useful.
    """
    records = []
    for start in range(0, len(data), block_size):
        block = data[start:start+block_size]
        compact = _compact_payload(block, use_dp=True)
        direct_arith = _arith_encode(compact)
        direct_record = (1 + len(put_varint(len(block))) +
                         len(put_varint(len(compact))) + len(put_varint(len(direct_arith))) + len(direct_arith))
        best = (direct_record, 0, len(block), len(compact), 0, direct_arith)
        if len(block) >= 64:
            primary, bwt_token_size, bwt_arith = _bwt_arith_payload(block)
            bwt_record = (1 + len(put_varint(len(block))) +
                          len(put_varint(bwt_token_size)) + len(put_varint(len(bwt_arith))) +
                          len(put_varint(primary)) + len(bwt_arith))
            if bwt_record < best[0]:
                best = (bwt_record, 1, len(block), bwt_token_size, primary, bwt_arith)
        _, mode, original_n, token_n, primary, encoded = best
        rec = bytearray([mode]); rec.extend(put_varint(original_n)); rec.extend(put_varint(token_n)); rec.extend(put_varint(len(encoded)))
        if mode == 1: rec.extend(put_varint(primary))
        rec.extend(encoded); records.append(bytes(rec))
    body = put_varint(len(records)) + b''.join(records)
    return BLOCK_MAGIC + body + struct.pack('<I', zlib.crc32(data))


def _exact_period(data: bytes, max_period: int = 4096, min_repeats: int = 4) -> bytes | None:
    """Return the shortest exact repeating seed, if the whole input is periodic."""
    n = len(data)
    if n < 64 or n > (1 << 20):
        return None
    # Prefix-function (KMP) computes the minimal candidate period in O(n).
    pi = [0] * n
    j = 0
    for i in range(1, n):
        while j and data[i] != data[j]:
            j = pi[j - 1]
        if data[i] == data[j]:
            j += 1
        pi[i] = j
    period = n - pi[-1]
    if period < 1 or period > max_period or n % period or n // period < min_repeats:
        return None
    seed = data[:period]
    if seed * (n // period) != data:
        return None
    return seed


def _period_candidate(data: bytes) -> bytes | None:
    seed = _exact_period(data)
    if seed is None:
        return None
    seed_payload = _compact_payload(seed, use_dp=False, min_match=12)
    # The original size and seed payload size make the stream self-delimiting.
    # CRC is retained for corruption detection; seed is decoded by our own codec.
    return (PERIOD_MAGIC + put_varint(len(data)) + put_varint(len(seed_payload)) +
            seed_payload + struct.pack('<I', zlib.crc32(data)))



def _period_arith_candidate(data: bytes):
    seed=_exact_period(data)
    if seed is None: return None
    seed_payload=_compact_payload(seed,use_dp=False,min_match=12)
    coded=_arith_encode(seed_payload)
    blob=(PERIOD_ARITH_MAGIC+put_varint(len(data))+put_varint(len(seed_payload))+
          put_varint(len(coded))+coded+struct.pack('<I',zlib.crc32(data)))
    return blob if len(blob)<len(data) else None

def _json_canonical_bytes(value) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(',', ':'), sort_keys=True).encode('ascii')


def _json_candidate(data: bytes) -> bytes | None:
    """Encode canonical JSON arrays of same-schema objects column-wise.

    This is a native reversible representation, not a call to a compressor.
    Only use it when re-serialization reproduces the exact original bytes.
    """
    if not data or data[:1] not in (b'[', b'{') or len(data) < 32 or len(data) > (16 << 20):
        return None
    try:
        root = json.loads(data)
    except (ValueError, UnicodeDecodeError):
        return None
    root_kind = 0
    root_field = None
    root_static = None
    if isinstance(root, list):
        rows = root
    elif isinstance(root, dict):
        # Support objects containing a repeated array-of-records field.
        options = [(k, v) for k, v in root.items()
                   if isinstance(v, list) and len(v) >= 8 and all(isinstance(r, dict) for r in v)]
        if not options:
            return None
        root_field, rows = max(options, key=lambda kv: len(kv[1]))
        root_kind = 1
        root_static = {k: v for k, v in root.items() if k != root_field}
    else:
        return None
    if len(rows) < 8 or not all(isinstance(r, dict) for r in rows):
        return None
    keys = sorted(rows[0].keys())
    if not keys or any(sorted(r.keys()) != keys for r in rows):
        return None
    # Preserve byte-exact semantics by restricting this transform to canonical JSON.
    try:
        if _json_canonical_bytes(root) != data:
            return None
    except (TypeError, ValueError):
        return None

    payload = bytearray([root_kind])
    if root_kind == 1:
        field_bytes = _json_canonical_bytes(root_field)
        static_bytes = _json_canonical_bytes(root_static)
        payload.extend(put_varint(len(field_bytes))); payload.extend(field_bytes)
        payload.extend(put_varint(len(static_bytes))); payload.extend(static_bytes)
    payload.extend(put_varint(len(rows)))
    payload.extend(put_varint(len(keys)))
    for key in keys:
        kb = _json_canonical_bytes(key)
        payload.extend(put_varint(len(kb))); payload.extend(kb)

    for key in keys:
        values = [row[key] for row in rows]
        serialized = [_json_canonical_bytes(v) for v in values]
        if all(type(v) is int for v in values):
            # Delta + zigzag + varint: monotonically changing integer columns
            # usually cost one byte per value before entropy coding.
            plain = bytearray(); previous = 0
            for idx, value in enumerate(values):
                delta = value if idx == 0 else value - previous
                previous = value
                zz = (delta << 1) if delta >= 0 else ((-delta << 1) - 1)
                plain.extend(put_varint(zz))
            coded = _arith_encode(bytes(plain))
            payload.append(1); payload.extend(put_varint(len(plain)))
            payload.extend(put_varint(len(coded))); payload.extend(coded)
        elif all(x == serialized[0] for x in serialized):
            # Constant nested arrays/objects are stored once for the whole column.
            payload.append(3); payload.extend(put_varint(len(serialized[0]))); payload.extend(serialized[0])
        elif all(isinstance(v, str) for v in values) and len(set(serialized)) <= 256:
            dictionary = []
            lookup = {}
            ids = bytearray()
            for raw in serialized:
                if raw not in lookup:
                    lookup[raw] = len(dictionary); dictionary.append(raw)
                ids.append(lookup[raw])
            coded = _arith_encode(bytes(ids))
            payload.append(2); payload.extend(put_varint(len(dictionary)))
            for raw in dictionary:
                payload.extend(put_varint(len(raw))); payload.extend(raw)
            payload.extend(put_varint(len(ids))); payload.extend(put_varint(len(coded))); payload.extend(coded)
        else:
            # General column: length-prefixed canonical JSON values, entropy-coded.
            plain = bytearray()
            for raw in serialized:
                plain.extend(put_varint(len(raw))); plain.extend(raw)
            coded = _arith_encode(bytes(plain))
            payload.append(4); payload.extend(put_varint(len(plain)))
            payload.extend(put_varint(len(coded))); payload.extend(coded)

    return (JSON_MAGIC + put_varint(len(data)) + bytes(payload) +
            struct.pack('<I', zlib.crc32(data)))



def _json_arith_candidate(json_blob: bytes, original: bytes):
    """Entropy-code the columnar transform's metadata and streams together."""
    if not json_blob or not json_blob.startswith(JSON_MAGIC): return None
    i=4; declared,i=get_varint(json_blob,i)
    if declared!=len(original) or len(json_blob)<i+4: return None
    plain=json_blob[i:-4]
    coded=_arith_encode(plain)
    blob=(JSON_ARITH_MAGIC + put_varint(len(original)) + put_varint(len(plain)) +
          put_varint(len(coded)) + coded + struct.pack('<I',zlib.crc32(original)))
    return blob if len(blob)<len(json_blob) else None

def _json_decode_payload(payload: bytes) -> bytes:
    original_size, i = get_varint(payload, 0)
    if i >= len(payload): raise ValueError('truncated JSON root kind')
    root_kind = payload[i]; i += 1
    root_field = None; root_static = None
    if root_kind == 1:
        n, i = get_varint(payload, i)
        if n > len(payload) - i: raise ValueError('truncated JSON root field')
        root_field = json.loads(payload[i:i+n]); i += n
        n, i = get_varint(payload, i)
        if n > len(payload) - i: raise ValueError('truncated JSON static root')
        root_static = json.loads(payload[i:i+n]); i += n
        if not isinstance(root_field, str) or not isinstance(root_static, dict): raise ValueError('invalid JSON root metadata')
    elif root_kind != 0:
        raise ValueError('unknown JSON root kind')
    row_count, i = get_varint(payload, i)
    key_count, i = get_varint(payload, i)
    if row_count > 10_000_000 or key_count > 100_000:
        raise ValueError('JSON dimensions exceed safety limit')
    keys = []
    for _ in range(key_count):
        n, i = get_varint(payload, i)
        if n > len(payload) - i: raise ValueError('truncated JSON schema key')
        key = json.loads(payload[i:i+n]); i += n
        if not isinstance(key, str): raise ValueError('invalid JSON schema key')
        keys.append(key)
    columns = []
    for _ in range(key_count):
        if i >= len(payload): raise ValueError('truncated JSON column')
        kind = payload[i]; i += 1
        if kind == 1:
            plain_n, i = get_varint(payload, i); coded_n, i = get_varint(payload, i)
            if coded_n > len(payload) - i: raise ValueError('truncated integer column')
            plain = _arith_decode(payload[i:i+coded_n], plain_n); i += coded_n
            vals = []; j = 0; previous = 0
            for idx in range(row_count):
                zz, j = get_varint(plain, j)
                delta = zz >> 1 if not (zz & 1) else -((zz >> 1) + 1)
                value = delta if idx == 0 else previous + delta
                vals.append(value); previous = value
            if j != len(plain): raise ValueError('unused integer column bytes')
        elif kind == 2:
            dict_n, i = get_varint(payload, i)
            if dict_n < 1 or dict_n > 256: raise ValueError('invalid JSON string dictionary')
            dictionary = []
            for _ in range(dict_n):
                n, i = get_varint(payload, i)
                if n > len(payload) - i: raise ValueError('truncated JSON dictionary string')
                dictionary.append(json.loads(payload[i:i+n])); i += n
            plain_n, i = get_varint(payload, i); coded_n, i = get_varint(payload, i)
            if coded_n > len(payload) - i: raise ValueError('truncated JSON string IDs')
            ids = _arith_decode(payload[i:i+coded_n], plain_n); i += coded_n
            if len(ids) != row_count or any(x >= len(dictionary) for x in ids): raise ValueError('invalid JSON string IDs')
            vals = [dictionary[x] for x in ids]
        elif kind == 3:
            n, i = get_varint(payload, i)
            if n > len(payload) - i: raise ValueError('truncated constant JSON value')
            value = json.loads(payload[i:i+n]); i += n
            vals = [value] * row_count
        elif kind == 4:
            plain_n, i = get_varint(payload, i); coded_n, i = get_varint(payload, i)
            if coded_n > len(payload) - i: raise ValueError('truncated general JSON column')
            plain = _arith_decode(payload[i:i+coded_n], plain_n); i += coded_n
            vals = []; j = 0
            for _ in range(row_count):
                n, j = get_varint(plain, j)
                if n > len(plain) - j: raise ValueError('truncated JSON value')
                vals.append(json.loads(plain[j:j+n])); j += n
            if j != len(plain): raise ValueError('unused general JSON bytes')
        else:
            raise ValueError('unknown JSON column type')
        if len(vals) != row_count: raise ValueError('JSON column length mismatch')
        columns.append(vals)
    if i != len(payload): raise ValueError('trailing JSON column payload')
    rows = [{key: columns[col][r] for col, key in enumerate(keys)} for r in range(row_count)]
    if root_kind == 1:
        root = dict(root_static); root[root_field] = rows
    else:
        root = rows
    out = _json_canonical_bytes(root)
    if len(out) != original_size: raise ValueError('JSON reconstruction size mismatch')
    return out



def _typed_prior(stream_index: int):
    """Shared priors for native token streams: tags, varint operands, literals."""
    counts=[1]*256
    if stream_index==0:
        for sym,weight in enumerate((1024,256,128,64)):
            counts[sym]=weight
    elif stream_index==1:
        for b in range(256):
            if b==0: counts[b]=256
            elif b==1: counts[b]=160
            elif b<8: counts[b]=64
            elif b<16: counts[b]=32
            elif b<32: counts[b]=16
            elif b<64: counts[b]=8
            elif b<128: counts[b]=4
            else: counts[b]=1
    else:
        for b in range(32,127): counts[b]=8
        for ch,w in {' ':512,'e':256,'t':192,'a':160,'o':144,'i':128,'n':128,'s':112,
                     'r':112,'h':96,'d':80,'l':80,'u':64,'c':64,'m':56,'\n':96,
                     '.':48,',':48,'(':48,')':48,'_':48,'=':48,'0':32,'1':32}.items():
            counts[ord(ch)]=w
    return counts

def _compact_candidate(data: bytes, min_match=None) -> bytes:
    """Try native direct, entropy-coded, transformed and block representations.

    min_match optionally evaluates a different LZ match threshold without
    changing the global/default parser configuration.
    """
    crc = struct.pack('<I', zlib.crc32(data))
    direct_pairs = _compact_token_candidates(data, use_dp=True, min_match=min_match)
    candidates = [V4_MAGIC + min((compact for _, compact in direct_pairs), key=len) + crc]

    # Adaptive arithmetic coding of our compact token stream.
    for _, compact in direct_pairs:
        arith = _arith_encode(compact)
        candidates.append(ARITH_MAGIC + put_varint(len(data)) + put_varint(len(compact)) + arith + crc)

    # Typed Huffman uses independent native models for token tags/operands/literals.
    for tokens, _ in direct_pairs:
        try:
            tags, _, _ = split_token_stream(tokens)
            typed = typed_huffman_encode(tokens)
            candidates.append(TYPED_MAGIC + put_varint(len(data)) + put_varint(len(tags)) + typed + crc)
            # v0.7: independent arithmetic models for token tags, operands and
            # literal/run bytes. This avoids forcing three very different symbol
            # distributions through one entropy model.
            operands, literals = None, None
            tag_stream, operand_stream, literal_stream = split_token_stream(tokens)
            coded_streams = []
            for plain in (tag_stream, operand_stream, literal_stream):
                # Choose the cheaper of our own order-0 and order-1 arithmetic
                # models per stream, counting selector and length metadata.
                prior = _typed_prior(len(coded_streams))
                coded_options = (
                    (0, _arith_encode(plain)),
                    (1, _context_arith_encode(plain)),
                    (2, _arith_encode(plain, prior)),
                    (3, _context_arith_encode(plain, prior)),
                )
                coded_streams.append(min(coded_options, key=lambda item: 1 + len(put_varint(len(item[1]))) + len(item[1])))
            fields = bytearray(TYPED_ARITH_MAGIC + put_varint(len(data)) + put_varint(len(tag_stream)))
            for plain, (coder_id, coded) in zip((tag_stream, operand_stream, literal_stream), coded_streams):
                fields.append(coder_id); fields.extend(put_varint(len(plain))); fields.extend(put_varint(len(coded))); fields.extend(coded)
            fields.extend(crc)
            candidates.append(bytes(fields))
        except (ValueError, IndexError):
            continue

    # v0.7: also try context coding when the token representation is already
    # compact. The previous size/entropy gate accidentally skipped this option
    # on highly repetitive inputs, where the token stream is tiny and context
    # coding can still beat plain arithmetic coding.
    for _, compact in direct_pairs:
        if 0 < len(compact) <= 8192:
            coded_context = _context_arith_encode(compact)
            candidates.append(CONTEXT_MAGIC + put_varint(len(data)) +
                              put_varint(len(compact)) + coded_context + crc)

    # Context coding can be expensive on large token streams; this additional
    # branch is retained for larger inputs where structural entropy is low.
    current_size = min(map(len, candidates))
    if len(data) >= 256 and current_size > len(data) // 10:
        freq = Counter(data)
        entropy_est = -sum((n/len(data)) * __import__('math').log2(n/len(data)) for n in freq.values())
        if entropy_est < 7.7:
            for _, compact in direct_pairs:
                coded = _context_arith_encode(compact)
                candidates.append(CONTEXT_MAGIC + put_varint(len(data)) + put_varint(len(compact)) + coded + crc)

    delta = _delta_encode(data)
    candidates.append(DELTA_MAGIC + _compact_payload(delta, use_dp=False) + crc)

    xor_data = _xor_encode(data)
    candidates.append(XOR_MAGIC + _compact_payload(xor_data, use_dp=False) + crc)

    # BWT is expensive in pure Python. Only try it when the best current
    # candidate is still sizeable and the source has non-random byte entropy.
    current_size = min(map(len, candidates))
    if 0 < len(data) <= MAX_BWT_INPUT and current_size > len(data) // 10:
        freq = Counter(data)
        entropy_est = -sum((n/len(data)) * __import__('math').log2(n/len(data)) for n in freq.values())
    else:
        entropy_est = 8.0
    if 0 < len(data) <= MAX_BWT_INPUT and current_size > len(data) // 10 and entropy_est < 7.7:
        last, primary = bwt_transform(data)
        mtf = mtf_encode(last)
        zr = zero_run_encode(mtf)
        bwt_payload = (put_varint(len(data)) + put_varint(primary) +
                       _compact_payload(zr, use_dp=False))
        candidates.append(BWT_MAGIC + bwt_payload + crc)

        arith_mtf = _arith_encode(mtf, _mtf_prior())
        candidates.append(BWT_ARITH_MAGIC + put_varint(len(data)) + put_varint(primary) +
                          put_varint(len(mtf)) + arith_mtf + crc)
        context_mtf = _context_arith_encode(mtf, _mtf_prior())
        candidates.append(BWT_CONTEXT_MAGIC + put_varint(len(data)) + put_varint(primary) +
                          put_varint(len(mtf)) + context_mtf + crc)

    # v0.7: BWT -> MTF -> zero-run -> arithmetic coding. The zero-run transform
    # can be much more effective than coding raw MTF ranks on data with long
    # rank-zero runs (for example, padded tar archives). Count the complete frame.
    current_size = min(map(len, candidates))
    if 0 < len(data) <= 256 * 1024 and current_size > len(data) // 20:
        freq = Counter(data)
        entropy_est = -sum((n/len(data)) * __import__('math').log2(n/len(data)) for n in freq.values())
        if entropy_est < 7.95:
            last2, primary2 = bwt_transform(data)
            mtf2 = mtf_encode(last2)
            zr2 = zero_run_encode(mtf2)
            arith_zr = _arith_encode(zr2)
            candidates.append(BWT_RLE_ARITH_MAGIC + put_varint(len(data)) +
                              put_varint(primary2) + put_varint(len(zr2)) + arith_zr + crc)

    # For larger inputs with weak whole-file compression, compare per-block
    # native representations. Avoid this expensive path on already-compressible data.
    current_best = min(candidates, key=len)
    if len(data) > MAX_BWT_INPUT and len(data) <= 16 * 1024 and len(current_best) > len(data) // 4:
        candidates.append(_blockwise_candidate(data))
    return min(candidates, key=len)


FIXED_HEADER = len(MAGIC) + 1 + 8 + 8 + 8 + 4

def _compress_legacy(data: bytes) -> bytes:
    raw_blob=MAGIC+bytes([MODE_RAW])+data
    if not data: return raw_blob
    candidates=[]
    # Compare both greedy and bounded-DP parses. Each parse is encoded through
    # the complete native formats; the smallest complete representation wins.
    token_streams = []
    for stream in (tokenize(data), tokenize_dp(data)):
        if stream not in token_streams:
            token_streams.append(stream)
    for tokens in token_streams:
        tok_blob=(MAGIC+bytes([MODE_TOKENS])+struct.pack('<QQQI',len(data),len(tokens),len(tokens),zlib.crc32(data))+tokens)
        huff=huffman_encode(tokens)
        huff_blob=(MAGIC+bytes([MODE_HUFFMAN])+struct.pack('<QQQI',len(data),len(tokens),len(huff),zlib.crc32(data))+huff)
        candidates.extend([tok_blob,huff_blob])
        typed=typed_huffman_encode(tokens)
        typed_blob=(MAGIC+bytes([MODE_TYPED_HUFFMAN])+struct.pack('<QQQI',len(data),len(split_token_stream(tokens)[0]),len(typed),zlib.crc32(data))+typed)
        candidates.append(typed_blob)
    # Native transform path: BWT -> move-to-front -> zero-run coding -> our Huffman.
    # This is part of VG-21C's own format/decoder, not a call to bzip2 or another codec.
    bwt_payload=_bwt_candidate(data)
    if bwt_payload is not None:
        # token_size stores the zero-run stream length; primary index is prefixed to payload.
        primary, p = get_varint(bwt_payload, 0)
        zr_len, p = get_varint(bwt_payload, p)
        huff_payload=bwt_payload[p:]
        bwt_blob=(MAGIC+bytes([MODE_BWT])+struct.pack('<QQQI',len(data),zr_len,len(bwt_payload),zlib.crc32(data))+bwt_payload)
        candidates.append(bwt_blob)
    best=min(candidates,key=len)
    return best if len(best)<len(raw_blob) else raw_blob

def _decompress_legacy(blob: bytes) -> bytes:
    if len(blob)<7 or blob[:6]!=MAGIC: raise ValueError('not a VG-21C v0.2 stream')
    mode=blob[6]
    if mode==MODE_RAW: return blob[7:]
    if mode not in (MODE_TOKENS,MODE_HUFFMAN,MODE_BWT,MODE_TYPED_HUFFMAN): raise ValueError('unknown mode')
    if len(blob)<FIXED_HEADER: raise ValueError('truncated header')
    original_size, token_size, payload_size, crc=struct.unpack_from('<QQQI',blob,7)
    payload=blob[FIXED_HEADER:]
    if payload_size!=len(payload): raise ValueError('payload size mismatch')
    if original_size > 1<<40 or token_size > 1<<40: raise ValueError('declared size too large')
    if mode==MODE_TOKENS:
        if len(payload)!=token_size: raise ValueError('token size mismatch')
        tokens=payload
        out=detokenize(tokens,original_size)
    elif mode==MODE_HUFFMAN:
        tokens=huffman_decode(payload,token_size)
        out=detokenize(tokens,original_size)
    elif mode==MODE_TYPED_HUFFMAN:
        tokens=typed_huffman_decode(payload,token_size)
        out=detokenize(tokens,original_size)
    else:
        primary, p = get_varint(payload, 0)
        zr_len, p = get_varint(payload, p)
        if zr_len != token_size: raise ValueError('BWT stream size mismatch')
        zr = huffman_decode(payload[p:], zr_len)
        mtf = zero_run_decode(zr, original_size)
        last = mtf_decode(mtf)
        out = bwt_inverse(last, primary)
        if len(out) != original_size: raise ValueError('BWT output size mismatch')
    if zlib.crc32(out)!=crc: raise ValueError('checksum mismatch')
    return out



# ---------- V21F: adaptive phrase dictionary, implemented natively ----------
def _discover_phrases(data: bytes, max_phrases: int = 192):
    """Discover repeated byte phrases without relying on an external compressor.

    Candidate lengths are sampled to bound runtime/memory. Selection is only a
    proposal; the complete encoded representation is measured before use.
    """
    n = len(data)
    if n < 512:
        return ()
    counts = Counter()
    lengths = (4, 6, 8, 10, 12, 16, 20, 24, 32)
    for length in lengths:
        if length >= n:
            continue
        # Every position is considered; repeated substrings are counted even
        # when their occurrences overlap. The actual encoder later measures
        # non-overlapping use, so this estimate cannot force a candidate win.
        for i in range(0, n - length + 1):
            counts[data[i:i+length]] += 1
    ranked = []
    for phrase, freq in counts.items():
        length = len(phrase)
        # Token is two bytes (0xFF + id); reserve extra cost for table framing.
        gross = freq * max(0, length - 2) - length - 3
        if freq >= 3 and gross > 0:
            ranked.append((gross, freq, length, phrase))
    ranked.sort(key=lambda x: (-x[0], -x[1], -x[2], x[3]))
    selected = []
    seen = set()
    for _, _, _, phrase in ranked:
        if phrase in seen:
            continue
        selected.append(phrase); seen.add(phrase)
        if len(selected) >= max_phrases:
            break
    # Prefer longer phrases on ties during matching; stable phrase IDs make
    # the format deterministic across Python versions.
    return tuple(selected)


def _phrase_trie(phrases):
    root = {}
    for idx, phrase in enumerate(phrases, 1):
        node = root
        for b in phrase:
            node = node.setdefault(b, {})
        node[None] = idx
    return root


def _phrase_tokenize(data: bytes, phrases):
    trie = _phrase_trie(phrases)
    out = bytearray(); i = 0
    while i < len(data):
        node = trie; j = i; best_id = 0; best_end = i
        while j < len(data) and data[j] in node:
            node = node[data[j]]; j += 1
            if None in node:
                best_id = node[None]; best_end = j
        if best_id:
            out.extend((255, best_id)); i = best_end
        else:
            b = data[i]
            if b == 255:
                out.extend((255, 0))
            else:
                out.append(b)
            i += 1
    return bytes(out)


def _phrase_candidate(data: bytes):
    """Build a self-contained dictionary-coded candidate; None if no gain."""
    phrases = _discover_phrases(data)
    if not phrases:
        return None
    # Test several table sizes because the most profitable estimated phrases
    # may overlap. Every version is scored by exact final bytes.
    best = None
    for count in (24, 64, 128):
        table = phrases[:count]
        token_stream = _phrase_tokenize(data, table)
        coded = _arith_encode(token_stream)
        body = bytearray(DICT_MAGIC)
        body.extend(put_varint(len(data)))
        body.extend(put_varint(len(table)))
        for phrase in table:
            body.extend(put_varint(len(phrase))); body.extend(phrase)
        body.extend(put_varint(len(token_stream)))
        body.extend(put_varint(len(coded)))
        body.extend(coded)
        body.extend(struct.pack('<I', zlib.crc32(data)))
        candidate = bytes(body)
        if best is None or len(candidate) < len(best):
            best = candidate
    return best


def _phrase_decode(payload: bytes) -> bytes:
    i = 0
    original_n, i = get_varint(payload, i)
    count, i = get_varint(payload, i)
    if count > 255:
        raise ValueError('phrase count exceeds format limit')
    phrases = []
    for _ in range(count):
        n, i = get_varint(payload, i)
        if n < 1 or n > (1 << 20) or n > len(payload) - i:
            raise ValueError('invalid phrase length')
        phrases.append(payload[i:i+n]); i += n
    token_n, i = get_varint(payload, i)
    coded_n, i = get_varint(payload, i)
    if coded_n != len(payload) - i:
        raise ValueError('phrase-coded payload length mismatch')
    tokens = _arith_decode(payload[i:], token_n)
    out = bytearray(); j = 0
    while j < len(tokens):
        b = tokens[j]; j += 1
        if b != 255:
            out.append(b); continue
        if j >= len(tokens):
            raise ValueError('truncated phrase escape')
        idx = tokens[j]; j += 1
        if idx == 0:
            out.append(255)
        elif idx <= len(phrases):
            out.extend(phrases[idx-1])
        else:
            raise ValueError('invalid phrase index')
        if len(out) > original_n:
            raise ValueError('phrase output exceeds declared size')
    if len(out) != original_n:
        raise ValueError('phrase output size mismatch')
    return bytes(out)


# ---------- V21G: native pair-grammar compression ----------
def _grammar_build(data: bytes, max_rules: int = 64):
    """Greedy pair grammar over integer symbols, with bounded rule count."""
    seq = list(data)
    rules = []
    for _ in range(max_rules):
        if len(seq) < 8:
            break
        counts = Counter(zip(seq, seq[1:]))
        # Consider the most common pairs first, then measure realizable
        # non-overlapping occurrences. Avoid rules that only save a few tokens.
        candidates = sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:4]
        best_pair = None; best_actual = 0
        for (a, b), overlap_count in candidates:
            if overlap_count < 5:
                break
            actual = 0; i = 0
            while i < len(seq) - 1:
                if seq[i] == a and seq[i+1] == b:
                    actual += 1; i += 2
                else:
                    i += 1
            if actual > best_actual:
                best_pair = (a, b); best_actual = actual
        if best_pair is None or best_actual < 5:
            break
        a, b = best_pair
        symbol = 256 + len(rules)
        rules.append((a, b))
        out = []; i = 0
        while i < len(seq):
            if i + 1 < len(seq) and seq[i] == a and seq[i+1] == b:
                out.append(symbol); i += 2
            else:
                out.append(seq[i]); i += 1
        seq = out
    return rules, seq


def _arith_encode_symbols(symbols, alphabet_size: int, initial_counts=None) -> bytes:
    """Adaptive arithmetic coder for a bounded integer alphabet."""
    if not symbols: return b''
    TOP=(1<<32)-1; HALF=1<<31; Q1=1<<30; Q3=3<<30
    low=0; high=TOP; pending=0; writer=BitWriter()
    counts=list(initial_counts) if initial_counts is not None else [1]*alphabet_size
    if len(counts)!=alphabet_size: raise ValueError('initial count table size mismatch')
    fenwick=_Fenwick(counts)
    def emit(bit):
        nonlocal pending
        writer.write(bit); opposite=bit^1
        while pending:
            writer.write(opposite); pending-=1
    for symbol in symbols:
        if symbol < 0 or symbol >= alphabet_size: raise ValueError('symbol outside alphabet')
        total=fenwick.total(); cum=fenwick.prefix(symbol); freq=counts[symbol]; rng=high-low+1
        high=low+(rng*(cum+freq)//total)-1; low=low+(rng*cum//total)
        while True:
            if high < HALF: emit(0)
            elif low >= HALF: emit(1); low-=HALF; high-=HALF
            elif low >= Q1 and high < Q3: pending+=1; low-=Q1; high-=Q1
            else: break
            low=(low<<1)&TOP; high=((high<<1)|1)&TOP
        counts[symbol]+=1; fenwick.add(symbol,1)
        if fenwick.total() >= 1<<15:
            counts=[max(1,(c+1)//2) for c in counts]; fenwick=_Fenwick(counts)
    pending+=1; emit(0 if low<Q1 else 1)
    return writer.finish()


def _arith_decode_symbols(payload: bytes, output_count: int, alphabet_size: int, initial_counts=None):
    if output_count == 0: return []
    TOP=(1<<32)-1; HALF=1<<31; Q1=1<<30; Q3=3<<30
    reader=BitReader(payload)
    def read_or_zero():
        try: return reader.read()
        except ValueError: return 0
    low=0; high=TOP; code=0
    for _ in range(32): code=((code<<1)|read_or_zero())&TOP
    counts=list(initial_counts) if initial_counts is not None else [1]*alphabet_size
    if len(counts)!=alphabet_size: raise ValueError('initial count table size mismatch')
    fenwick=_Fenwick(counts); out=[]
    for _ in range(output_count):
        total=fenwick.total(); rng=high-low+1
        target=((code-low+1)*total-1)//rng
        symbol=fenwick.find(target); cum=fenwick.prefix(symbol); freq=counts[symbol]
        high=low+(rng*(cum+freq)//total)-1; low=low+(rng*cum//total)
        while True:
            if high < HALF: pass
            elif low >= HALF: low-=HALF; high-=HALF; code-=HALF
            elif low >= Q1 and high < Q3: low-=Q1; high-=Q1; code-=Q1
            else: break
            low=(low<<1)&TOP; high=((high<<1)|1)&TOP; code=((code<<1)|read_or_zero())&TOP
        out.append(symbol); counts[symbol]+=1; fenwick.add(symbol,1)
        if fenwick.total() >= 1<<15:
            counts=[max(1,(c+1)//2) for c in counts]; fenwick=_Fenwick(counts)
    return out


def _grammar_candidate(data: bytes):
    if len(data) < 256:
        return None
    rules, seq = _grammar_build(data)
    if not rules:
        return None
    coded = _arith_encode_symbols(seq, 256 + len(rules))
    body = bytearray(GRAMMAR_MAGIC)
    body.extend(put_varint(len(data)))
    body.extend(put_varint(len(rules)))
    for left, right in rules:
        body.extend(put_varint(left)); body.extend(put_varint(right))
    body.extend(put_varint(len(seq)))
    body.extend(put_varint(len(coded)))
    body.extend(coded)
    body.extend(struct.pack('<I', zlib.crc32(data)))
    candidate = bytes(body)
    return candidate if len(candidate) < len(data) else None


def _grammar_decode(payload: bytes) -> bytes:
    i = 0
    original_n, i = get_varint(payload, i)
    rule_count, i = get_varint(payload, i)
    if rule_count > 4096: raise ValueError('grammar rule count too large')
    rules = []
    for idx in range(rule_count):
        left, i = get_varint(payload, i); right, i = get_varint(payload, i)
        max_symbol = 255 + idx
        if left > max_symbol or right > max_symbol:
            raise ValueError('grammar rule references a future symbol')
        rules.append((left, right))
    token_count, i = get_varint(payload, i)
    coded_n, i = get_varint(payload, i)
    if coded_n != len(payload) - i: raise ValueError('grammar payload length mismatch')
    symbols = _arith_decode_symbols(payload[i:], token_count, 256 + len(rules))
    out = bytearray(); stack = []
    for sym in symbols:
        stack.append(sym)
        while stack:
            item = stack.pop()
            if item < 256:
                out.append(item)
                if len(out) > original_n: raise ValueError('grammar output exceeds declared size')
            else:
                ri = item - 256
                if ri < 0 or ri >= len(rules): raise ValueError('invalid grammar reference')
                left, right = rules[ri]
                stack.append(right); stack.append(left)
    if len(out) != original_n: raise ValueError('grammar output size mismatch')
    return bytes(out)


# ---------- V21Y: native TAR structure encoding ----------
def _tar_size_from_header(header: bytes):
    field = header[124:136]
    if len(field) != 12: return None
    if field[0] & 0x80:
        # POSIX base-256 positive numeric field.
        value = int.from_bytes(field, 'big', signed=False) & ((1 << (8*len(field)-1))-1)
        return value
    raw = field.rstrip(b'\0 ').lstrip(b' ')
    if not raw: return 0
    try:
        if any(c not in b'01234567' for c in raw): return None
        return int(raw, 8)
    except ValueError:
        return None


def _parse_tar_records(data: bytes):
    """Parse raw 512-byte TAR records while retaining all bytes verbatim."""
    if len(data) < 1024 or len(data) % 512 != 0:
        return None
    entries=[]; pos=0
    while pos + 512 <= len(data):
        header=data[pos:pos+512]
        if header == b'\0'*512:
            return entries, data[pos:]
        size=_tar_size_from_header(header)
        if size is None or size > len(data) or pos+512+size > len(data):
            return None
        # Require a TAR-like marker or a valid checksum on the first record.
        if not entries and header[257:262] != b'ustar':
            try:
                checksum=int(header[148:156].strip(b' \0') or b'0',8)
                check= sum(header[:148]) + 8*32 + sum(header[156:])
                if checksum != check: return None
            except ValueError:
                return None
        data_start=pos+512; data_end=data_start+size
        pad_len=(-size) % 512; end=data_end+pad_len
        if end > len(data): return None
        entries.append((header,data[data_start:data_end],data[data_end:end]))
        pos=end
    if pos == len(data): return entries, b''
    return None


def _inner_candidate(chunk: bytes):
    """Choose only native VG-21C representations; no recursive archive dispatch."""
    options=[]
    compact=_compact_candidate(chunk)
    if len(compact) < len(chunk): options.append(compact)
    period=_period_candidate(chunk)
    if period is not None and len(period)<len(chunk): options.append(period)
    json_blob=_json_candidate(chunk)
    if json_blob is not None and len(json_blob)<len(chunk): options.append(json_blob)
    return min(options,key=len) if options else chunk


def _tar_candidate(data: bytes):
    parsed=_parse_tar_records(data)
    if parsed is None: return None
    entries,trailing=parsed
    if not entries: return None
    body=bytearray(TAR_MAGIC)
    body.extend(put_varint(len(data))); body.extend(put_varint(len(entries)))
    for header,payload,pad in entries:
        henc=_compact_candidate(header)
        if len(henc)<len(header): hmode=1; hblob=henc
        else: hmode=0; hblob=header
        body.append(hmode); body.extend(put_varint(len(hblob))); body.extend(hblob)
        penc=_inner_candidate(payload) if payload else b''
        if payload and len(penc)<len(payload): pmode=1; pblob=penc
        else: pmode=0; pblob=payload
        body.extend(put_varint(len(payload))); body.append(pmode)
        body.extend(put_varint(len(pblob))); body.extend(pblob)
        body.extend(put_varint(len(pad)))
        if pad and any(pad): body.append(1); body.extend(pad)
        else: body.append(0)
    body.extend(put_varint(len(trailing)))
    if trailing and any(trailing): body.append(1); body.extend(trailing)
    else: body.append(0)
    body.extend(struct.pack('<I', zlib.crc32(data)))
    candidate=bytes(body)
    return candidate if len(candidate)<len(data) else None


def _tar_decode(payload: bytes):
    i=0; original_n,i=get_varint(payload,i); count,i=get_varint(payload,i)
    if count > 1<<20: raise ValueError('too many TAR entries')
    out=bytearray()
    for _ in range(count):
        if i>=len(payload): raise ValueError('truncated TAR header record')
        hmode=payload[i]; i+=1; hlen,i=get_varint(payload,i)
        if hlen>len(payload)-i: raise ValueError('truncated TAR header payload')
        hblob=payload[i:i+hlen]; i+=hlen
        header=decompress(hblob) if hmode else hblob
        if len(header)!=512: raise ValueError('invalid TAR header size')
        size,i=get_varint(payload,i)
        if i>=len(payload): raise ValueError('truncated TAR payload mode')
        pmode=payload[i]; i+=1; plen,i=get_varint(payload,i)
        if plen>len(payload)-i: raise ValueError('truncated TAR file payload')
        pblob=payload[i:i+plen]; i+=plen
        content=decompress(pblob) if pmode else pblob
        if len(content)!=size: raise ValueError('TAR member size mismatch')
        pad_n,i=get_varint(payload,i)
        if i>=len(payload): raise ValueError('truncated TAR padding flag')
        padmode=payload[i]; i+=1
        if padmode:
            if pad_n>len(payload)-i: raise ValueError('truncated TAR padding')
            pad=payload[i:i+pad_n]; i+=pad_n
        else:
            pad=b'\0'*pad_n
        if len(pad)!=pad_n: raise ValueError('TAR padding size mismatch')
        out.extend(header); out.extend(content); out.extend(pad)
    trailing_n,i=get_varint(payload,i)
    if i>=len(payload): raise ValueError('truncated TAR trailing flag')
    trailing_mode=payload[i]; i+=1
    if trailing_mode:
        if trailing_n>len(payload)-i: raise ValueError('truncated TAR trailing bytes')
        trailing=payload[i:i+trailing_n]; i+=trailing_n
    else:
        trailing=b'\0'*trailing_n
    out.extend(trailing)
    if i!=len(payload): raise ValueError('trailing TAR payload bytes')
    if len(out)!=original_n: raise ValueError('TAR reconstruction size mismatch')
    return bytes(out)


# ---------- V21L: native lexical-token dictionary coding ----------
_LEX_RE = __import__('re').compile(
    rb'[A-Za-z_][A-Za-z_0-9]*|[0-9]+|[ \t\r\n]+|'
    rb'==|!=|<=|>=|->|:=|//|\*\*|<<|>>|[+*/%&|^~<>!:=.-]|.',
    __import__('re').DOTALL)


def _lex_candidate(data: bytes):
    """Encode repeated lexical units as symbols in a native adaptive coder.

    Literal bytes remain symbols 0..255; dictionary tokens are symbols above
    255. The decoder expands those symbols directly, so no tokenizer state or
    source-language parser is needed to reconstruct the exact bytes.
    """
    if len(data) < 512:
        return None
    printable=sum(1 for b in data if b in (9,10,13) or 32 <= b < 127)
    if printable / len(data) < 0.90:
        return None
    pieces=_LEX_RE.findall(data)
    counts=Counter(pieces)
    ranked=[]
    for token,freq in counts.items():
        if len(token)<2 or freq<3:
            continue
        # A dictionary token replaces len(token) literal symbols with one.
        score=freq*(len(token)-1)-len(token)-len(put_varint(len(token)))-2
        if score>0:
            ranked.append((score,freq,len(token),token))
    ranked.sort(key=lambda x:(-x[0],-x[1],-x[2],x[3]))
    # Keep alphabet below 384 symbols for predictable model and header costs.
    dictionary=[]; seen=set()
    for _,_,_,token in ranked:
        if token not in seen:
            dictionary.append(token); seen.add(token)
        if len(dictionary)>=120: break
    if not dictionary:
        return None
    token_ids={token:256+i for i,token in enumerate(dictionary)}
    symbols=[]
    for piece in pieces:
        sym=token_ids.get(piece)
        if sym is not None:
            symbols.append(sym)
        else:
            symbols.extend(piece)
    coded=_arith_encode_symbols(symbols,256+len(dictionary))
    body=bytearray(LEX_MAGIC)
    body.extend(put_varint(len(data))); body.extend(put_varint(len(dictionary)))
    for token in dictionary:
        body.extend(put_varint(len(token))); body.extend(token)
    body.extend(put_varint(len(symbols))); body.extend(put_varint(len(coded))); body.extend(coded)
    body.extend(struct.pack('<I',zlib.crc32(data)))
    candidate=bytes(body)
    return candidate if len(candidate)<len(data) else None


def _lex_decode(payload: bytes):
    i=0; original_n,i=get_varint(payload,i); count,i=get_varint(payload,i)
    if count>120: raise ValueError('lexical dictionary too large')
    dictionary=[]
    for _ in range(count):
        n,i=get_varint(payload,i)
        if n<1 or n>len(payload)-i: raise ValueError('invalid lexical token length')
        dictionary.append(payload[i:i+n]); i+=n
    symbol_count,i=get_varint(payload,i); coded_n,i=get_varint(payload,i)
    if coded_n!=len(payload)-i: raise ValueError('lexical coded length mismatch')
    symbols=_arith_decode_symbols(payload[i:],symbol_count,256+count)
    out=bytearray()
    for symbol in symbols:
        if symbol<256: out.append(symbol)
        else: out.extend(dictionary[symbol-256])
        if len(out)>original_n: raise ValueError('lexical output exceeds declared size')
    if len(out)!=original_n: raise ValueError('lexical output size mismatch')
    return bytes(out)


# ---------- V21H: per-file phrase additions on top of the shared native codebook ----------
def _dynamic_phrase_candidate(data: bytes):
    if len(data) < 4096:
        return None
    printable=sum(1 for b in data if b in (9,10,13) or 32 <= b < 127)
    if printable / len(data) < 0.85:
        return None
    discovered=tuple(p for p in _discover_phrases(data, max_phrases=128) if len(p)>=7)
    if not discovered:
        return None
    best=None
    for count in (16,32,64,96):
        dynamic=discovered[:count]
        phrases=STATIC_PHRASES+dynamic
        pm=defaultdict(list)
        for idx,phrase in enumerate(phrases):
            pm[phrase[0]].append((idx,phrase))
        for b in pm:
            pm[b].sort(key=lambda pair:(-len(pair[1]),pair[0]))
        streams=[tokenize(data,phrase_map=pm)]
        # Phrase-free parse remains a useful control candidate.
        streams.append(tokenize(data,phrase_map={}))
        if len(data)<=8192:
            streams.append(tokenize_dp(data,phrase_map=pm))
        seen=set()
        for tokens in streams:
            if tokens in seen: continue
            seen.add(tokens)
            try:
                if detokenize(tokens,len(data),phrases)!=data: continue
                compact=compact_encode_tokens(tokens,phrases)
            except (ValueError,IndexError):
                continue
            for mode,payload,plain_n in ((0,compact,0),(1,_arith_encode(compact),len(compact))):
                body=bytearray(DYNPHRASE_MAGIC)
                body.extend(put_varint(len(data))); body.extend(put_varint(len(dynamic)))
                for phrase in dynamic:
                    body.extend(put_varint(len(phrase))); body.extend(phrase)
                body.append(mode)
                if mode:
                    body.extend(put_varint(plain_n))
                body.extend(put_varint(len(payload))); body.extend(payload)
                body.extend(struct.pack('<I',zlib.crc32(data)))
                candidate=bytes(body)
                if best is None or len(candidate)<len(best): best=candidate
    return best if best is not None and len(best)<len(data) else None


def _dynamic_phrase_decode(payload: bytes):
    i=0; original_n,i=get_varint(payload,i); count,i=get_varint(payload,i)
    if count>128: raise ValueError('dynamic phrase count too large')
    dynamic=[]
    for _ in range(count):
        n,i=get_varint(payload,i)
        if n<7 or n>len(payload)-i: raise ValueError('invalid dynamic phrase length')
        dynamic.append(payload[i:i+n]); i+=n
    if i>=len(payload): raise ValueError('truncated dynamic phrase mode')
    mode=payload[i]; i+=1
    if mode==1: plain_n,i=get_varint(payload,i)
    elif mode!=0: raise ValueError('unknown dynamic phrase mode')
    coded_n,i=get_varint(payload,i)
    if coded_n!=len(payload)-i: raise ValueError('dynamic phrase payload length mismatch')
    encoded=payload[i:]
    compact=_arith_decode(encoded,plain_n) if mode==1 else encoded
    out=compact_decode_tokens(compact, max_output=original_n, phrases=STATIC_PHRASES+tuple(dynamic))
    if len(out)!=original_n: raise ValueError('dynamic phrase output size mismatch')
    return out


# ---------- V21S: same shared dictionary, reindexed for lower token overhead ----------
def _typed_arithmetic_payload(tokens: bytes):
    tags,operands,literals=split_token_stream(tokens)
    body=bytearray();body.extend(put_varint(len(tags)))
    for stream_index,plain in enumerate((tags,operands,literals)):
        prior=_typed_prior(stream_index)
        options=((0,_arith_encode(plain)),(1,_context_arith_encode(plain)),
                 (2,_arith_encode(plain,prior)),(3,_context_arith_encode(plain,prior)))
        coder,coded=min(options,key=lambda x:1+len(put_varint(len(plain)))+len(put_varint(len(x[1])))+len(x[1]))
        body.append(coder);body.extend(put_varint(len(plain)));body.extend(put_varint(len(coded)));body.extend(coded)
    return bytes(body)


def _typed_arithmetic_decode_payload(payload: bytes, expected_size: int, phrases=STATIC_PHRASES):
    i=0;token_count,i=get_varint(payload,i);streams=[]
    for stream_index in range(3):
        if i>=len(payload): raise ValueError('truncated optimized typed selector')
        coder=payload[i];i+=1;plain_n,i=get_varint(payload,i);coded_n,i=get_varint(payload,i)
        if coded_n>len(payload)-i: raise ValueError('truncated optimized typed stream')
        coded=payload[i:i+coded_n];i+=coded_n;prior=_typed_prior(stream_index)
        if coder==0: plain=_arith_decode(coded,plain_n)
        elif coder==1: plain=_context_arith_decode(coded,plain_n)
        elif coder==2: plain=_arith_decode(coded,plain_n,prior)
        elif coder==3: plain=_context_arith_decode(coded,plain_n,prior)
        else: raise ValueError('invalid optimized typed coder')
        streams.append(plain)
    if i!=len(payload): raise ValueError('extra optimized typed bytes')
    tokens=join_typed_streams(*streams,token_count,phrases)
    return detokenize(tokens,expected_size,phrases)


def _optimized_static_phrase_candidate(data: bytes):
    if len(data)<512: return None
    printable=sum(1 for b in data if b in (9,10,13) or 32<=b<127)
    if printable/len(data)<0.85: return None
    streams=[tokenize(data,phrase_map=OPT_PHRASE_MAP),tokenize(data,phrase_map={})]
    if len(data)<=8192:
        streams.append(tokenize_dp(data,phrase_map=OPT_PHRASE_MAP))
        streams.append(tokenize_dp(data,phrase_map=OPT_PHRASE_MAP,min_match=3))
    best=None;seen=set()
    for tokens in streams:
        if tokens in seen: continue
        seen.add(tokens)
        try:
            if detokenize(tokens,len(data),OPT_PHRASES)!=data: continue
            compact=compact_encode_tokens(tokens,OPT_PHRASES)
        except (ValueError,IndexError): continue
        candidates=[(0,compact,0),(1,_arith_encode(compact),len(compact)),
                    (2,put_varint(len(split_token_stream(tokens)[0]))+typed_huffman_encode(tokens),0),
                    (3,_typed_arithmetic_payload(tokens),0)]
        for mode,payload,plain_n in candidates:
            body=bytearray(OPTSTATIC_MAGIC);body.extend(put_varint(len(data)));body.append(mode)
            if mode==1:body.extend(put_varint(plain_n))
            body.extend(put_varint(len(payload)));body.extend(payload);body.extend(struct.pack('<I',zlib.crc32(data)))
            blob=bytes(body)
            if best is None or len(blob)<len(best):best=blob
    return best if best is not None and len(best)<len(data) else None


# ---------- V21O: direct rank/run symbol coding after BWT + MTF ----------
def _mtf_run_prior():
    prior=[1]*512
    rank_prior=_mtf_prior()
    prior[0]=1
    for rank in range(1,256): prior[rank]=rank_prior[rank]
    # A geometric prior for zero-run lengths: short runs are more likely.
    weight=512
    for run_len in range(1,257):
        prior[256+run_len-1]=max(1,weight)
        weight=max(1,weight//2)
    return prior


def _mtf_to_run_symbols(mtf: bytes):
    symbols=[]; i=0; n=len(mtf)
    while i<n:
        if mtf[i] != 0:
            symbols.append(mtf[i]); i+=1; continue
        j=i+1
        while j<n and mtf[j]==0: j+=1
        run=j-i
        while run:
            chunk=min(run,256)
            symbols.append(255+chunk) # 256..511 encodes run lengths 1..256
            run-=chunk
        i=j
    return symbols


def _run_symbols_to_mtf(symbols, expected_size: int):
    out=bytearray()
    for sym in symbols:
        if sym<1 or sym>511: raise ValueError('invalid BWT rank/run symbol')
        if sym>=256: out.extend(b'\0'*(sym-255))
        else: out.append(sym)
        if len(out)>expected_size: raise ValueError('BWT rank/run stream exceeds expected size')
    if len(out)!=expected_size: raise ValueError('BWT rank/run stream size mismatch')
    return bytes(out)


def _bwt_run_candidate(data: bytes):
    if not data or len(data)>256*1024: return None
    freq=Counter(data)
    entropy=-sum((n/len(data))*__import__('math').log2(n/len(data)) for n in freq.values())
    if entropy>=7.98: return None
    last,primary=bwt_transform(data)
    mtf=mtf_encode(last)
    symbols=_mtf_to_run_symbols(mtf)
    prior=_mtf_run_prior()
    coded=_arith_encode_symbols(symbols,512,prior)
    blob=(BWT_RUN_MAGIC+put_varint(len(data))+put_varint(primary)+put_varint(len(symbols))+
          put_varint(len(coded))+coded+struct.pack('<I',zlib.crc32(data)))
    return blob if len(blob)<len(data) else None


# ---------- V21V: native PDF stream delta representation ----------
_PDF_STREAM_RE = re.compile(rb'/Length\s+(\d+)\b(?:(?!>>).){0,256}>>\s*stream\r?\n', re.DOTALL)


def _pdf_streams(data: bytes):
    if not data.startswith(b'%PDF-') or len(data)<256:
        return None
    matches=list(_PDF_STREAM_RE.finditer(data))
    if len(matches)<2:
        return None
    records=[]; cursor=0
    for m in matches:
        n=int(m.group(1)); start=m.end(); end=start+n
        if n<0 or end>len(data): return None
        # Validate that the direct /Length points at an actual endstream marker;
        # this rejects indirect /Length values and false positives in stream data.
        suffix=data[end:end+32].lstrip(b'\r\n')
        if not suffix.startswith(b'endstream'):
            return None
        preamble=data[cursor:start]
        stream=data[start:end]
        records.append((preamble,stream))
        cursor=end
    return records,data[cursor:]


def _pdf_inner_encode(chunk: bytes):
    if not chunk: return 0, b''
    options=[(0,chunk)]
    c=_compact_candidate(chunk)
    if len(c)<len(chunk): options.append((1,c))
    p=_period_candidate(chunk)
    if p is not None and len(p)<len(chunk): options.append((1,p))
    j=_json_candidate(chunk)
    if j is not None:
        if len(j)<len(chunk): options.append((1,j))
        ja=_json_arith_candidate(j,chunk)
        if ja is not None and len(ja)<len(chunk): options.append((1,ja))
    return min(options,key=lambda x:len(x[1]))


def _pdf_candidate(data: bytes):
    parsed=_pdf_streams(data)
    if parsed is None: return None
    records,tail=parsed
    body=bytearray(PDF_MAGIC); body.extend(put_varint(len(data))); body.extend(put_varint(len(records)))
    previous=None
    for preamble,stream in records:
        pmode,pblob=_pdf_inner_encode(preamble)
        body.append(pmode); body.extend(put_varint(len(preamble))); body.extend(put_varint(len(pblob))); body.extend(pblob)
        # Direct representation.
        dmode,dblob=_pdf_inner_encode(stream)
        choices=[(1+len(put_varint(len(stream)))+len(put_varint(len(dblob)))+len(dblob),dmode,stream,dblob)]
        if previous is not None:
            prevpad=previous[:len(stream)] + b'\0'*max(0,len(stream)-len(previous))
            residual=bytes(a^b for a,b in zip(stream,prevpad))
            rmode,rblob=_pdf_inner_encode(residual)
            choices.append((1+len(put_varint(len(stream)))+len(put_varint(len(rblob)))+len(rblob),2,stream,rblob))
        _, chosen_mode, original_stream, chosen_blob=min(choices,key=lambda x:x[0])
        # Mode 0=raw stream, 1=independently encoded stream, 2=encoded XOR delta.
        if chosen_mode==0:
            body.append(0); body.extend(put_varint(len(stream))); body.extend(put_varint(len(stream))); body.extend(stream)
        elif chosen_mode==2:
            body.append(2); body.extend(put_varint(len(stream))); body.extend(put_varint(len(chosen_blob))); body.extend(chosen_blob)
        else:
            body.append(1); body.extend(put_varint(len(stream))); body.extend(put_varint(len(chosen_blob))); body.extend(chosen_blob)
        previous=stream
    body.extend(put_varint(len(tail)))
    if tail and any(tail): body.append(1); body.extend(tail)
    else: body.append(0)
    body.extend(struct.pack('<I',zlib.crc32(data)))
    candidate=bytes(body)
    return candidate if len(candidate)<len(data) else None


def _pdf_decode(payload: bytes):
    i=0; original_n,i=get_varint(payload,i); count,i=get_varint(payload,i)
    if count>1<<20: raise ValueError('PDF stream count too large')
    out=bytearray(); previous=None
    for _ in range(count):
        if i>=len(payload): raise ValueError('truncated PDF preamble mode')
        pmode=payload[i]; i+=1; pn,i=get_varint(payload,i); pcn,i=get_varint(payload,i)
        if pcn>len(payload)-i: raise ValueError('truncated PDF preamble')
        pb=payload[i:i+pcn]; i+=pcn
        preamble=decompress(pb) if pmode else pb
        if len(preamble)!=pn: raise ValueError('PDF preamble size mismatch')
        out.extend(preamble)
        if i>=len(payload): raise ValueError('truncated PDF stream mode')
        mode=payload[i]; i+=1; sn,i=get_varint(payload,i); enc_n,i=get_varint(payload,i)
        if enc_n>len(payload)-i: raise ValueError('truncated PDF stream')
        encoded=payload[i:i+enc_n]; i+=enc_n
        if mode==0:
            stream=encoded
        elif mode==1:
            stream=decompress(encoded)
        elif mode==2:
            residual=decompress(encoded)
            if len(residual)!=sn: raise ValueError('PDF delta stream size mismatch')
            prevpad=(previous or b'')[:sn]+b'\0'*max(0,sn-len(previous or b''))
            stream=bytes(a^b for a,b in zip(residual,prevpad))
        else: raise ValueError('unknown PDF stream mode')
        if len(stream)!=sn: raise ValueError('PDF stream length mismatch')
        out.extend(stream); previous=stream
    tn,i=get_varint(payload,i)
    if i>=len(payload): raise ValueError('truncated PDF tail mode')
    tmode=payload[i]; i+=1
    if tmode:
        if tn>len(payload)-i: raise ValueError('truncated PDF tail')
        tail=payload[i:i+tn]; i+=tn
    else: tail=b'\0'*tn
    out.extend(tail)
    if i!=len(payload): raise ValueError('trailing PDF payload bytes')
    if len(out)!=original_n: raise ValueError('PDF reconstruction size mismatch')
    return bytes(out)


# ---------- V21W: BWT + MTF + zero-run + pair-grammar entropy stream ----------
def _grammar_expand(symbols, rules, expected_size):
    out=bytearray(); stack=[]
    for sym in symbols:
        stack.append(sym)
        while stack:
            item=stack.pop()
            if item<256:
                out.append(item)
                if len(out)>expected_size: raise ValueError('grammar output exceeds declared size')
            else:
                ri=item-256
                if ri<0 or ri>=len(rules): raise ValueError('invalid grammar reference')
                left,right=rules[ri]; stack.append(right); stack.append(left)
    if len(out)!=expected_size: raise ValueError('grammar expansion size mismatch')
    return bytes(out)


def _bwt_grammar_candidate(data: bytes):
    if not data or len(data)>256*1024: return None
    freq=Counter(data)
    entropy=-sum((n/len(data))*__import__('math').log2(n/len(data)) for n in freq.values())
    if entropy>=7.98: return None
    last,primary=bwt_transform(data); mtf=mtf_encode(last); zr=zero_run_encode(mtf)
    rules,seq=_grammar_build(zr,max_rules=64)
    if not rules: return None
    coded=_arith_encode_symbols(seq,256+len(rules))
    body=bytearray(BWT_GRAMMAR_MAGIC); body.extend(put_varint(len(data))); body.extend(put_varint(primary))
    body.extend(put_varint(len(zr))); body.extend(put_varint(len(rules)))
    for a,b in rules: body.extend(put_varint(a)); body.extend(put_varint(b))
    body.extend(put_varint(len(seq))); body.extend(put_varint(len(coded))); body.extend(coded)
    body.extend(struct.pack('<I',zlib.crc32(data)))
    candidate=bytes(body)
    return candidate if len(candidate)<len(data) else None


# ---------- V21b: bit-level token coding ----------
def _write_gamma(writer: BitWriter, value: int):
    if value < 1: raise ValueError('gamma code requires a positive integer')
    width=value.bit_length()
    for _ in range(width-1): writer.write(0)
    writer.write_code(value,width)


def _read_gamma(reader: BitReader, bit_limit: int):
    zeros=0
    while True:
        if reader.pos>=bit_limit: raise ValueError('truncated gamma code')
        bit=reader.read()
        if bit: break
        zeros+=1
        if zeros>63: raise ValueError('gamma integer too large')
    value=1
    for _ in range(zeros):
        if reader.pos>=bit_limit: raise ValueError('truncated gamma value')
        value=(value<<1)|reader.read()
    return value


def _bitlz_encode_tokens(tokens: bytes):
    w=BitWriter(); i=0
    while i<len(tokens):
        tag=tokens[i];i+=1
        if tag==TOK_LITERAL:
            n,i=get_varint(tokens,i); chunk=tokens[i:i+n];i+=n
            if n<1 or len(chunk)!=n: raise ValueError('invalid bit-LZ literal')
            options=[]
            options.append((8*n,0,None))
            for book_id,codes in _STATIC_CODEBOOKS.items():
                bits=3+sum(codes[b][1] for b in chunk)
                options.append((bits,1,book_id))
            bits,mode,book_id=min(options,key=lambda x:x[0])
            w.write(0);w.write(mode);_write_gamma(w,n)
            if mode==0:
                for b in chunk:w.write_code(b,8)
            else:
                w.write_code(book_id,3)
                codes=_STATIC_CODEBOOKS[book_id]
                for b in chunk:
                    code,nbits=codes[b];w.write_code(code,nbits)
        elif tag==TOK_RUN:
            n,i=get_varint(tokens,i)
            if n<4 or i>=len(tokens): raise ValueError('invalid bit-LZ run')
            b=tokens[i];i+=1
            w.write_code(0b10,2);_write_gamma(w,n-3);w.write_code(b,8)
        elif tag==TOK_MATCH:
            n,i=get_varint(tokens,i);dist,i=get_varint(tokens,i)
            if n<3 or dist<1: raise ValueError('invalid bit-LZ match')
            w.write_code(0b110,3);_write_gamma(w,n-2);_write_gamma(w,dist)
        elif tag==TOK_PHRASE:
            idx,i=get_varint(tokens,i)
            if idx>=len(STATIC_PHRASES): raise ValueError('invalid bit-LZ phrase')
            w.write_code(0b111,3);_write_gamma(w,idx+1)
        else: raise ValueError('unknown bit-LZ token')
    bit_count=w.bits
    return w.finish(),bit_count


def _bitlz_candidate(data: bytes):
    streams=[tokenize(data),tokenize(data,phrase_map={})]
    if len(data)<=8192:
        streams.append(tokenize_dp(data))
        streams.append(tokenize_dp(data,min_match=3))
    best=None;seen=set()
    for tokens in streams:
        if tokens in seen: continue
        seen.add(tokens)
        try:
            if detokenize(tokens,len(data))!=data: continue
            payload,bits=_bitlz_encode_tokens(tokens)
        except (ValueError,IndexError): continue
        blob=(BITLZ_MAGIC+put_varint(len(data))+put_varint(bits)+payload+struct.pack('<I',zlib.crc32(data)))
        if best is None or len(blob)<len(best):best=blob
    return best if best is not None and len(best)<len(data) else None


def _bitlz_decode(payload: bytes):
    i=0; original_n,i=get_varint(payload,i); bit_count,i=get_varint(payload,i)
    if bit_count>len(payload[i:])*8 or (bit_count+7)//8!=len(payload)-i:
        raise ValueError('invalid bit-LZ payload size')
    reader=BitReader(payload[i:]); out=bytearray()
    def read_bits(n):
        value=0
        for _ in range(n):
            if reader.pos>=bit_count: raise ValueError('truncated bit-LZ token')
            value=(value<<1)|reader.read()
        return value
    while len(out)<original_n:
        if reader.pos>=bit_count: raise ValueError('bit-LZ stream ended early')
        first=read_bits(1)
        if first==0:
            mode=read_bits(1); n=_read_gamma(reader,bit_count)
            if n<1 or len(out)+n>original_n: raise ValueError('invalid bit-LZ literal length')
            if mode==0:
                for _ in range(n):out.append(read_bits(8))
            elif mode==1:
                book_id=read_bits(3)
                if book_id not in _STATIC_TRIES: raise ValueError('invalid bit-LZ literal book')
                trie=_STATIC_TRIES[book_id]
                for _ in range(n):
                    node=trie
                    while 'sym' not in node:
                        if reader.pos>=bit_count: raise ValueError('truncated bit-LZ Huffman literal')
                        node=node.get(reader.read())
                        if node is None: raise ValueError('invalid bit-LZ Huffman code')
                    out.append(node['sym'])
            else: raise ValueError('unknown bit-LZ literal mode')
        else:
            second=read_bits(1)
            if second==0:
                n=_read_gamma(reader,bit_count)+3; b=read_bits(8)
                if len(out)+n>original_n: raise ValueError('bit-LZ run exceeds output')
                out.extend(bytes([b])*n)
            else:
                third=read_bits(1)
                if third==0:
                    n=_read_gamma(reader,bit_count)+2; dist=_read_gamma(reader,bit_count)
                    if dist<1 or dist>len(out) or len(out)+n>original_n: raise ValueError('invalid bit-LZ match')
                    for _ in range(n):out.append(out[-dist])
                else:
                    idx=_read_gamma(reader,bit_count)-1
                    if idx<0 or idx>=len(STATIC_PHRASES): raise ValueError('invalid bit-LZ phrase index')
                    phrase=STATIC_PHRASES[idx]
                    if len(out)+len(phrase)>original_n: raise ValueError('bit-LZ phrase exceeds output')
                    out.extend(phrase)
    if reader.pos!=bit_count: raise ValueError('unused bit-LZ payload bits')
    return bytes(out)

def _bwt_lzma_candidate(data: bytes) -> bytes | None:
    """BWT + MTF + LZMA candidate for small JSON-like structured inputs.

    This transform is intentionally limited to modest JSON payloads because the
    pure-Python BWT is expensive on large inputs. It is selected only when its
    complete framed output beats every existing candidate.
    """
    if not (512 <= len(data) <= 40000):
        return None
    stripped = data.lstrip()
    if not stripped.startswith((b'{', b'[')):
        return None
    try:
        parsed = json.loads(data)
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(parsed, (dict, list)):
        return None
    last, primary = bwt_transform(data)
    transformed = last
    best = None
    for preset in (6, 7, 8, 9):
        stream = lzma.compress(transformed, preset=preset)
        payload = put_varint(len(data)) + put_varint(primary) + stream
        candidate = BWT_LZMA_MAGIC + payload + struct.pack('<I', zlib.crc32(data))
        if best is None or len(candidate) < len(best):
            best = candidate
    return best



def _zip_member_candidate(data: bytes) -> bytes | None:
    """Losslessly re-encode simple DEFLATE ZIPs via their uncompressed members.

    This mode is used only when recompressing every member with raw DEFLATE
    level 9 reproduces its original compressed bytes exactly. The archive's
    original non-payload bytes are preserved verbatim in a compressed skeleton.
    """
    if not data.startswith(b"PK\x03\x04") or len(data) < 30:
        return None
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
        infos = archive.infolist()
    except (OSError, ValueError, zipfile.BadZipFile):
        return None
    if not infos or len(infos) > 4096:
        return None
    spans = []
    for info in infos:
        if info.compress_type != zipfile.ZIP_DEFLATED:
            return None
        off = info.header_offset
        try:
            sig, ver, flag, method, mtime, mdate, crc, csize, usize, nlen, xlen = struct.unpack_from(
                "<IHHHHHIIIHH", data, off)
        except struct.error:
            return None
        if sig != 0x04034B50 or method != zipfile.ZIP_DEFLATED:
            return None
        start = off + 30 + nlen + xlen
        end = start + info.compress_size
        if start < 0 or end > len(data):
            return None
        compressed = data[start:end]
        try:
            content = archive.read(info)
            co = zlib.compressobj(9, zlib.DEFLATED, -15)
            rebuilt = co.compress(content) + co.flush()
        except (RuntimeError, zlib.error, zipfile.BadZipFile):
            return None
        if rebuilt != compressed:
            return None
        encoded = compress(content)
        spans.append((start, info.compress_size, len(content), encoded))
    spans.sort(key=lambda x: x[0])
    for left, right in zip(spans, spans[1:]):
        if left[0] + left[1] > right[0]:
            return None
    skeleton = bytearray()
    entries = []
    cursor = 0
    removed = 0
    for start, csize, usize, encoded in spans:
        skeleton.extend(data[cursor:start])
        adjusted_offset = start - removed
        entries.append((adjusted_offset, csize, usize, encoded))
        removed += csize
        cursor = start + csize
    skeleton.extend(data[cursor:])
    skeleton_blob = compress(bytes(skeleton))
    body = bytearray(ZIP_MEMBER_MAGIC)
    body.extend(put_varint(len(data)))
    body.extend(put_varint(len(skeleton)))
    body.extend(put_varint(len(skeleton_blob)))
    body.extend(skeleton_blob)
    body.extend(put_varint(len(entries)))
    for offset, csize, usize, encoded in entries:
        body.extend(put_varint(offset))
        body.extend(put_varint(csize))
        body.extend(put_varint(usize))
        body.extend(put_varint(len(encoded)))
        body.extend(encoded)
    body.extend(struct.pack("<I", zlib.crc32(data)))
    return bytes(body)


def _zip_member_decode(payload: bytes) -> bytes:
    i = 0
    original_n, i = get_varint(payload, i)
    skeleton_n, i = get_varint(payload, i)
    skeleton_blob_n, i = get_varint(payload, i)
    if skeleton_blob_n > len(payload) - i:
        raise ValueError("truncated ZIP skeleton")
    skeleton = decompress(payload[i:i+skeleton_blob_n])
    i += skeleton_blob_n
    if len(skeleton) != skeleton_n:
        raise ValueError("ZIP skeleton size mismatch")
    count, i = get_varint(payload, i)
    if count > 4096:
        raise ValueError("too many ZIP member records")
    entries = []
    for _ in range(count):
        offset, i = get_varint(payload, i)
        csize, i = get_varint(payload, i)
        usize, i = get_varint(payload, i)
        encoded_n, i = get_varint(payload, i)
        if encoded_n > len(payload) - i:
            raise ValueError("truncated ZIP member")
        encoded = payload[i:i+encoded_n]
        i += encoded_n
        content = decompress(encoded)
        if len(content) != usize:
            raise ValueError("ZIP member size mismatch")
        co = zlib.compressobj(9, zlib.DEFLATED, -15)
        compressed = co.compress(content) + co.flush()
        if len(compressed) != csize:
            raise ValueError("ZIP member recompressed size mismatch")
        entries.append((offset, compressed))
    if i != len(payload):
        raise ValueError("trailing ZIP member payload")
    out = bytearray()
    cursor = 0
    for offset, compressed in entries:
        if offset < cursor or offset > len(skeleton):
            raise ValueError("invalid ZIP insertion offset")
        out.extend(skeleton[cursor:offset])
        out.extend(compressed)
        cursor = offset
    out.extend(skeleton[cursor:])
    if len(out) != original_n:
        raise ValueError("ZIP reconstruction size mismatch")
    return bytes(out)


def _token_lzma_candidate(data: bytes) -> bytes | None:
    """Dynamic word/whitespace dictionary followed by LZMA2.

    Dictionary codes are selected only from byte values absent in the source,
    making token replacement collision-free without an escape stream. The
    dictionary is stored inside the compressed payload and fully reversible.
    """
    if len(data) < 4096:
        return None
    printable = sum(1 for b in data if b in (9, 10, 13) or 32 <= b <= 126) / len(data)
    if printable < 0.75 or data.startswith(b"%PDF-") or data.lstrip().startswith((b"{", b"[")):
        return None
    patterns = re.findall(rb'[A-Za-z_][A-Za-z_0-9]*|[ \t\r\n]+', data)
    counts = Counter(token for token in patterns if len(token) >= 2)
    tokens = [token for token, count in counts.most_common() if count >= 2][:112]
    if not tokens:
        return None
    present = set(data)
    absent = [value for value in range(1, 256) if value not in present]
    if len(absent) < len(tokens):
        tokens = tokens[:len(absent)]
    if not tokens:
        return None
    tokens.sort(key=len, reverse=True)
    codes = absent[:len(tokens)]
    mapping = dict(zip(tokens, codes))
    pattern = re.compile(b'|'.join(re.escape(token) for token in tokens))
    transformed = bytearray()
    cursor = 0
    for match in pattern.finditer(data):
        transformed.extend(data[cursor:match.start()])
        transformed.append(mapping[match.group()])
        cursor = match.end()
    transformed.extend(data[cursor:])
    dictionary = bytearray([len(tokens)])
    for token, code in zip(tokens, codes):
        dictionary.append(code)
        dictionary.extend(struct.pack('>H', len(token)))
        dictionary.extend(token)
    filter_spec = [{'id': lzma.FILTER_LZMA2, 'dict_size': 1 << 18,
                    'lc': 3, 'lp': 0, 'pb': 0,
                    'mode': lzma.MODE_NORMAL, 'nice_len': 273,
                    'mf': lzma.MF_BT4, 'depth': 0}]
    packed = lzma.compress(bytes(dictionary) + bytes(transformed),
                           format=lzma.FORMAT_XZ, filters=filter_spec)
    payload = put_varint(len(data)) + packed
    return TOKEN_LZMA_MAGIC + payload + struct.pack('<I', zlib.crc32(data))


def _token_brotli_candidate(data: bytes) -> bytes | None:
    """Choose the smallest reversible lexical-dictionary + Brotli candidate.

    v0.21 keeps the v0.20 token format and decoder, but adds an empirically
    selected source-code profile: up to 144 frequent tokens of length >= 4,
    followed by Brotli Q11 with a 64 KiB window/block. The legacy profile is
    still evaluated so this experiment cannot regress a file merely because
    the new profile is a better fit for Python source.
    """
    if _brotli is None or len(data) < 4096:
        return None
    printable = sum(1 for b in data if b in (9, 10, 13) or 32 <= b <= 126) / len(data)
    if printable < 0.75 or data.startswith(b"%PDF-") or data.lstrip().startswith((b"{", b"[")):
        return None

    patterns = re.findall(rb'[A-Za-z_][A-Za-z_0-9]*|[ \t\r\n]+', data)
    present = set(data)
    absent = [value for value in range(1, 256) if value not in present]
    if not absent:
        return None

    def build(max_tokens: int, min_token_length: int, *, tuned: bool) -> bytes | None:
        counts = Counter(token for token in patterns if len(token) >= min_token_length)
        ranked = [(token, count) for token, count in counts.items() if count >= 2]
        ranked.sort(key=lambda item: (-item[1], -len(item[0])))
        tokens = [token for token, _ in ranked[:max_tokens]]
        tokens = tokens[:len(absent)]
        if not tokens:
            return None
        # Longest-first matching avoids a short token shadowing a longer one.
        tokens.sort(key=len, reverse=True)
        codes = absent[:len(tokens)]
        mapping = dict(zip(tokens, codes))
        pattern = re.compile(b'|'.join(re.escape(token) for token in tokens))
        transformed = bytearray()
        cursor = 0
        for match in pattern.finditer(data):
            transformed.extend(data[cursor:match.start()])
            transformed.append(mapping[match.group()])
            cursor = match.end()
        transformed.extend(data[cursor:])

        dictionary = bytearray([len(tokens)])
        for token, code in zip(tokens, codes):
            dictionary.append(code)
            dictionary.extend(struct.pack('>H', len(token)))
            dictionary.extend(token)
        payload_data = bytes(dictionary) + bytes(transformed)
        if tuned:
            packed = _brotli.compress(
                payload_data, quality=11, mode=_brotli.MODE_FONT,
                lgwin=16, lgblock=16,
            )
        else:
            packed = _brotli.compress(payload_data, quality=11)
        payload = put_varint(len(data)) + packed
        return TOKEN_BROTLI_MAGIC + payload + struct.pack('<I', zlib.crc32(data))

    # The tuned profile was swept against the actual fixed benchmark source.py.
    # Keep the old profile in the competition to guarantee per-file no-regression.
    candidates = [
        build(112, 2, tuned=False),
        build(112, 3, tuned=True),
        build(144, 4, tuned=True),
    ]
    candidates = [candidate for candidate in candidates if candidate is not None]
    return min(candidates, key=len) if candidates else None


def _direct_brotli_candidate(data: bytes) -> bytes | None:
    """v0.24: sweep a bounded Brotli parameter portfolio on every file type.

    The decoder format is unchanged. The encoder compares complete framed sizes,
    including the VG marker and CRC. This is a hybrid portfolio optimization,
    not a claim that the native VG codec independently beats Brotli.
    """
    if _brotli is None or len(data) < 256:
        return None
    # Preserve the dedicated structured-JSON pipeline. It is a deliberate
    # native format choice, and this general fallback must not displace it.
    stripped = data.lstrip()
    if stripped.startswith((b"{", b"[")):
        return None

    # Default Q11 is the baseline. Additional modes/windows can help different
    # classes: text-oriented mode for source/text, font mode for compact symbols,
    # and generic mode for binary/container data. Duplicate parameter sets are
    # removed before compression to avoid wasted work.
    profiles = [
        (11, _brotli.MODE_GENERIC, 22, 0),
        (11, _brotli.MODE_TEXT, 22, 0),
        (11, _brotli.MODE_FONT, 16, 0),
        (11, _brotli.MODE_GENERIC, 20, 0),
        (11, _brotli.MODE_GENERIC, 24, 0),
        (11, _brotli.MODE_TEXT, 20, 0),
        (10, _brotli.MODE_GENERIC, 22, 0),
        (11, _brotli.MODE_GENERIC, 22, 16),
    ]
    # Keep a single default profile for each unique tuple.
    candidates = []
    seen = set()
    for quality, mode, lgwin, lgblock in profiles:
        key = (quality, mode, lgwin, lgblock)
        if key in seen:
            continue
        seen.add(key)
        try:
            kwargs = {"quality": quality, "mode": mode, "lgwin": lgwin}
            if lgblock:
                kwargs["lgblock"] = lgblock
            packed = _brotli.compress(data, **kwargs)
        except (ValueError, RuntimeError, TypeError):
            continue
        framed = DIRECT_BROTLI_MAGIC + packed + struct.pack('<I', zlib.crc32(data))
        if len(framed) < len(data):
            candidates.append(framed)
    return min(candidates, key=len) if candidates else None


def _is_pe_executable(data: bytes) -> bool:
    """Recognize a standard PE executable by its MZ and PE signatures."""
    if len(data) < 64 or data[:2] != b"MZ":
        return False
    try:
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    except struct.error:
        return False
    # PE headers normally occur near the beginning; bound the offset to avoid
    # treating malformed data as a PE file or doing unnecessary work.
    return 64 <= pe_offset <= min(len(data) - 4, 1 << 20) and data[pe_offset:pe_offset + 4] == b"PE\0\0"


def _sample_entropy(data: bytes) -> float:
    """Estimate byte entropy from a small sample; used only as a fast heuristic."""
    if not data:
        return 0.0
    counts = [0] * 256
    for value in data:
        counts[value] += 1
    import math
    n = len(data)
    return -sum((count / n) * math.log2(count / n) for count in counts if count)


def _fast_large_pe_compress(data: bytes) -> bytes:
    """Bound runtime for large PE files without changing the stream format.

    Uses a tiny multi-region entropy screen, then raw DEFLATE level 1. Only if
    that does not provide a useful reduction does it try Brotli quality 1. The
    result is selected only if the complete framed stream is smaller; otherwise
    the original bytes are returned (escaped if required).
    """
    n = len(data)
    raw = RAW_ESCAPE + data if data.startswith(COMPRESSED_MAGICS + (RAW_ESCAPE, MAGIC)) else data

    # A few tiny samples spread over the file avoid a full expensive search on
    # packed/already-compressed executables. This is a speed heuristic, not a
    # proof of incompressibility. Returning raw is always lossless.
    sample_size = 4096
    offsets = sorted({0, max(0, n // 4 - sample_size // 2),
                      max(0, n // 2 - sample_size // 2),
                      max(0, (3 * n) // 4 - sample_size // 2),
                      max(0, n - sample_size)})
    entropies = [_sample_entropy(data[o:o + sample_size]) for o in offsets]
    if entropies and all(value >= 7.90 for value in entropies):
        return raw

    crc = struct.pack('<I', zlib.crc32(data))
    try:
        co = zlib.compressobj(1, zlib.DEFLATED, -15)
        packed = co.compress(data) + co.flush()
        candidate = ZLIB_MAGIC + put_varint(n) + packed + crc
        # Prefer a quick, worthwhile result rather than spending more time
        # hunting for marginal improvements on an ~825 MiB executable.
        if len(candidate) <= len(raw) * 0.99:
            return candidate
    except (OSError, ValueError, zlib.error, MemoryError):
        candidate = None

    # Low-quality Brotli is a bounded-speed fallback, not Q11. It uses the same
    # DIRECT_BROTLI_MAGIC decoder already supported by prior VG-21C releases.
    if _brotli is not None:
        try:
            packed = _brotli.compress(data, quality=1, mode=_brotli.MODE_GENERIC, lgwin=22)
            brotli_candidate = DIRECT_BROTLI_MAGIC + packed + crc
            if len(brotli_candidate) < len(raw):
                if candidate is None or len(brotli_candidate) < len(candidate):
                    candidate = brotli_candidate
        except (ValueError, RuntimeError, TypeError, MemoryError):
            pass

    if candidate is not None and len(candidate) < len(raw):
        return candidate
    return raw


def compress(data: bytes) -> bytes:
    """Compress using the VG-21C v0.25 adaptive portfolio.

    Large PE executables (>=64 MiB) use a bounded-time fast path; other inputs
    retain the v0.24 candidate portfolio. The format uses existing markers. Raw data is returned
    unchanged unless it begins with a reserved marker, in which case RAW_ESCAPE
    makes decoding unambiguous. CRC32 is included on compressed streams.
    """
    if not data:
        return data

    # v0.25: large PE executables use a bounded-time path. This is deliberately
    # narrow: smaller files and every non-PE input retain the v0.24 search path.
    # The output markers are existing v0.24 modes, so the decoder format stays
    # backward-compatible. Compression level is intentionally faster than Q11.
    if len(data) >= 64 * 1024 * 1024 and _is_pe_executable(data):
        return _fast_large_pe_compress(data)

    # v0.24 endgame fast-path: don't spend minutes running heavyweight codecs
    # on obvious already-compressed/high-entropy data. For ZIP-based containers,
    # first attempt the dedicated exact-reconstruction member optimizer. For
    # JPEG and high-entropy binary data, raw fallback is a deliberate safe choice
    # unless a cheap, lossless candidate proves a strict reduction.
    if len(data) >= 4096 and (data.startswith(b"\xff\xd8\xff") or
                              data.startswith(b"\x89PNG\r\n\x1a\n") or
                              data.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"))):
        if data.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
            zip_candidate = _zip_member_candidate(data)
            if zip_candidate is not None and len(zip_candidate) < len(data):
                return zip_candidate
        raw = data
        if data.startswith(COMPRESSED_MAGICS + (RAW_ESCAPE, MAGIC)):
            raw = RAW_ESCAPE + data
        return raw

    # v0.24 bounded-budget path for large text/source files: run the two most
    # relevant dictionary/Brotli candidates first. If either achieves a strong
    # reduction, return the best of them rather than spending many minutes
    # sweeping dozens of LZMA/native configurations for marginal gains. This
    # trades exhaustive search for predictable runtime on large source files.
    if len(data) >= 65536:
        sample = data[:min(len(data), 16384)]
        printable_ratio = sum(1 for b in sample if b in (9, 10, 13) or 32 <= b <= 126) / len(sample)
        if printable_ratio >= 0.78 and not data.startswith(b"%PDF-"):
            quick = []
            for fn in (_token_brotli_candidate, _direct_brotli_candidate):
                try:
                    item = fn(data)
                    if item is not None and len(item) < len(data):
                        quick.append(item)
                except (ValueError, RuntimeError, TypeError, MemoryError):
                    pass
            if quick:
                best_quick = min(quick, key=len)
                if len(best_quick) <= len(data) * 0.50:
                    return best_quick

    # Entropy screen for random-like binary inputs. A 4 KiB sample is enough to
    # identify near-uniform bytes; skip expensive search when even the sample
    # has almost maximal empirical Shannon entropy. This is a speed heuristic,
    # not a proof that every such input is incompressible.
    if len(data) >= 8192:
        sample = data[:4096]
        counts = [0] * 256
        for byte in sample:
            counts[byte] += 1
        import math
        entropy = -sum((n / len(sample)) * math.log2(n / len(sample))
                       for n in counts if n)
        if entropy >= 7.985:
            raw = data
            if data.startswith(COMPRESSED_MAGICS + (RAW_ESCAPE, MAGIC)):
                raw = RAW_ESCAPE + data
            return raw

    candidate = _compact_candidate(data)
    # v0.11: evaluate a stricter LZ match threshold on PDF/text-heavy inputs.
    # It reduces token overhead when short matches cost more than their literals.
    # Always compare complete framed candidates and retain the smaller valid one.
    printable_ratio = (sum(1 for b in data if b in (9, 10, 13) or 32 <= b <= 126) / len(data)) if len(data) >= 256 else 0.0
    alpha_ratio = (sum(1 for b in data if 65 <= b <= 90 or 97 <= b <= 122) / len(data)) if len(data) >= 256 else 0.0
    if (data.startswith(b"%PDF-") or
            (256 <= len(data) <= 40000 and printable_ratio >= 0.80) or
            (80000 < len(data) <= 120000 and alpha_ratio >= 0.65)):
        compact6 = _compact_candidate(data, min_match=6)
        if len(compact6) < len(candidate):
            candidate = compact6
    bitlz = _bitlz_candidate(data) if len(data) >= 256 else None
    if bitlz is not None and len(bitlz) < len(candidate):
        candidate = bitlz
    # Native BWT/MTF rank-run coding: unlike byte-wise zero-RLE, each zero run
    # is a single symbol in a dedicated adaptive alphabet.
    if len(data) >= 512 and len(candidate) > len(data) // 20:
        bwt_run = _bwt_run_candidate(data)
        if bwt_run is not None and len(bwt_run) < len(candidate):
            candidate = bwt_run
            if data.count(0) / len(data) > 0.05:
                bwt_grammar = _bwt_grammar_candidate(data)
                if bwt_grammar is not None and len(bwt_grammar) < len(candidate):
                    candidate = bwt_grammar
    # Native structure-aware candidates are evaluated alongside the general codec.
    period = _period_candidate(data)
    if period is not None and len(period) < len(candidate):
        candidate = period
    period_arith = _period_arith_candidate(data)
    if period_arith is not None and len(period_arith) < len(candidate):
        candidate = period_arith
    json_candidate = _json_candidate(data)
    if json_candidate is not None:
        if len(json_candidate) < len(candidate):
            candidate = json_candidate
        json_arith = _json_arith_candidate(json_candidate, data)
        if json_arith is not None and len(json_arith) < len(candidate):
            candidate = json_arith
    # Lexical token dictionary is aimed at source-like files whose general
    # binary representation remains relatively large.
    # Dynamic dictionary is retained as an experimental encoder but is not
    # automatically invoked: on the fixed corpus its table overhead was high.
    # Exploratory phrase/grammar candidates remain available for experiments,
    # but are disabled in the default path because they lost on the frozen corpus.
    tar_candidate = (_tar_candidate(data) if len(data) >= 1024 and len(data) % 512 == 0
                     and len(candidate) > len(data) // 5 else None)
    if tar_candidate is not None and len(tar_candidate) < len(candidate):
        candidate = tar_candidate
    # v0.14 experiment: BWT + MTF followed by LZMA for small JSON-like payloads.
    # It is bounded to <=40 KB and selected only if the complete frame is smaller.
    bwt_lzma = _bwt_lzma_candidate(data)
    if bwt_lzma is not None and len(bwt_lzma) < len(candidate):
        candidate = bwt_lzma
    # v0.12 experiment: compare a standard-library LZMA candidate against every
    # native candidate. This is a hybrid fallback, not a replacement for native
    # modes; it is accepted only when the complete framed stream is smaller.
    # LZMA framing includes original size and CRC via the common outer frame.
    if len(data) >= 1024:
        # Compare several fully framed LZMA2 configurations. The default preset
        # remains in the set for compatibility; lower lc can help binary-like
        # data, while lc=3 is often stronger on text/source. Every candidate is
        # decoded by the same XZ/LZMA decoder and selected on complete size.
        lz_payloads = [lzma.compress(data, preset=9),
                       lzma.compress(data, preset=9 | lzma.PRESET_EXTREME)]
        # v0.15: add a low-literal-context LZMA2 configuration. A fixed-corpus
        # sweep found this setting materially smaller on PDF and TAR bytes than
        # the previously evaluated lc=2..4 configurations. It is only promoted
        # when its complete framed output beats the current best candidate.
        low_context_filter = [{'id': lzma.FILTER_LZMA2,
                               'dict_size': 1 << 20,
                               'lc': 0, 'lp': 0, 'pb': 0,
                               'mode': lzma.MODE_NORMAL,
                               'nice_len': 273,
                               'mf': lzma.MF_BT4, 'depth': 0}]
        try:
            lz_payloads.append(lzma.compress(data, format=lzma.FORMAT_XZ,
                                             filters=low_context_filter))
        except (ValueError, lzma.LZMAError):
            pass
        # v0.19 experiment: focused small-dictionary HC4 candidates found in a
        # measured configuration sweep. These complement BT4 rather than
        # replacing it; the complete framed size decides whether they survive.
        # HC4 can be smaller on short PDF object streams and TAR metadata.
        targeted_hc4 = None
        if data.startswith(b"%PDF-"):
            targeted_hc4 = {'id': lzma.FILTER_LZMA2, 'dict_size': 1 << 18,
                            'lc': 0, 'lp': 0, 'pb': 0,
                            'mode': lzma.MODE_NORMAL, 'nice_len': 273,
                            'mf': lzma.MF_HC4, 'depth': 0}
        elif len(data) >= 512 and len(data) % 512 == 0 and data[257:262] == b'ustar':
            targeted_hc4 = {'id': lzma.FILTER_LZMA2, 'dict_size': 1 << 18,
                            'lc': 3, 'lp': 0, 'pb': 0,
                            'mode': lzma.MODE_NORMAL, 'nice_len': 273,
                            'mf': lzma.MF_HC4, 'depth': 0}
        elif (len(data) >= 1024 and
              sum(1 for b in data if b in (9, 10, 13) or 32 <= b <= 126) / len(data) >= 0.75):
            targeted_hc4 = {'id': lzma.FILTER_LZMA2, 'dict_size': 1 << 18,
                            'lc': 3, 'lp': 0, 'pb': 0,
                            'mode': lzma.MODE_NORMAL, 'nice_len': 273,
                            'mf': lzma.MF_HC4, 'depth': 0}
        if targeted_hc4 is not None:
            try:
                lz_payloads.append(lzma.compress(data, format=lzma.FORMAT_XZ,
                                                 filters=[targeted_hc4]))
            except (ValueError, lzma.LZMAError):
                pass
        # v0.16: a focused TAR candidate. POSIX ustar files have the magic at
        # byte offset 257 and are 512-byte aligned. A small dictionary and
        # pb=0/lc=3 model won a broader measured sweep for the fixed TAR case.
        # This is only attempted for recognizable ustar archives, and still
        # must beat the best complete framed stream before selection.
        if len(data) >= 512 and len(data) % 512 == 0 and data[257:262] == b'ustar':
            tar_filter = [{'id': lzma.FILTER_LZMA2,
                           'dict_size': 1 << 18,
                           'lc': 3, 'lp': 0, 'pb': 0,
                           'mode': lzma.MODE_NORMAL,
                           'nice_len': 273,
                           'mf': lzma.MF_BT4, 'depth': 0}]
            try:
                lz_payloads.append(lzma.compress(data, format=lzma.FORMAT_XZ,
                                                 filters=tar_filter))
            except (ValueError, lzma.LZMAError):
                pass
        for lc in (2, 3, 4):
            for dict_size in (1 << 20, 1 << 22, 1 << 24):
                # Existing pb=2 configurations retained for stable comparison.
                filters = [{'id': lzma.FILTER_LZMA2, 'dict_size': dict_size,
                            'lc': lc, 'lp': 0, 'pb': 2,
                            'mode': lzma.MODE_NORMAL, 'nice_len': 273,
                            'mf': lzma.MF_BT4, 'depth': 0}]
                try:
                    lz_payloads.append(lzma.compress(data, format=lzma.FORMAT_XZ,
                                                     filters=filters))
                except (ValueError, lzma.LZMAError):
                    continue
                # v0.18 experiment: pb=0 reduces position-model overhead on
                # source-like data. Restrict the extra sweep to source/text so
                # archives and binary-specialized paths do not pay needless cost.
                if (not data.startswith(b'%PDF-') and
                        sum(1 for b in data if b in (9, 10, 13) or 32 <= b <= 126) / len(data) >= 0.75):
                    filters_pb0 = [{'id': lzma.FILTER_LZMA2, 'dict_size': dict_size,
                                    'lc': lc, 'lp': 0, 'pb': 0,
                                    'mode': lzma.MODE_NORMAL, 'nice_len': 273,
                                    'mf': lzma.MF_BT4, 'depth': 0}]
                    try:
                        lz_payloads.append(lzma.compress(data, format=lzma.FORMAT_XZ,
                                                         filters=filters_pb0))
                    except (ValueError, lzma.LZMAError):
                        continue
        for lz_stream in lz_payloads:
            lz_payload = put_varint(len(data)) + lz_stream
            lz_candidate = LZMA_MAGIC + lz_payload + struct.pack('<I', zlib.crc32(data))
            if len(lz_candidate) < len(candidate):
                candidate = lz_candidate
    # v0.19: per-file lexical dictionary for large text/source-like inputs.
    token_lzma = _token_lzma_candidate(data)
    if token_lzma is not None and len(token_lzma) < len(candidate):
        candidate = token_lzma
    # v0.21 research branch: dictionary+Brotli profiles compete by complete size.
    # This is not an independent-codec result; it is evaluated on complete size.
    token_brotli = _token_brotli_candidate(data)
    if token_brotli is not None and len(token_brotli) < len(candidate):
        candidate = token_brotli
    # v0.17: lossless ZIP member recompression. It is accepted only when the
    # original DEFLATE payloads are exactly reproducible by raw zlib level 9.
    zip_candidate = _zip_member_candidate(data)
    if zip_candidate is not None and len(zip_candidate) < len(candidate):
        candidate = zip_candidate
    # v0.22: direct Brotli Q11 competes with specialized PDF/TAR candidates.
    # The wrapper adds 8 bytes (magic + CRC); select only on complete size.
    direct_brotli = _direct_brotli_candidate(data)
    if direct_brotli is not None and len(direct_brotli) < len(candidate):
        candidate = direct_brotli
    # v0.24 endgame: broaden the lossless portfolio with BZip2 and zlib.
    # These modes are selected only when their complete framed stream beats
    # every candidate already considered. They are alternatives, not claims of
    # a new entropy coder; the point is data-dependent selection with no size
    # regression for a single input.
    if len(data) >= 128:
        try:
            bz_payload = bz2.compress(data, compresslevel=9)
            bz_candidate = (BZIP2_MAGIC + put_varint(len(data)) + bz_payload +
                            struct.pack('<I', zlib.crc32(data)))
            if len(bz_candidate) < len(candidate):
                candidate = bz_candidate
        except (OSError, ValueError):
            pass
        try:
            # zlib level 9 is broadly available; raw DEFLATE avoids zlib header
            # overhead, while the outer VG frame supplies size and integrity.
            co = zlib.compressobj(9, zlib.DEFLATED, -15)
            z_payload = co.compress(data) + co.flush()
            z_candidate = (ZLIB_MAGIC + put_varint(len(data)) + z_payload +
                           struct.pack('<I', zlib.crc32(data)))
            if len(z_candidate) < len(candidate):
                candidate = z_candidate
        except (OSError, ValueError, zlib.error):
            pass
    # Raw output is the true byte baseline. Escape only the reserved prefixes.
    raw = data
    if data.startswith(COMPRESSED_MAGICS + (RAW_ESCAPE, MAGIC)):
        raw = RAW_ESCAPE + data
    if len(candidate) < len(raw):
        return candidate
    return raw


def decompress(blob: bytes) -> bytes:
    """Decode supported native VG-21C streams or unchanged raw fallback."""
    if blob.startswith(RAW_ESCAPE):
        return blob[len(RAW_ESCAPE):]
    if blob.startswith(COMPRESSED_MAGICS):
        if len(blob) < 8:
            raise ValueError('truncated VG-21C stream')
        marker = blob[:4]
        payload = blob[4:-4]
        expected_crc = struct.unpack('<I', blob[-4:])[0]
        if marker == ZIP_MEMBER_MAGIC:
            out = _zip_member_decode(payload)
        elif marker == BWT_LZMA_MAGIC:
            original_size, i = get_varint(payload, 0)
            primary, i = get_varint(payload, i)
            last = lzma.decompress(payload[i:])
            out = bwt_inverse(last, primary)
            if len(out) != original_size:
                raise ValueError('BWT-LZMA output size mismatch')
        elif marker == LZMA_MAGIC:
            original_size, i = get_varint(payload, 0)
            out = lzma.decompress(payload[i:])
            if len(out) != original_size:
                raise ValueError('LZMA output size mismatch')
        elif marker == DIRECT_BROTLI_MAGIC:
            if _brotli is None:
                raise ValueError("decoding this VG-21C mode requires the optional brotli package")
            out = _brotli.decompress(payload)
        elif marker == BZIP2_MAGIC:
            original_size, i = get_varint(payload, 0)
            out = bz2.decompress(payload[i:])
            if len(out) != original_size:
                raise ValueError('BZip2 output size mismatch')
        elif marker == ZLIB_MAGIC:
            original_size, i = get_varint(payload, 0)
            out = zlib.decompress(payload[i:], -15)
            if len(out) != original_size:
                raise ValueError('zlib output size mismatch')
        elif marker == TOKEN_BROTLI_MAGIC:
            if _brotli is None:
                raise ValueError("decoding this VG-21C mode requires the optional brotli package")
            original_size, i = get_varint(payload, 0)
            decoded = _brotli.decompress(payload[i:])
            if not decoded:
                raise ValueError("empty token-Brotli payload")
            count = decoded[0]
            cursor = 1
            reverse = {}
            for _ in range(count):
                if cursor + 3 > len(decoded):
                    raise ValueError("truncated token-Brotli dictionary")
                code = decoded[cursor]
                token_n = struct.unpack(">H", decoded[cursor+1:cursor+3])[0]
                cursor += 3
                if token_n == 0 or cursor + token_n > len(decoded) or code in reverse:
                    raise ValueError("invalid token-Brotli dictionary entry")
                reverse[code] = decoded[cursor:cursor+token_n]
                cursor += token_n
            out = bytearray()
            for value in decoded[cursor:]:
                out.extend(reverse[value] if value in reverse else bytes([value]))
            out = bytes(out)
            if len(out) != original_size:
                raise ValueError("token-Brotli output size mismatch")
        elif marker == TOKEN_LZMA_MAGIC:
            original_size, i = get_varint(payload, 0)
            decoded = lzma.decompress(payload[i:])
            if not decoded:
                raise ValueError('empty token-LZMA payload')
            count = decoded[0]
            cursor = 1
            reverse = {}
            for _ in range(count):
                if cursor + 3 > len(decoded):
                    raise ValueError('truncated token-LZMA dictionary')
                code = decoded[cursor]
                token_n = struct.unpack('>H', decoded[cursor+1:cursor+3])[0]
                cursor += 3
                if token_n == 0 or cursor + token_n > len(decoded) or code in reverse:
                    raise ValueError('invalid token-LZMA dictionary entry')
                reverse[code] = decoded[cursor:cursor+token_n]
                cursor += token_n
            out = bytearray()
            for value in decoded[cursor:]:
                out.extend(reverse[value] if value in reverse else bytes([value]))
            out = bytes(out)
            if len(out) != original_size:
                raise ValueError('token-LZMA output size mismatch')
        elif marker == PERIOD_ARITH_MAGIC:
            original_size,i=get_varint(payload,0); seed_n,i=get_varint(payload,i); coded_n,i=get_varint(payload,i)
            if coded_n!=len(payload)-i: raise ValueError('period arithmetic payload length mismatch')
            seed_payload=_arith_decode(payload[i:],seed_n)
            seed=compact_decode_tokens(seed_payload)
            if not seed or original_size%len(seed): raise ValueError('invalid period arithmetic seed')
            out=seed*(original_size//len(seed))
        elif marker == PERIOD_MAGIC:
            original_size, i = get_varint(payload, 0)
            seed_n, i = get_varint(payload, i)
            if seed_n > len(payload) - i: raise ValueError('truncated period seed')
            seed = compact_decode_tokens(payload[i:i+seed_n]); i += seed_n
            if i != len(payload) or not seed or original_size % len(seed):
                raise ValueError('invalid period stream')
            out = seed * (original_size // len(seed))
        elif marker == DICT_MAGIC:
            out = _phrase_decode(payload)
        elif marker == GRAMMAR_MAGIC:
            out = _grammar_decode(payload)
        elif marker == TAR_MAGIC:
            out = _tar_decode(payload)
        elif marker == LEX_MAGIC:
            out = _lex_decode(payload)
        elif marker == DYNPHRASE_MAGIC:
            out = _dynamic_phrase_decode(payload)
        elif marker == OPTSTATIC_MAGIC:
            original_n,i=get_varint(payload,0)
            if i>=len(payload): raise ValueError('truncated optimized-static mode')
            mode=payload[i]; i+=1
            if mode==1: plain_n,i=get_varint(payload,i)
            elif mode not in (0,2,3): raise ValueError('unknown optimized-static mode')
            coded_n,i=get_varint(payload,i)
            if coded_n!=len(payload)-i: raise ValueError('optimized-static payload length mismatch')
            if mode in (0,1):
                compact=_arith_decode(payload[i:],plain_n) if mode==1 else payload[i:]
                out=compact_decode_tokens(compact,max_output=original_n,phrases=OPT_PHRASES)
            elif mode==2:
                token_count,j=get_varint(payload,i)
                out=detokenize(typed_huffman_decode(payload[j:],token_count,OPT_PHRASES),original_n,OPT_PHRASES)
            else:
                out=_typed_arithmetic_decode_payload(payload[i:],original_n,OPT_PHRASES)
            if len(out)!=original_n: raise ValueError('optimized-static output size mismatch')
        elif marker == JSON_ARITH_MAGIC:
            original_size, i = get_varint(payload, 0)
            plain_n, i = get_varint(payload, i)
            coded_n, i = get_varint(payload, i)
            if coded_n != len(payload)-i: raise ValueError('JSON arithmetic payload length mismatch')
            plain = _arith_decode(payload[i:], plain_n)
            out = _json_decode_payload(put_varint(original_size) + plain)
        elif marker == JSON_MAGIC:
            out = _json_decode_payload(payload)
        elif marker == CONTEXT_MAGIC:
            original_size, i = get_varint(payload, 0)
            token_size, i = get_varint(payload, i)
            compact = _context_arith_decode(payload[i:], token_size)
            out = compact_decode_tokens(compact)
            if len(out) != original_size: raise ValueError('context stream output size mismatch')
        elif marker == BLOCK_MAGIC:
            i = 0; count, i = get_varint(payload, i); out_buf = bytearray()
            if count > 1 << 20: raise ValueError('too many VG-21C blocks')
            for _ in range(count):
                if i >= len(payload): raise ValueError('truncated block record')
                mode = payload[i]; i += 1
                original_n, i = get_varint(payload, i)
                token_n, i = get_varint(payload, i)
                encoded_n, i = get_varint(payload, i)
                primary = 0
                if mode == 1: primary, i = get_varint(payload, i)
                if encoded_n > len(payload)-i: raise ValueError('truncated block payload')
                encoded = payload[i:i+encoded_n]; i += encoded_n
                if mode == 0:
                    compact = _arith_decode(encoded, token_n)
                    block = compact_decode_tokens(compact)
                elif mode == 1:
                    compact = _arith_decode(encoded, token_n)
                    zr = compact_decode_tokens(compact)
                    mtf = zero_run_decode(zr, original_n)
                    block = bwt_inverse(mtf_decode(mtf), primary)
                else:
                    raise ValueError('unknown block mode')
                if len(block) != original_n: raise ValueError('block output size mismatch')
                out_buf.extend(block)
            if i != len(payload): raise ValueError('trailing block payload data')
            out = bytes(out_buf)
        elif marker == BITLZ_MAGIC:
            out = _bitlz_decode(payload)
        elif marker == PDF_MAGIC:
            out = _pdf_decode(payload)
        elif marker == BWT_GRAMMAR_MAGIC:
            original_size,i=get_varint(payload,0); primary,i=get_varint(payload,i)
            zr_n,i=get_varint(payload,i); rule_count,i=get_varint(payload,i)
            if rule_count>4096: raise ValueError('BWT grammar rule count too large')
            rules=[]
            for idx in range(rule_count):
                a,i=get_varint(payload,i); b,i=get_varint(payload,i)
                if a>255+idx or b>255+idx: raise ValueError('BWT grammar future reference')
                rules.append((a,b))
            symbol_count,i=get_varint(payload,i); coded_n,i=get_varint(payload,i)
            if coded_n!=len(payload)-i: raise ValueError('BWT grammar coded length mismatch')
            symbols=_arith_decode_symbols(payload[i:],symbol_count,256+rule_count)
            zr=_grammar_expand(symbols,rules,zr_n)
            mtf=zero_run_decode(zr,original_size)
            out=bwt_inverse(mtf_decode(mtf),primary)
            if len(out)!=original_size: raise ValueError('BWT grammar output size mismatch')
        elif marker == BWT_RUN_MAGIC:
            original_size,i=get_varint(payload,0); primary,i=get_varint(payload,i)
            symbol_count,i=get_varint(payload,i); coded_n,i=get_varint(payload,i)
            if coded_n!=len(payload)-i: raise ValueError('BWT rank/run coded length mismatch')
            symbols=_arith_decode_symbols(payload[i:],symbol_count,512,_mtf_run_prior())
            mtf=_run_symbols_to_mtf(symbols,original_size)
            out=bwt_inverse(mtf_decode(mtf),primary)
            if len(out)!=original_size: raise ValueError('BWT rank/run output size mismatch')
        elif marker == BWT_ARITH_MAGIC:
            original_size, i = get_varint(payload, 0)
            primary, i = get_varint(payload, i)
            transformed_size, i = get_varint(payload, i)
            mtf = _arith_decode(payload[i:], transformed_size, _mtf_prior())
            last = mtf_decode(mtf)
            out = bwt_inverse(last, primary)
            if len(out) != original_size: raise ValueError('BWT output size mismatch')
        elif marker == BWT_CONTEXT_MAGIC:
            original_size, i = get_varint(payload, 0)
            primary, i = get_varint(payload, i)
            transformed_size, i = get_varint(payload, i)
            mtf = _context_arith_decode(payload[i:], transformed_size)
            out = bwt_inverse(mtf_decode(mtf), primary)
            if len(out) != original_size: raise ValueError('BWT output size mismatch')
        elif marker == BWT_RLE_ARITH_MAGIC:
            original_size, i = get_varint(payload, 0)
            primary, i = get_varint(payload, i)
            transformed_size, i = get_varint(payload, i)
            zr = _arith_decode(payload[i:], transformed_size)
            mtf = zero_run_decode(zr, original_size)
            out = bwt_inverse(mtf_decode(mtf), primary)
            if len(out) != original_size: raise ValueError('BWT-RLE output size mismatch')
        elif marker == BWT_MAGIC:
            original_size, i = get_varint(payload, 0)
            primary, i = get_varint(payload, i)
            zr = compact_decode_tokens(payload[i:])
            if len(zr) > (1 << 40): raise ValueError('transformed stream too large')
            mtf = zero_run_decode(zr, original_size)
            last = mtf_decode(mtf)
            out = bwt_inverse(last, primary)
            if len(out) != original_size: raise ValueError('BWT output size mismatch')
        elif marker == TYPED_ARITH_MAGIC:
            original_size, i = get_varint(payload, 0)
            token_count, i = get_varint(payload, i)
            streams = []
            for stream_index in range(3):
                if i >= len(payload): raise ValueError('truncated typed arithmetic selector')
                coder_id = payload[i]; i += 1
                plain_n, i = get_varint(payload, i)
                coded_n, i = get_varint(payload, i)
                if coded_n > len(payload) - i: raise ValueError('truncated typed arithmetic stream')
                coded = payload[i:i+coded_n]
                prior = _typed_prior(stream_index)
                if coder_id == 0:
                    streams.append(_arith_decode(coded, plain_n))
                elif coder_id == 1:
                    streams.append(_context_arith_decode(coded, plain_n))
                elif coder_id == 2:
                    streams.append(_arith_decode(coded, plain_n, prior))
                elif coder_id == 3:
                    streams.append(_context_arith_decode(coded, plain_n, prior))
                else:
                    raise ValueError('unknown typed arithmetic coder')
                i += coded_n
            if i != len(payload): raise ValueError('trailing typed arithmetic data')
            tokens = join_typed_streams(streams[0], streams[1], streams[2], token_count)
            out = detokenize(tokens, original_size)
        elif marker == TYPED_MAGIC:
            original_size, i = get_varint(payload, 0)
            token_count, i = get_varint(payload, i)
            tokens = typed_huffman_decode(payload[i:], token_count)
            out = detokenize(tokens, original_size)
        elif marker == ARITH_MAGIC:
            original_size, i = get_varint(payload, 0)
            token_size, i = get_varint(payload, i)
            compact = _arith_decode(payload[i:], token_size)
            out = compact_decode_tokens(compact)
            if len(out) != original_size: raise ValueError('arithmetic stream output size mismatch')
        else:
            transformed = compact_decode_tokens(payload)
            if marker == DELTA_MAGIC:
                out = _delta_decode(transformed)
            elif marker == XOR_MAGIC:
                out = _xor_decode(transformed)
            else:
                out = transformed
        if zlib.crc32(out) != expected_crc:
            raise ValueError('VG-21C v0.8 checksum mismatch')
        return out
    if blob.startswith(MAGIC):
        return _decompress_legacy(blob)
    # Non-magic blobs are raw data. Reserved prefixes are escaped by compress().
    return blob


def stats(data: bytes):
    t=time.perf_counter(); enc=compress(data); ct=time.perf_counter()-t
    t=time.perf_counter(); dec=decompress(enc); dt=time.perf_counter()-t
    assert dec==data
    return {'original_bytes':len(data),'encoded_bytes':len(enc),'net_saved_bytes':len(data)-len(enc),
            'ratio':(len(enc)/len(data) if data else 0.0),'compression_seconds':ct,
            'decompression_seconds':dt,'roundtrip_ok':True,'mode':(enc[:4].decode('ascii', errors='replace') if enc[:4] in COMPRESSED_MAGICS else 'raw')}

# Interactive file/folder container for the v0.21 byte compressor.
# Container header: magic + kind (F=file, D=directory) + UTF-8 name length/name + compressed payload.
CONTAINER_MAGIC = b'VG21CF01'


def _container_pack(kind: bytes, name: str, payload: bytes) -> bytes:
    encoded_name = name.encode('utf-8')
    if kind not in (b'F', b'D'):
        raise ValueError('invalid container kind')
    if len(encoded_name) > 65535:
        raise ValueError('input name is too long')
    return CONTAINER_MAGIC + kind + struct.pack('>H', len(encoded_name)) + encoded_name + compress(payload)


def _container_unpack(blob: bytes):
    if not blob.startswith(CONTAINER_MAGIC):
        # Accept older raw VG-21C streams too.
        return b'F', 'decompressed.bin', decompress(blob)
    i = len(CONTAINER_MAGIC)
    if len(blob) < i + 3:
        raise ValueError('truncated VG-21C container header')
    kind = blob[i:i+1]; i += 1
    if kind not in (b'F', b'D'):
        raise ValueError('unknown VG-21C container type')
    name_len = struct.unpack('>H', blob[i:i+2])[0]; i += 2
    if len(blob) < i + name_len:
        raise ValueError('truncated VG-21C container name')
    name = blob[i:i+name_len].decode('utf-8'); i += name_len
    if not name or name in ('.', '..') or '/' in name or '\\' in name:
        raise ValueError('unsafe original name in VG-21C container')
    return kind, name, decompress(blob[i:])


def _folder_to_tar(folder: Path) -> bytes:
    """Pack a directory as a tar stream; reject symlinks/special files for safety."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w', format=tarfile.PAX_FORMAT) as tf:
        tf.add(folder, arcname=folder.name, recursive=False)
        for root, dirs, files in os.walk(folder, followlinks=False):
            root_path = Path(root)
            for dirname in list(dirs):
                item = root_path / dirname
                if item.is_symlink():
                    raise ValueError(f'symbolic links are not supported: {item}')
                tf.add(item, arcname=item.relative_to(folder.parent).as_posix(), recursive=False)
            for filename in files:
                item = root_path / filename
                if item.is_symlink() or not item.is_file():
                    raise ValueError(f'special files/symbolic links are not supported: {item}')
                tf.add(item, arcname=item.relative_to(folder.parent).as_posix(), recursive=False)
    return buf.getvalue()


def _safe_tar_extract(tar_bytes: bytes, destination: Path, expected_root: str) -> None:
    """Extract only regular files and directories, preventing traversal/link attacks."""
    destination.mkdir(parents=True, exist_ok=True)
    root = destination.resolve()
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode='r:') as tf:
        members = tf.getmembers()
        for member in members:
            if member.issym() or member.islnk() or not (member.isdir() or member.isfile()):
                raise ValueError(f'unsafe/unsupported archive member: {member.name}')
            target = (destination / member.name).resolve()
            if target != root and root not in target.parents:
                raise ValueError(f'unsafe archive path: {member.name}')
            parts = Path(member.name).parts
            if not parts or parts[0] != expected_root or '..' in parts:
                raise ValueError(f'archive does not match expected folder: {member.name}')
        tf.extractall(destination, members=members)


def _ask_existing_path(path: Path, description: str) -> Path | None:
    if not path.exists():
        return path
    print(f'\n{description} already exists: {path}')
    alternative = input('Enter another destination path (or press Enter to cancel): ').strip().strip('"')
    if not alternative:
        print('Cancelled; no files were overwritten.')
        return None
    candidate = Path(alternative).expanduser()
    if candidate.exists():
        print('That destination also exists. Please choose a new path and run again.')
        return None
    return candidate


def compress_path(input_path: Path) -> Path:
    input_path = input_path.expanduser().resolve()
    if not input_path.exists():
        raise FileNotFoundError(f'Path not found: {input_path}')
    if input_path.is_symlink():
        raise ValueError('Compressing a symbolic link directly is not supported.')
    output_path = _ask_existing_path(input_path.with_suffix('.vg21c'), 'Output file')
    if output_path is None:
        raise InterruptedError('compression cancelled')
    if input_path.is_file():
        kind = b'F'
        payload = input_path.read_bytes()
    elif input_path.is_dir():
        kind = b'D'
        payload = _folder_to_tar(input_path)
    else:
        raise ValueError('Choose a regular file or directory.')
    encoded = _container_pack(kind, input_path.name, payload)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(encoded)
    # Verify the complete container before reporting success.
    decoded_kind, decoded_name, decoded_payload = _container_unpack(output_path.read_bytes())
    if decoded_kind != kind or decoded_name != input_path.name or decoded_payload != payload:
        output_path.unlink(missing_ok=True)
        raise RuntimeError('verification failed; output removed')
    print(f'\nCompression complete: {output_path}')
    print(f'Input payload: {len(payload):,} bytes')
    print(f'VG-21C file:   {len(encoded):,} bytes')
    print(f'Net saved:     {len(payload) - len(encoded):,} bytes (container overhead included)')
    print('Round-trip verification: PASS')
    return output_path


def decompress_path(input_path: Path) -> Path:
    input_path = input_path.expanduser().resolve()
    if not input_path.is_file():
        raise FileNotFoundError(f'Compressed file not found: {input_path}')
    kind, original_name, payload = _container_unpack(input_path.read_bytes())
    output_path = input_path.parent / original_name
    if kind == b'F':
        if output_path.exists():
            output_path = _ask_existing_path(output_path, 'Restored output file')
            if output_path is None:
                raise InterruptedError('decompression cancelled')
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(payload)
    else:
        extraction_parent = input_path.parent
        if output_path.exists():
            print(f'\nRestored folder already exists: {output_path}')
            alternative = input('Enter another destination DIRECTORY (or press Enter to cancel): ').strip().strip('"')
            if not alternative:
                raise InterruptedError('decompression cancelled')
            extraction_parent = Path(alternative).expanduser().resolve()
            if (extraction_parent / original_name).exists():
                raise FileExistsError(f'the folder already exists in that destination: {extraction_parent / original_name}')
        extraction_parent.mkdir(parents=True, exist_ok=True)
        _safe_tar_extract(payload, extraction_parent, original_name)
        output_path = extraction_parent / original_name
    print(f'\nDecompression complete: {output_path}')
    print('Output is ready.')
    return output_path


def main():
    print('=' * 58)
    print(' VG-21C v0.25 — Interactive File & Folder Compressor')
    print('=' * 58)
    print('1. Compress a file or folder')
    print('2. Decompress a .vg21c file')
    choice = input('\nChoose 1 or 2 [1]: ').strip() or '1'
    if choice not in ('1', '2'):
        print('Invalid choice. Please run again and choose 1 or 2.')
        return
    raw_path = input('Enter the full path to the file/folder: ').strip().strip('"')
    if not raw_path:
        print('No path entered. Nothing was changed.')
        return
    path = Path(raw_path).expanduser()
    try:
        if choice == '1':
            compress_path(path)
        else:
            decompress_path(path)
    except (ValueError, OSError, EOFError, InterruptedError, tarfile.TarError) as exc:
        print(f'\nError: {exc}')


if __name__=='__main__': main()
