"""Image/file steganography and binary-artifact solvers.

Images, appended archives, LSB-encoded text and QR codes are all handled
here. Each solver degrades gracefully (returns nothing) if an optional
dependency (Pillow / numpy / opencv) isn't installed.
"""
from __future__ import annotations

import io
import re
import struct
import zlib

from autocrypt.core import solver
from autocrypt.scoring import assess
import autocrypt.filetypes as filetypes

try:
    from PIL import Image, ExifTags
except ImportError:
    Image = None
try:
    import numpy as _np
except ImportError:
    _np = None
try:
    import cv2 as _cv2
except ImportError:
    _cv2 = None

_FLAG_HINT = re.compile(rb"[A-Za-z0-9_]{2,20}\{[^{}]{1,300}\}")


def _emit(ctx, plain, method, params=None, score=None):
    params = params or {}
    if score is None:
        score, _ = assess(plain)
    yield plain, method, params, score


# --------------------------------------------------------- EXIF/metadata ---
@solver("image-metadata", lambda fp: .5 if fp.get("filetype") in filetypes.IMAGE_TYPES else 0.0)
def solve_metadata(data, ctx):
    if Image is None:
        return
    try:
        im = Image.open(io.BytesIO(data))
        im.load()
    except Exception:
        return
    notes = []
    info_text = " | ".join(f"{k}={v}" for k, v in im.info.items()
                            if isinstance(v, (str, bytes, int, float)) and k != "exif")[:800]
    if info_text:
        notes.append(f"Image metadata: {info_text}")
    try:
        exif = im.getexif()
        if exif:
            pairs = []
            for tag_id, value in exif.items():
                name = ExifTags.TAGS.get(tag_id, str(tag_id))
                pairs.append(f"{name}={value}")
            if pairs:
                notes.append("EXIF: " + ", ".join(pairs)[:800])
    except Exception:
        pass
    if not notes:
        return
    blob = " | ".join(notes)
    ctx.findings.append(blob[:500])
    match = _FLAG_HINT.search(blob.encode("utf-8", "replace"))
    if match:
        yield from _emit(ctx, match.group(0), "image metadata (flag-like string)")


# -------------------------------------------------- appended/carved data ---
def _png_end(data):
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return None
    pos = 8
    while pos + 8 <= len(data):
        length = int.from_bytes(data[pos:pos + 4], "big")
        kind = data[pos + 4:pos + 8]
        pos += 8 + length + 4  # length + type + data + crc
        if kind == b"IEND":
            return pos
    return None


def _jpeg_end(data):
    if not data.startswith(b"\xff\xd8"):
        return None
    marker = data.rfind(b"\xff\xd9")
    return marker + 2 if marker != -1 else None


@solver("appended-data", lambda fp: .6 if fp.get("filetype") in
        (filetypes.IMAGE_TYPES | {"GIF image"}) and fp["length"] > 200 else 0.0)
def solve_appended(data, ctx):
    if ctx.depth > 0:
        return
    end = None
    ft = filetypes.detect_filetype(data)
    if ft == "PNG image":
        end = _png_end(data)
    elif ft == "JPEG image":
        end = _jpeg_end(data)
    if end is None or end >= len(data):
        return
    tail = data[end:]
    if len(tail.strip(b"\x00\r\n")) < 4:
        return
    ctx.findings.append(f"{len(tail)} bytes appended after the end of the {ft} "
                         f"(offset {end}); treating them as hidden data.")
    yield from _emit(ctx, tail, "appended data", {"offset": end})


@solver("carved-file", lambda fp: .45 if fp["length"] > 64 else 0.0)
def solve_carve(data, ctx):
    if ctx.depth > 0 or len(data) > 25_000_000:
        return
    found = 0
    for sig, label in filetypes.EMBEDDED:
        offset = data.find(sig, 8)  # skip the file's own header at offset 0
        if offset <= 0:
            continue
        found += 1
        if found > 4:
            break
        carved = data[offset:]
        ctx.findings.append(f"Found a {label} signature at offset {offset}; carved {len(carved)} "
                             "trailing bytes as a possible hidden file.")
        yield from _emit(ctx, carved, "carved file", {"type": label, "offset": offset}, score=.3)


# ---------------------------------------------------------------- LSB ------
def _lsb_extract_np(arr, channels, plane):
    bits = ((arr[..., channels] >> plane) & 1).reshape(-1)
    nbytes = min(len(bits) // 8, 60_000)
    if nbytes < 1:
        return b""
    return _np.packbits(bits[:nbytes * 8]).tobytes()


def _lsb_extract_plain(pixels, channels, plane):
    bits = []
    for px in pixels:
        for c in channels:
            bits.append((px[c] >> plane) & 1)
    nbytes = min(len(bits) // 8, 60_000)
    if nbytes < 1:
        return b""
    out = bytearray()
    for i in range(nbytes):
        v = 0
        for j in range(8):
            v = (v << 1) | bits[i * 8 + j]
        out.append(v)
    return bytes(out)


_channel_combos = (
    ("RGB", [0, 1, 2]),
    ("R", [0]),
    ("G", [1]),
    ("B", [2]),
)


@solver("lsb-steganography", lambda fp: .5 if fp.get("filetype") == "PNG image" else 0.0)
def solve_lsb(data, ctx):
    if Image is None:
        return
    try:
        im = Image.open(io.BytesIO(data)).convert("RGB")
    except Exception:
        return
    arr = None
    pixels = None
    if _np is not None:
        try:
            arr = _np.array(im)
        except Exception:
            arr = None
    if arr is None:
        try:
            pixels = list(im.getdata())
        except Exception:
            return
    if arr is None and not pixels:
        return
    best = None
    for chname, chans in _channel_combos:
        for plane in range(8):
            if ctx.expired():
                return
            try:
                if arr is not None:
                    raw = _lsb_extract_np(arr, chans, plane)
                else:
                    raw = _lsb_extract_plain(pixels, chans, plane)
            except Exception:
                continue
            if not raw:
                continue
            label = f"{chname} bit {plane}"
            match = _FLAG_HINT.search(raw)
            if match:
                yield from _emit(ctx, match.group(0), "LSB steganography",
                                 {"channel": chname, "plane": plane}, score=.9)
                continue
            cut = raw.find(b"\x00")
            text = raw[:cut] if cut > 4 else raw
            score, _ = assess(text)
            if best is None or score > best[0]:
                best = (score, text, label)
    if best and best[0] >= .3:
        score, text, label = best
        yield from _emit(ctx, text, "LSB steganography", {"channel": label}, score=score)


# -------------------------------------------------------------- WAV LSB ---
def _wav_data(data):
    if data[:4] != b"RIFF" or data[8:12] != b"WAVE":
        return None
    pos = 12
    bps = None
    channels = None
    while pos + 8 <= len(data):
        size = int.from_bytes(data[pos + 4:pos + 8], "little")
        if data[pos:pos + 4] == b"fmt ":
            fmt = data[pos + 8:pos + 8 + size]
            if len(fmt) >= 16:
                bps = int.from_bytes(fmt[14:16], "little")
                channels = int.from_bytes(fmt[2:4], "little")
        elif data[pos:pos + 4] == b"data":
            # Without a fmt chunk we cannot know bit depth / channels -> bail.
            if bps is None or channels is None:
                return None
            return data[pos + 8:pos + 8 + size], bps, channels
        pos += 8 + size + (size & 1)
    return None


@solver("wav-lsb", lambda fp: .5 if fp.get("filetype") == "WAV audio" or
        (fp["length"] > 44 and fp.get("_head", b"")[:4] == b"RIFF" and fp.get("_head", b"")[8:12] == b"WAVE") else 0.0)
def solve_wav_lsb(data, ctx):
    parsed = _wav_data(data)
    if parsed is None:
        return
    raw, bps, channels = parsed
    if raw is None or not channels:
        return
    step = bps // 8
    samples = []
    for i in range(0, len(raw) - step + 1, step):
        samples.append(int.from_bytes(raw[i:i + step], "little", signed=(bps == 16)))
    best = None
    for plane in range(8):
        if ctx.expired():
            break
        bits = []
        for s in samples:
            bits.append((s >> plane) & 1)
        nbytes = len(bits) // 8
        if nbytes < 4:
            continue
        out = bytearray()
        for j in range(nbytes):
            v = 0
            for k in range(8):
                v = (v << 1) | bits[j * 8 + k]
            out.append(v)
        raw_out = bytes(out)
        match = _FLAG_HINT.search(raw_out)
        if match:
            yield from _emit(ctx, match.group(0), "WAV LSB", {"plane": plane}, score=.9)
            continue
        cut = raw_out.find(b"\x00")
        text = raw_out[:cut] if cut > 4 else raw_out
        score, _ = assess(text)
        if best is None or score > best[0]:
            best = (score, text, plane)
    if best and best[0] >= .3:
        score, text, plane = best
        yield from _emit(ctx, text, "WAV LSB", {"plane": plane}, score=score)


# -------------------------------------------------------------- QR code ----
@solver("qr-code", lambda fp: .6 if fp.get("filetype") in filetypes.IMAGE_TYPES else 0.0)
def solve_qr(data, ctx):
    if _cv2 is None or _np is None:
        return
    try:
        arr = _np.frombuffer(data, dtype=_np.uint8)
        img = _cv2.imdecode(arr, _cv2.IMREAD_COLOR)
    except Exception:
        return
    if img is None:
        return
    try:
        detector = _cv2.QRCodeDetector()
    except Exception:
        return
    results = []
    try:
        ok, texts, *_rest = detector.detectAndDecodeMulti(img)
        if ok:
            results = [t for t in texts if t]
    except Exception:
        pass
    if not results:
        try:
            text, *_ = detector.detectAndDecode(img)
            results = [text] if text else []
        except Exception:
            results = []
    for text in results:
        yield from _emit(ctx, text.encode("utf-8", "replace"), "QR code", score=.9)


# -------------------------------------------------------- printable strings
@solver("binary-strings", lambda fp: .3 if fp["charset"] in ("binary", "mixed")
        and fp["length"] > 64 else 0.0)
def solve_strings(data, ctx):
    if ctx.depth > 0 or len(data) > 10_000_000:
        return
    found = _FLAG_HINT.findall(data)
    for match in dict.fromkeys(found[:5]):
        yield from _emit(ctx, match, "printable strings (flag-like)", score=.9)
    if not found:
        runs = re.findall(rb"[\x20-\x7e]{6,}", data)
        if runs:
            ctx.findings.append(f"{len(runs)} printable strings of 6+ chars found in the binary "
                                 f"(longest: {max(runs, key=len)[:80]!r}).")
