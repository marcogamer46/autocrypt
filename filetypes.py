"""Tiny dependency-free file-type sniffing shared by core and the stego solvers."""
from __future__ import annotations

IMAGE_TYPES = {"PNG image", "JPEG image", "GIF image", "BMP image", "WebP image"}

_HEAD = (
    (b"\x89PNG\r\n\x1a\n", "PNG image"), (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF87a", "GIF image"), (b"GIF89a", "GIF image"),
    (b"PK\x03\x04", "ZIP archive"), (b"PK\x05\x06", "ZIP archive"),
    (b"%PDF", "PDF document"), (b"7z\xbc\xaf\x27\x1c", "7z archive"),
    (b"Rar!\x1a\x07", "RAR archive"), (b"\x7fELF", "ELF executable"),
    (b"\xfd7zXZ\x00", "xz data"), (b"OggS", "Ogg audio"), (b"fLaC", "FLAC audio"),
    (b"ID3", "MP3 audio"), (b"SQLite format 3\x00", "SQLite database"),
)

# Signatures searched for anywhere inside a blob, to carve an embedded file
# out of a cover file (classic "file hidden inside a file" steganography).
EMBEDDED = (
    (b"PK\x03\x04", "ZIP archive"), (b"\x1f\x8b\x08", "gzip data"),
    (b"%PDF-", "PDF document"), (b"7z\xbc\xaf\x27\x1c", "7z archive"),
    (b"Rar!\x1a\x07", "RAR archive"), (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"GIF89a", "GIF image"), (b"GIF87a", "GIF image"),
    (b"\xff\xd8\xff\xe0", "JPEG image"), (b"\xff\xd8\xff\xe1", "JPEG image"),
    (b"\x7fELF", "ELF executable"), (b"BZh", "bzip2 data"),
    (b"\xfd7zXZ\x00", "xz data"),
)


def detect_filetype(data: bytes) -> str:
    head = data[:32]
    for sig, label in _HEAD:
        if head.startswith(sig):
            return label
    if head[:4] == b"RIFF" and head[8:12] == b"WAVE":
        return "WAV audio"
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "WebP image"
    if head[:2] == b"BM" and len(data) > 26:
        return "BMP image"
    if head[:2] == b"MZ" and len(data) > 64:
        return "PE executable"
    return ""
