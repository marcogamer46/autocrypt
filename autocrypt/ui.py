"""Interactive terminal UI for autocrypt; kept separate from search and solvers."""
from __future__ import annotations

import glob
import json
import os
import re
import shutil
import sys
import textwrap
import threading
import time
from pathlib import Path

from ._version import __version__ as VERSION
_ANSI = {"cyan": "\033[36m", "green": "\033[32m", "yellow": "\033[33m",
         "red": "\033[31m", "dim": "\033[90m", "reset": "\033[0m"}

def _width(): return max(1, shutil.get_terminal_size((80, 24)).columns)

# Set by autocrypt.py from the CLI: None = auto-detect (default), True/False
# = force on/off (e.g. `--no-color`). `--no-color` and the NO_COLOR env var
# always win over auto-detection.
COLOR_ENABLED = None

def _color_on():
    if COLOR_ENABLED is not None:
        return bool(COLOR_ENABLED)
    return bool(getattr(sys.stdout, "isatty", lambda: False)()) and "NO_COLOR" not in os.environ

def paint(text, color):
    return f"{_ANSI[color]}{text}{_ANSI['reset']}" if _color_on() else str(text)

def _safe(text):
    """Coerce text to something the console can encode; never raise on a
    legacy (e.g. cp1252) terminal even in non-color mode."""
    try:
        return str(text).encode(sys.stdout.encoding or "utf-8", "replace").decode(
            sys.stdout.encoding or "utf-8")
    except (LookupError, UnicodeEncodeError):
        return str(text)

def _unicode():
    try: "┌─│└─┘─┐░█".encode(getattr(sys.stdout, "encoding", None) or "utf-8"); return True
    except (LookupError, UnicodeEncodeError): return False

def _fit(text, width): return text[:max(0, width)]

def banner(width=None):
    width = max(1, width or _width())
    if width >= 40:
        art = [
            "  ______               __                 ______   _______  __      __  _______  ________",
            " /      \\             |  \\               /      \\ |       \\|  \\    /  \\|       \\|        \\",
            "|  $$$$$$\\ __    __  _| $$_     ______  |  $$$$$$\\| $$$$$$$\\\\$$\\  /  $$| $$$$$$$\\\\$$$$$$$$",
            "| $$__| $$|  \\  |  \\|   $$ \\   /      \\ | $$   \\$$| $$__| $$ \\$$\\/  $$ | $$__/ $$  | $$",
            "| $$    $$| $$  | $$ \\$$$$$$  |  $$$$$$\\| $$      | $$    $$  \\$$  $$  | $$    $$  | $$",
            "| $$$$$$$$| $$  | $$  | $$ __ | $$  | $$| $$   __ | $$$$$$$\\   \\$$$$   | $$$$$$$   | $$",
            "| $$  | $$| $$__/ $$  | $$|  \\| $$__/ $$| $$__/  \\| $$  | $$   | $$    | $$        | $$",
            "| $$  | $$ \\$$    $$   \\$$  $$ \\$$    $$ \\$$    $$| $$  | $$   | $$    | $$        | $$",
            " \\$$   \\$$  \\$$$$$$     \\$$$$   \\$$$$$$   \\$$$$$$  \\$$   \\$$    \\$$     \\$$         \\$$",
        ]
    else:
        art = ["autocrypt"]
    tag = f"autocrypt {VERSION}"
    tag = tag.encode("ascii", "replace").decode("ascii")
    lines = [_fit(line, width) for line in art]
    lines.extend(_fit(line, width) for line in textwrap.wrap(tag, width=max(1, width)))
    return "\n".join(paint(line, "cyan") for line in lines)

def confidence_bar(value, width=10):
    value = max(0.0, min(1.0, float(value)))
    filled = round(value * width)
    glyphs = ("█", "░") if _unicode() else ("#", ".")
    bar = f"[{glyphs[0] * filled}{glyphs[1] * (width - filled)}] {value:.2f}"
    color = "green" if value >= .75 else "yellow" if value >= .4 else "red"
    return paint(bar, color)

def _wrap_lines(lines, width):
    output = []
    for line in lines:
        if not line:
            output.append("")
        else:
            output.extend(textwrap.wrap(str(line), width=max(1, width),
                                        break_long_words=True, break_on_hyphens=False) or [""])
    return output

def box(title, lines, width=None, color="cyan"):
    width = max(1, width or _width())
    inner = max(1, width - 4)
    contents = _wrap_lines(lines, inner)
    if width < 6:
        return "\n".join(_fit(s, width) for s in [title, *contents])
    if _unicode():
        top, side, bottom = "┌", "│", "└"
        horiz = "─"
    else:
        top, side, bottom = "+", "|", "+"
        horiz = "-"
    head = f"{top}{horiz} {title} "
    head = head + horiz * max(0, width - len(head) - 1) + ("┐" if _unicode() else "+")
    rows = [head[:width]]
    rows.extend(f"{side} {line:<{inner}} {side}" for line in contents)
    rows.append(f"{bottom}{horiz * (width - 2)}" + ("┘" if _unicode() else "+"))
    return "\n".join(paint(row, color) for row in rows)

def fingerprint_panel(fp, width=None):
    encodings = ", ".join(f"{name} {prior:.2f}" for name, prior in fp["hypotheses"]) or "none detected"
    return box("Fingerprint", [
        f"Length: {fp['length']} bytes   Entropy: {fp['entropy']:.3f} bits/byte",
        f"Charset: {fp['charset']}   IC: {fp['ic']:.4f}",
        "Detected encodings (prior): " + encodings,
        *(["Tells: " + ", ".join(fp["magic"])] if fp["magic"] else []),
        *(["Hash hints: " + ", ".join(fp["hashes"])] if fp["hashes"] else []),
    ], width)

def empty_panel(status, width=None):
    messages = {
        "TIMEOUT": ("Timed out", "Time budget expired before a result was recovered."),
        "TOO_SHORT": ("Input too short to judge", "Not enough text for reliable statistical evidence."),
        "SOLVER_FAILED": ("Solver failed", "A solver failed or was cut short, so this result is unreliable"),
        "NOT_FOUND": ("No weakness found", "Looks like properly encrypted or random data."),
    }
    title, message = messages.get(status, messages["NOT_FOUND"])
    color = "yellow" if status in ("TIMEOUT", "TOO_SHORT", "SOLVER_FAILED") else "green"
    return box(title, [message], width, color)

def verdict_banner(results):
    """A one-line headline verdict for the ranked results."""
    if not results:
        return ""
    top = results[0]
    conf = top.get("confidence", 0.0)
    plain = str(top.get("plaintext", "")).strip()
    if top.get("is_flag") and conf >= 0.80:
        msg = "Flag-like result at rank 1 (confidence {:.2f})".format(conf)
        if plain and len(plain) <= 200 and "\n" not in plain:
            return _safe(paint(msg + "\n" + plain, "green"))
        return _safe(paint(msg, "green"))
    if conf >= 0.80:
        return _safe(paint("Best guess at rank 1 (confidence {:.2f})".format(conf), "yellow"))
    return _safe(paint("Low-confidence candidates only - treat with caution.", "yellow"))

def results_panel(results, width=None, preview_boxes=3):
    width = max(1, width or _width())
    lines, plaintext_boxes = [], []
    for rank, item in enumerate(results, 1):
        badge = paint(" FLAG", "green") if item.get("is_flag") else ""
        lines.append(f"#{rank} {confidence_bar(item.get('confidence', 0))}{badge}")
        lines.extend("  " + part for part in _wrap_lines(
            ["Chain: " + item.get("chain", "")], max(1, width - 4)))
        reason = item.get("_reason", "")
        if reason:
            color = ("yellow" if reason.startswith(("LOW CONFIDENCE", "Partial solve:"))
                     else "dim")
            lines.extend("  " + paint(part, color) for part in _wrap_lines([reason], max(1, width - 4)))
        plain = str(item.get("plaintext", ""))
        shown = plain[:2400]
        chunks = _wrap_lines(shown.splitlines() or [""], max(1, width - 6))
        if len(plain) > len(shown):
            chunks.append("[preview truncated; save results for full plaintext]")
        plaintext_boxes.append(box(f"Plaintext #{rank}", chunks, width, "cyan"))
    sections = [box(f"Ranked results ({len(results)})", lines, width, "cyan")]
    # By default only preview the top few full plaintexts; the summaries above
    # always list every rank, and "save" writes all of them regardless.
    sections.extend(plaintext_boxes[:max(1, preview_boxes)])
    if len(plaintext_boxes) > max(1, preview_boxes):
        sections.append(paint(f"(... {len(plaintext_boxes) - max(1, preview_boxes)} more plaintexts; "
                              "use save to write them all)", "dim"))
    # A higher timeout budget can surface additional lower-ranked candidates
    # (best-first search runs more solvers) — never changes the top result.
    sections.append(paint("Raising the timeout may reveal more lower-ranked candidates "
                          "(never changes the top).", "dim"))
    return "\n".join(sections)

def _valid_regex(pattern):
    try: re.compile(pattern, re.DOTALL); return True, ""
    except re.error as exc: return False, str(exc)

def _tab_completion():
    try:
        import readline; readline.set_completer(lambda t, s: (lambda m: m[s] if s < len(m) else None)(glob.glob(t + "*"))); readline.parse_and_bind("tab: complete")
    except (ImportError, AttributeError): pass

def _settings(settings):
    while True:
        print(box("Settings", [
            f"1. Flag format: {settings['flag_format']}",
            f"2. Timeout: {settings['timeout']} seconds",
            f"3. Top-N: {settings['top']}",
            f"4. Known-plaintext crib: {settings['known_plaintext'] or '(none)'}",
            f"5. Wordlist: {settings['wordlist'] or '(none)'}",
            f"6. Cipher key: {settings['key'] or '(blank = auto-crack)'}",
            "0. Back",
        ]))
        try:
            choice = input("Change setting: ").strip().lower()
        except EOFError:
            return False
        if choice in ("0", "b", "back"):
            return True
        try:
            if choice in ("1", "f"):
                value = input("Flag regex: ")
                valid, error = _valid_regex(value)
                if not valid:
                    print(paint(f"Invalid regex: {error}", "red"))
                else:
                    settings["flag_format"] = value
                    settings["flag_format_explicit"] = True
            elif choice in ("2", "t"):
                value = float(input("Timeout seconds: "))
                if value <= 0:
                    raise ValueError("timeout must be positive")
                settings["timeout"] = value
            elif choice in ("3", "n"):
                value = int(input("Top-N: "))
                if value < 0:
                    raise ValueError("top-N must be nonnegative")
                settings["top"] = value
            elif choice in ("4", "k"):
                settings["known_plaintext"] = input("Known plaintext (empty clears): ")
            elif choice in ("5", "w"):
                settings["wordlist"] = input("Wordlist path (empty clears): ").strip()
            elif choice in ("6", "key"):
                settings["key"] = input("Cipher key (empty clears): ").strip()
            else:
                print(paint("Choose 0–6.", "yellow"))
        except (ValueError, EOFError) as exc:
            if isinstance(exc, EOFError): return False
            print(paint(f"Invalid value: {exc}", "red"))

_HELP = {
    "base16": ("Hex bytes", "48656c6c6f"), "base32": ("RFC 4648 base32", "JBSWY3DP"),
    "base64": ("Base64/base64url", "SGVsbG8="), "base58": ("Bitcoin base58", "JxF12TrwUP45BMd"),
    "base85": ("Base85/ASCII85", "NM&qn"), "url": ("Percent URL encoding", "hello%20world"),
    "binary": ("Eight-bit binary bytes", "01001000 01101001"), "octal": ("Octal byte values", "110 145 154"),
    "decimal": ("Decimal byte values", "72 101 108"), "morse": ("Morse letters/words", ".... . .-.. .-.. ---"),
    "quoted-printable": ("Quoted-printable bytes", "hello=20world"), "a1z26": ("A1Z26 mapping", "8-5-12-12-15"),
    "bacon": ("Bacon A/B groups", "AABBA ABBAA"), "polybius": ("Polybius coordinate pairs", "23 15"),
    "PEM": ("PEM body/base64 extraction", "-----BEGIN PUBLIC KEY-----"), "zlib/gzip": ("Decompress gzip/zlib streams (magic 1f8b / 78)", "789ccb48cdc9c90700062c0215"),
    "reverse": ("Reverse text", "!dlrow olleH"), "caesar": ("All Caesar shifts", "synt{...}"),
    "ROT13": ("ROT13 transformation", "synt{...}"), "ROT47": ("Printable-ASCII ROT47", "w6==@"),
    "atbash": ("Alphabet reversal", "zgyzhs"), "affine": ("Brute-force affine keys", "Ihhwvc swfrcpu"),
    "vigenere-family": ("Vigenere/Beaufort variants", "ciphertext; optional crib"),
    "autokey": ("Autokey, optionally cribbed", "ciphertext + known plaintext"),
    "rail-fence": ("Rail-fence transposition", "Wrivdlaneaedsoee"), "scytale": ("Scytale (route) transposition", "acdtkatawatn"),
    "columnar-transposition": ("Columnar transposition", "TCTWTKDNAAAA"),
    "monoalphabetic-substitution": ("Monoalphabetic substitution (hill-climb)", "gtm psalw jvbxh ybz iseuf bqmv gtm cnor kbd"),
    "playfair": ("Playfair square hill-climb", "BMODZBXDNABEKUDMUIXMMOUVIFABCDEFGHIJKLMNOP"),
    "xor-single-byte": ("Single-byte XOR", "BOFFE"),
    "xor-repeating": ("Repeating-key XOR", "1e2b2027... (hex bytes)"),
    "known-plaintext-XOR": ("XOR crib recovery", "ciphertext + --known-plaintext"),
    "many-time-pad": ("Crib-drag multiple hex ciphertexts", "hex-cipher-1\\nhex-cipher-2"),
    "JWT": ("Decode JWT; try none/HS256 wordlist", "header.payload.signature"),
    "hash-identification": ("Identify/crack hash with wordlist", "5ebe2294ecd0e0f08eab7690d2a6ee69"),
    "RSA": ("Small-e, factoring, related attacks (optional p/q/d)", "n=...,e=3,c=..."),
}

_HELP.update({
    "3des-key": ("Triple-DES with a known key", "key=... hex ciphertext"),
    "RSA-dp-leak": ("RSA dp/dq leak to factor n", "n=..., c=..., dp=..."),
    "RSA-extra": ("RSA extra-information attacks", "n=..., e=..., c=..., extra bits"),
    "RSA-related-message": ("RSA related-message (Franklin-Reiter)", "two (n,c) pairs, related m"),
    "RSA-shared-prime": ("RSA shared-prime gcd(n_i,n_j)", "n1=..., n2=..., c1=..., c2=..."),
    "RSA-sum-leak": ("RSA p+q leak", "n=..., s=p+q, c=..."),
    "a1z26-hex": ("A1Z26 hex index values", "08 05 0c 0c 0f"),
    "adfgvx": ("ADFGVX cipher", "ADFGVX pairs + key square"),
    "aes-key": ("AES-CBC/CTR with a provided key", "key=... iv=... hex ciphertext"),
    "aes-known-key": ("AES decrypt with known key+mode", "key hex + IV hex + ciphertext"),
    "appended-data": ("Extract trailing/appended bytes", "file with a hidden tail"),
    "b16-shift-vigenere": ("Base16 + shift-vigenere combo", "hex text + vigenere shift"),
    "base-variants": ("Decode base32/base64 variants (base32hex, Crockford, swapcase/reversed base64)", "mixed base32hex or case-shifted base64 text"),
    "base36": ("Base36 decode", "zz12abc"),
    "base36-caesar": ("Base36 + Caesar double encode", "base36 digits then letter shift"),
    "base45": ("Base45 decode", "GG%UTJ"),
    "base62": ("Base62 decode", "7Rjk3q"),
    "base91": ("Base91 decode", "RJ0DWi0"),
    "base92": ("Base92 decode", "X=~!w"),
    "baudot-ita2": ("Baudot/ITA2 decode", "5-bit codes or symbol shells"),
    "beaufort": ("Beaufort cipher", "ciphertext in plain letters"),
    "bifid": ("Bifid cipher", "polybius-encoded text"),
    "binary-strings": ("Extract printable string runs / flag-like text embedded in binary data", "binary blob containing readable text"),
    "block-transposition": ("Block transposition", "text reordered in blocks"),
    "blowfish-key": ("Blowfish with a known key", "key=... hex ciphertext"),
    "braille": ("Braille six-bit encoding", "⠓⠕⠕⠕⠙"),
    "brainfuck": ("Brainfuck interpreter", "+[----->+++<]>++.+."),
    "byte-transforms": ("Byte rol/ror/add/sub transforms", "binary blob; transform guessing"),
    "bytes-literal": ("Python bytes literal parse", "b'\x48\x69'"),
    "carved-file": ("Carve an embedded file signature", "header magic + trailer"),
    "chacha20-key": ("ChaCha20 with known key/nonce", "key hex + nonce + ciphertext"),
    "columnar-brute": ("Columnar transposition brute force", "transposed text; key search"),
    "crt": ("Chinese Remainder Theorem combine", "congruences x mod m"),
    "custom-alphabet-base": ("Custom-alphabet base decode", "alphabet string + value"),
    "decimal-ascii": ("Decimal ASCII codes", "72 101 108 108 111"),
    "des-key": ("DES with a known key", "key=... hex ciphertext"),
    "dh-dlp": ("Diffie-Hellman discrete log", "g, p, A, B"),
    "diffie-hellman-xor": ("DH + XOR keystream", "g, p, public, XORed ciphertext"),
    "discrete-log": ("Discrete log g^x=h mod p", "g=..., p=..., h=..."),
    "dlp-composite-smooth": ("DLP with smooth composite modulus", "g, h, n with small factors"),
    "dna-2bit": ("DNA 2-bit encoding", "ACGT sequence"),
    "docx-text": ("DOCX text extraction", "package zip bytes"),
    "dsa-nonce-reuse": ("Recover DSA private key from nonce (k) reuse", "q=... r=... s1=... s2=... h1=... h2=..."),
    "ebcdic": ("EBCDIC decode", "EBCDIC bytes to ASCII"),
    "ecb-detect": ("Detect ECB repeated blocks", "16-byte block repeats"),
    "ecb-repeated-blocks": ("ECB repeated-block analysis", "ciphertext 16-byte blocks"),
    "ecdlp": ("Elliptic-curve DLP small order", "curve params + point"),
    "ecdsa-nonce-reuse": ("ECDSA k-reuse to private key", "(r,s) pairs"),
    "elliptic-curve-dlog": ("Elliptic-curve discrete log", "p, a, b, G, Q"),
    "enigma-m3": ("Enigma M3 settings", "rotors + plugboard ciphertext"),
    "extra-encodings": ("Miscellaneous encodings", "unusual encoded text"),
    "fernet-key": ("Fernet token with key", "key + token"),
    "flag-body-decode": ("Decode a flag body payload", "flag{...} inner encoding"),
    "four-square": ("Four-square cipher over built-in key squares", "ciphertext letters only (e.g. XKQYWVBLCDPG)"),
    "franklin-reiter": ("Franklin-Reiter related messages", "two ciphertexts, same n"),
    "gray-code": ("Gray-code decode", "gray bitstring"),
    "gronsfeld": ("Gronsfeld cipher (numeric key recovered automatically)", "ciphertext letters only"),
    "hash-crack": ("Identify/crack a hash with wordlist", "md5/sha1 hash hex"),
    "hex+rot13": ("Hex then ROT13", "hex bytes -> ROT13 text"),
    "hex-in-text": ("Hex tokens inside text", "text with 0xff.. tokens"),
    "hex-le": ("Little-endian hex bytes", "DE AD BE EF reversed"),
    "hill-2x2": ("Hill cipher 2x2 (key brute-forced)", "ciphertext letters only (even length)"),
    "hill3-crib": ("Hill 3x3 with crib", "9-letter known plaintext"),
    "hint-caesar": ("Caesar decrypt using an explicit shift marker", "shift=13\nfrperg"),
    "hint-keystream-xor": ("Keystream XOR using a provided keystream marker", "keystream_hex=0x..\nct=0x.."),
    "hint-secret-xor": ("Repeating-key XOR using a hint secret marker", "secret_bytes=0x..\nct=0x.."),
    "hint-vigenere": ("Vigenere decrypt using the key_bytes marker", "key_bytes=0x6c656d6f6e\n(hex ciphertext)"),
    "html-entities": ("HTML entity decode", "&#72;&#105;"),
    "image-metadata": ("Image EXIF/metadata extraction (flag-like strings found in metadata)", "full PNG/JPEG image"),
    "integer-to-bytes": ("Integer/bigint to bytes", "large decimal int"),
    "keyboard-shift": ("Keyboard-layout shift", "shifted-typing text"),
    "lcg-recover": ("LCG parameter recovery", ">=6 consecutive outputs"),
    "lcg-recovery": ("LCG recovery", "consecutive outputs"),
    "lfsr-known-fields": ("LFSR with known taps/init", "ciphertext + fields"),
    "lfsr-known-plaintext": ("LFSR keystream from plaintext", "ciphertext + known PT"),
    "linear-recurrence-hash-xor": ("G2-style Python source: linear recurrence + hash + XOR-decrypt flag", "challenge source with ENCRYPTED_FLAG"),
    "lsb-steganography": ("LSB steganography in PNG images", "PNG image bytes"),
    "merkle-hellman": ("Merkle-Hellman knapsack", "pubkey + ciphertext"),
    "mt19937-predict": ("MT19937 state recovery", "624 consecutive 32-bit outputs"),
    "multi-base64": ("Nested base64 layers", "repeated Base64"),
    "nato-phonetic": ("NATO phonetic-alphabet decode", "Alpha Bravo Charlie Delta Echo"),
    "new-caesar-b16": ("New-Caesar b16 (shift over 16-letter alphabet)", "abcdefghijklmnop"),
    "nihilist": ("Nihilist cipher (Polybius + additive key)", "342 568 432 678 123 456"),
    "ook": ("Ook! esolang decode (to brainfuck)", "Ook. Ook. Ook! Ook?"),
    "pdf-text": ("PDF text extraction", "PDF stream bytes"),
    "porta": ("Porta cipher (recovers key)", "HPMSSGRJPLQGPRQGO"),
    "punycode": ("Punycode/IDN hostname decode", "xn--bcher-kva"),
    "qr-code": ("QR code decode", "QR image bytes"),
    "radix-ascii": ("Interpret numbers in any base (2..36) as ASCII bytes", "72 101 108 108 111"),
    "rc4": ("RC4 with candidate key", "key guess + ciphertext"),
    "rc4-key": ("RC4 given key", "key=... ciphertext"),
    "reverse-each-word": ("Reverse letters per word", "olleh dlrow"),
    "reverse-words": ("Reverse word order", "world hello"),
    "reversed-text": ("Overall text reversal", "!dlrow olleH"),
    "rot-n-brute": ("Brute-force all ROT-N shifts", "Uryyb Jbeyq"),
    "rot18": ("ROT18 (ROT13 letters + ROT5 digits)", "Uryyb 12345"),
    "rot5": ("ROT5 digits", "12345 -> 67890"),
    "rsa-dp-dq-leak": ("RSA dp/dq CRT leak", "p, dp, dq, c"),
    "sample-keystream-xor": ("Sample keystream XOR", "keystream snippet + ciphertext"),
    "straddling-checkerboard": ("Straddling checkerboard", "digit rows; ciphertext"),
    "substitution-wordlist": ("Substitution with wordlist", "ciphertext + dictionary"),
    "t9-phone": ("Decode T9 multi-tap phone keypad numbers", "44 33 555 555 666"),
    "tap-code": ("Decode tap code (Polybius 5x5) from digit pairs", "12 15 31 24"),
    "trifid": ("Crack Trifid cipher (cube auto-guessed)", "ciphertext letters only"),
    "two-symbol-binary": ("Two-symbol encoding", "AB AAB ABB..."),
    "unicode-escapes": ("Decode Unicode escape sequences (\\u, \\x, %u, &#…)", "\\u0048\\u0069"),
    "uuencode": ("uuencode decode", "begin ... end"),
    "vigenere-brute": ("Vigenere IC brute force", "30+ letters"),
    "vigenere-dictionary": ("Vigenere with a dictionary-searched key", "ciphertext (dictionary key searched)"),
    "wav-lsb": ("WAV LSB stego", "WAV PCM samples"),
    "whitespace-stego": ("Zero-width/whitespace stego", "invisible chars"),
    "xor-literal-pads": ("XOR literal pad guessing", "ciphertext + pad strings"),
    "xor-short": ("Short repeating-key XOR", "short key guess"),
    "z85": ("Z85 (ZeroMQ) decode", "Z85 symbol stream"),
    "zip-archive": ("ZIP archive listing/extract", "PK.. archive bytes"),
})

def _help():
    import autocrypt.solvers
    from autocrypt.core import REGISTRY
    lines = (f"{x.name}: {d} Example: {e}" for x in REGISTRY
             for d, e in [_HELP.get(x.name, ("Registered solver.", "unknown ciphertext"))])
    print(box("Solver help", list(lines), color="cyan"))

def _save(results):
    try:
        path = input("Save path (.txt or .json): ").strip()
    except EOFError:
        return
    if not path:
        return
    public = [{k: row[k] for k in ("chain", "plaintext", "confidence", "is_flag")}
              for row in results]
    try:
        out = Path(path).expanduser()
        # Auto-create missing parent directories instead of failing.
        if out.parent and not out.parent.exists():
            try:
                out.parent.mkdir(parents=True, exist_ok=True)
            except OSError:
                pass  # surfaced below by write_text
        if out.suffix.lower() == ".json":
            out.write_text(json.dumps(public, ensure_ascii=False, indent=2) + "\n",
                           encoding="utf-8")
        else:
            text = "\n\n".join(
                f"{i}. {row['chain']}\nConfidence: {row['confidence']:.2f}"
                f"{' FLAG' if row['is_flag'] else ''}\n{row['plaintext']}"
                for i, row in enumerate(results, 1))
            out.write_text(text + "\n", encoding="utf-8")
        print(paint(f"Saved full results to {path}", "green"))
    except OSError as exc:
        print(paint(f"Could not save: {exc}", "red"))

def _solve(data, settings, params=""):
    import autocrypt
    from autocrypt.failures import DEFAULT_FILE
    active = ["starting"]
    stop = threading.Event()
    tty = bool(getattr(sys.stdout, "isatty", lambda: False)())

    def progress(name):
        active[0] = name or "searching"

    def animate():
        start = time.monotonic()
        frames = "|/-\\"
        i = 0
        while not stop.wait(.12):
            raw = f" {frames[i % 4]} Solving: {active[0]}  {time.monotonic() - start:5.1f}s"
            sys.stdout.write("\r" + paint(_fit(raw, _width()), "cyan"))
            sys.stdout.flush()
            i += 1

    thread = None
    if tty:
        thread = threading.Thread(target=animate, daemon=True)
        thread.start()
    try:
        return autocrypt.solve_data(
            data, flag_format=settings["flag_format"], timeout=settings["timeout"],
            top=settings["top"], known_plaintext=settings["known_plaintext"],
            wordlist_path=settings["wordlist"], params=params,
            progress_callback=progress, flag_format_explicit=settings["flag_format_explicit"],
            key=settings.get("key", ""),
            failure_log_path=DEFAULT_FILE,
        )
    finally:
        if thread:
            stop.set()
            thread.join()
            sys.stdout.write("\r" + " " * _width() + "\r")
            sys.stdout.flush()

def _show(data, settings, params=""):
    _t0 = time.monotonic()
    fp, results, ctx = _solve(data, settings, params)
    _elapsed = time.monotonic() - _t0
    print(fingerprint_panel(fp))
    verdict = verdict_banner(results)
    if verdict:
        print(verdict)
    print("\n".join(paint("Finding: " + f, "yellow") for f in dict.fromkeys(ctx.findings)))
    print("\n".join(paint("Solver failure: " + f, "red") for f in dict.fromkeys(ctx.failures)))
    if results:
        print(results_panel(results))
        # Phase 7: for RSA recoveries, also show the raw bytes as hex/byte
        # counts so non-printable or binary plaintexts are still inspectable.
        for r in results:
            if r.get("chain", "").startswith("RSA"):
                pt = r.get("plaintext", "")
                try:
                    raw = pt.encode("utf-8", "replace")
                except Exception:
                    raw = b""
                if raw:
                    print(paint(f"  RSA bytes ({len(raw)}): {raw.hex()}", "dim"))
    else:
        print(empty_panel(results.status))
    print(paint(f"Solved in {_elapsed:.1f}s (budget {settings['timeout']:.0f}s).", "dim"))
    return results

def _paste():
    print(paint("Paste ciphertext; finish with an empty line or Ctrl-D.", "dim"))
    lines = []
    while True:
        try:
            line = input()
        except EOFError: break
        if not line: break
        lines.append(line)
    return "\n".join(lines).encode("utf-8")

def _rsa_num(prompt, required):
    """Read one RSA numeric field as a decimal string. Auto-detects hex: a
    value is hex if it starts with 0x or contains any [a-f] hex digit (decimal
    cannot contain those); otherwise it is taken as decimal."""
    while True:
        v = input(prompt).strip().replace(" ", "").replace("_", "")
        if not v:
            if required:
                print(paint("Required.", "yellow"))
                continue
            return ""
        try:
            if v.lower().startswith("0x"):
                return str(int(v, 16))
            if any(c in "abcdefABCDEF" for c in v) and all(
                    c in "0123456789abcdefABCDEF" for c in v):
                return str(int(v, 16))
            int(v, 10)  # validate decimal
            return v
        except ValueError:
            print(paint(f"Not a valid number: {v}", "red"))


_RSA_KEY_ALIASES = {
    "modulus": "n", "exponent": "e",
    "cyphertext": "c", "ciphertext": "c", "cypher": "c", "cipher": "c",
    "encrypted": "c", "message": "c", "msg": "c", "ct": "c", "enc": "c",
    "priv": "d", "private": "d", "private_exponent": "d",
}


def _rsa_value_to_decimal(v):
    """Validate/normalize one RSA value as a decimal string (auto-detects hex:
    0x prefix or any [a-f] digit implies hex). Returns '' when unusable."""
    v = v.strip().replace(" ", "").replace("_", "")
    if not v:
        return ""
    try:
        if v.lower().startswith("0x"):
            return str(int(v, 16))
        if any(c in "abcdefABCDEF" for c in v) and all(
                c in "0123456789abcdefABCDEF" for c in v):
            return str(int(v, 16))
        int(v, 10)
        return v
    except ValueError:
        return ""


def _parse_rsa_spec(text):
    """Parse n/e/c/p/q/d key=value pairs from multi-line / comma / semicolon
    text (labels may be separated by '=' or ':'; keys are case-insensitive and
    common aliases like modulus/exponent/ciphertext/priv are accepted).
    Returns (fields, unrecognized): fields maps each key to its decimal-string
    value; unrecognized lists the lines that could not be parsed."""
    fields = {}
    unknown = []
    for raw in re.split(r"[\n,;]+", text):
        line = raw.strip()
        if not line:
            continue
        m = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)\s*[:=]\s*(.+)", line)
        if not m:
            unknown.append(line)
            continue
        key = m.group(1).lower()
        k = _RSA_KEY_ALIASES.get(key, key)
        if k in ("n", "e", "c", "p", "q", "d"):
            dv = _rsa_value_to_decimal(m.group(2))
            if dv:
                fields[k] = dv
            else:
                unknown.append(line)
        else:
            unknown.append(line)
    return fields, unknown


def _rsa_input():
    """Phase 7 RSA mode: paste a labeled spec (multi-line or comma-separated:
    n=..., e=..., c=..., optional p=..., q=..., d=...). Missing required fields
    are prompted for individually; hex is auto-detected. Returns (spec, data)
    where data == spec.encode(), or (None, None) on an empty input (cancel)."""
    print(paint(
        "RSA mode — paste parameters as n=..., e=..., c=... lines "
        "(optional p=..., q=..., d=...). Finish with a blank line.", "dim"))
    lines = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        if not line.strip():
            break
        lines.append(line)
    text = "\n".join(lines)
    if not text.strip():
        print(paint("No input; returning to the menu.", "yellow"))
        return None, None
    fields, unknown = _parse_rsa_spec(text)
    for u in unknown:
        print(paint(f"Unrecognized/unusable line (skipped): {u!r}", "red"))

    # Required: n and c; and at least one of e or d.
    if "n" not in fields:
        v = _rsa_num("n: ", True)
        if v:
            fields["n"] = v
    if "c" not in fields:
        v = _rsa_num("c: ", True)
        if v:
            fields["c"] = v
    if "e" not in fields and "d" not in fields:
        v = _rsa_num("e: (or provide d) ", False)
        if v:
            fields["e"] = v
        elif "d" not in fields:
            print(paint("Need either e or d to decrypt.", "red"))
            return None, None

    # Optional p/q/d — only prompt for ones not already pasted.
    if "p" not in fields:
        v = _rsa_num("p: (blank to skip) ", False)
        if v:
            fields["p"] = v
    if "q" not in fields:
        v = _rsa_num("q: (blank to skip) ", False)
        if v:
            fields["q"] = v
    if "d" not in fields:
        v = _rsa_num("d: (blank to skip) ", False)
        if v:
            fields["d"] = v

    echo = [f"{k}=<{len(fields[k])} digits>" for k in ("n", "e", "c", "p", "q", "d") if k in fields]
    print(paint("Parsed RSA parameters: " + ", ".join(echo), "green"))
    spec = ",".join(f"{k}={fields[k]}" for k in ("n", "e", "c", "p", "q", "d") if k in fields)
    return spec, spec.encode()

def _post_solve(results, settings):
    while True:
        print(paint("What next? [1] solve  [2] re-run top  [3] save  [4] settings  [5] quit", "dim"))
        try:
            choice = input("> ").strip().lower()
        except EOFError:
            return "quit"
        if choice in ("1", "s", "solve"):
            return "menu"
        if choice in ("2", "r", "rerun"):
            return ("rerun", results[0]["plaintext"].encode("utf-8")) if results else "menu"
        if choice in ("3", "w", "save"):
            _save(results)
        elif choice in ("4", "c", "settings"):
            if not _settings(settings):
                return "quit"
        elif choice in ("5", "q", "quit"):
            return "quit"
        else:
            print(paint("Choose 1–5.", "yellow"))

def interactive():
    if os.name == "nt":
        try:
            os.system("")
            import colorama
            colorama.just_fix_windows_console()
        except (ImportError, AttributeError):
            pass
    settings = {"flag_format": r"\w{1,40}\{.*?\}", "flag_format_explicit": False, "timeout": 20.0,
                "top": 5, "known_plaintext": "", "wordlist": "", "key": ""}
    last = {}
    print(banner())
    _tab_completion()
    while True:
        print(box("Main menu", [
            "1. Paste ciphertext", "2. Load from file", "3. RSA mode (paste n,e,c)",
            "4. Settings", "5. Help", "6. Quit"]))
        try:
            choice = input("Select 1–6 (or a letter): ").strip().lower()
        except EOFError:
            return 0
        except KeyboardInterrupt:
            try:
                quit_now = input("\nQuit autocrypt? [y/N] ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                return 0
            if quit_now in ("y", "yes"):
                return 0
            continue
        try:
            params = ""
            if choice in ("1", "p"):
                data = _paste()
                # Phase 5: optional cipher key (blank = auto-crack). Persists in
                # settings until changed, so it can also be set via the menu.
                try:
                    key_in = input("Optional cipher key (blank = auto-crack): ").strip()
                    if key_in:
                        settings["key"] = key_in
                except EOFError:
                    pass
                last.update(notes=[], source="")
            elif choice in ("2", "f"):
                import shlex
                import autocrypt.challenge as challenge
                raw = input("File path(s) — data .txt and/or challenge .py (space-separated): ").strip()
                try:
                    data, notes, source = challenge.load(shlex.split(raw))
                except (OSError, ValueError) as exc:
                    print(paint(f"Cannot load file: {exc}", "red"))
                    continue
                last.update(notes=notes, source=source)
                for n in notes:
                    print(paint("Challenge: " + n, "yellow"))
            elif choice in ("3", "r"):
                params, data = _rsa_input()
                if data is None:
                    continue
            elif choice in ("4", "s"):
                if not _settings(settings):
                    return 0
                continue
            elif choice in ("5", "h"):
                _help()
                continue
            elif choice in ("6", "q"):
                return 0
            else:
                print(paint("Choose 1–6.", "yellow"))
                continue
            while True:
                try:
                    results = _show(data, settings, params)
                    last.update(data=data, results=results)
                except KeyboardInterrupt:
                    print(paint("\nSolve cancelled; returning to the menu.", "yellow"))
                    break
                action = _post_solve(results, settings)
                if action == "quit":
                    return 0
                if action == "menu":
                    break
                _, data = "rerun", action[1]
                params = ""
        except EOFError:
            return 0
        except KeyboardInterrupt:
            print(paint("\nCancelled; returning to the menu.", "yellow"))
        except Exception as exc:
            print(paint(f"Error: {exc}", "red"))
