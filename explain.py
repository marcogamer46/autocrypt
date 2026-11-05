"""Human-readable chain explanations for the ``--explain`` flag.

Maps each layer of a recovery chain (a ``" -> "``-joined string of solver
names, e.g. ``base64 -> caesar(shift=7)``) to a short plain-English sentence.
Unknown solvers fall back to a generic "decoded with X" phrasing so the tool
never crashes on a solver it does not know.
"""
import re


def _strip(tok: str) -> str:
    """Remove a trailing parenthesized parameter block, e.g. 'caesar(shift=7)'."""
    return re.split(r"\(", tok, 1)[0].strip()


# base name -> (one-line description template, uses-key?)
# {k}/{v} are filled from parameters when present.
_KNOWN = {
    "as-is": ("the input was already readable/flag-shaped", False),
    "base64": ("Base64-decoded (one of the standard encodings)", False),
    "base64url": ("Base64url-decoded (URL-safe alphabet)", False),
    "base32": ("Base32-decoded", False),
    "base16": ("Base16/hex-decoded", False),
    "base36": ("Base36-decoded", False),
    "base58": ("Base58-decoded", False),
    "base62": ("Base62-decoded", False),
    "base85": ("Base85/Ascii85-decoded", False),
    "base91": ("Base91-decoded", False),
    "base92": ("Base92-decoded", False),
    "multi-base64": ("layered Base64-decoded", False),
    "z85": ("ZeroMQ Z85-decoded", False),
    "binary": ("raw binary bytes interpreted as text", False),
    "octal": ("octal (base-8) escapes decoded", False),
    "decimal": ("decimal byte values decoded", False),
    "decimal-ascii": ("decimal ASCII codes decoded to characters", False),
    "hex-in-text": ("a hex string embedded in the text was decoded", False),
    "hex-le": ("little-endian hex decoded", False),
    "radix-ascii": ("radix-encoded ASCII decoded", False),
    "a1z26": ("A1Z26 (numbers-as-letters) decoded", False),
    "a1z26-hex": ("A1Z26 over hex digits decoded", False),
    "url": ("URL-percent-decoded", False),
    "quoted-printable": ("quoted-printable decoded", False),
    "html-entities": ("HTML entities decoded", False),
    "unicode-escapes": ("Unicode escapes (\\u/\\x) decoded", False),
    "punycode": ("Punycode-decoded", False),
    "uuencode": ("uuencoded data decoded", False),
    "morse": ("Morse code decoded", False),
    "ook": ("on-off keying (OOK / binary Morse) decoded", False),
    "braille": ("Braille cells decoded to text", False),
    "dna-2bit": ("DNA-codon 2-bit encoding decoded", False),
    "two-symbol-binary": ("two-symbol alphabet decoded as binary", False),
    "binary-strings": ("binary strings decoded to text", False),
    "nato-phonetic": ("NATO phonetic alphabet decoded", False),
    "tap-code": ("tap code decoded", False),
    "t9-phone": ("T9 phone keypad decoded", False),
    "bacon": ("Bacon's cipher decoded", False),
    "gray-code": ("Gray code decoded", False),
    "keyboard-shift": ("keyboard adjacent-key shift corrected", False),
    "whitespace-stego": ("whitespace steganography decoded", False),
    "bytes-literal": ("Python bytes literal parsed", False),
    "custom-alphabet-base": ("custom-alphabet base decoded", False),
    "extra-encodings": ("an extra encoding variant decoded", False),
    "integer-to-bytes": ("large integer converted to bytes", False),
    "carved-file": ("an embedded file was carved out", False),
    "zip-archive": ("ZIP archive extracted", False),
    "zlib/gzip": ("zlib/gzip decompressed", False),
    "pdf-text": ("text extracted from a PDF", False),
    "docx-text": ("text extracted from a DOCX document", False),
    "image-metadata": ("metadata read from an image", False),
    "qr-code": ("QR code decoded", False),
    "lsb-steganography": ("LSB steganography extracted", False),
    "wav-lsb": ("LSB bits extracted from audio", False),
    "caesar": ("Caesar shift by {k} applied", True),
    "rot5": ("ROT5 (digit shift) applied", False),
    "rot13": ("ROT13 applied", False),
    "rot18": ("ROT18 applied", False),
    "rot47": ("ROT47 applied", False),
    "rot-n-brute": ("ROT/brute-forced rotation applied", True),
    "atbash": ("Atbash substitution (a<->z) applied", False),
    "affine": ("affine cipher (a=c, b={b}) applied", True),
    "reverse": ("text reversed", False),
    "reverse-words": ("word order reversed", False),
    "reverse-each-word": ("each word's letters reversed", False),
    "reversed-text": ("reversed text decoded", False),
    "ascii": ("ASCII-shifted", False),
    "vigenere": ("Vigenère cipher with key {k}", True),
    "vigenere-brute": ("Vigenère cipher (key brute-forced)", True),
    "vigenere-dictionary": ("Vigenère cipher (dictionary key)", True),
    "vigenere-family": ("Vigenère-family cipher", True),
    "beaufort": ("Beaufort cipher with key {k}", True),
    "autokey": ("Autokey cipher", True),
    "gronsfeld": ("Gronsfeld cipher", True),
    "porta": ("Porta cipher", True),
    "bifid": ("Bifid cipher", False),
    "trifid": ("Trifid cipher", False),
    "four-square": ("Four-square cipher", False),
    "adfgvx": ("ADFGVX cipher", False),
    "nihilist": ("Nihilist cipher", False),
    "playfair": ("Playfair cipher", False),
    "polybius": ("Polybius square decoded", False),
    "scytale": ("Scytale transposition unstaggered", False),
    "columnar-transposition": ("columnar transposition unjumbled", False),
    "columnar-brute": ("columnar transposition (brute-forced)", False),
    "rail-fence": ("rail-fence transposition unjumbled", False),
    "hill-2x2": ("Hill cipher (2x2 matrix) broken", True),
    "hill3-crib": ("Hill cipher (3x3, crib) broken", True),
    "monoalphabetic-substitution": ("monoalphabetic substitution broken (hill-climb)", False),
    "enigma-m3": ("Enigma M3 (known settings) decoded", False),
    "straddling-checkerboard": ("straddling checkerboard decoded", False),
    "known-plaintext-XOR": ("XOR with known plaintext", True),
    "xor-single-byte": ("single-byte repeating XOR broken", True),
    "xor-short": ("short-key repeating XOR broken", True),
    "xor-repeating": ("repeating-key XOR broken (key={k})", True),
    "many-time-pad": ("many-time pad (reused key) broken", False),
    "ecb-detect": ("ECB-mode block cipher detected/broken", False),
    "ecb-repeated-blocks": ("repeated ECB blocks detected", False),
    "rc4": ("RC4 decrypted (key recovered)", True),
    "rc4-key": ("RC4 with given key decrypted", True),
    "aes-key": ("AES decrypted (key given)", True),
    "fernet-key": ("Fernet token decrypted (key given)", True),
    "hash-crack": ("hash cracked ({k})", True),
    "hash-identification": ("hash type identified", False),
    "dh-dlp": ("Diffie-Hellman discrete log broken (shared secret recovered)", False),
    "diffie-hellman-xor": ("Diffie-Hellman shared-secret XOR applied", False),
    "discrete-log": ("discrete logarithm solved", False),
    "dlp-composite-smooth": ("discrete log on a smooth composite modulus solved", False),
    "ecdlp": ("elliptic-curve discrete log solved", False),
    "ecdsa-nonce-reuse": ("ECDSA nonce reuse broken (private key recovered)", False),
    "dsa-nonce-reuse": ("DSA nonce reuse broken", False),
    "lcg-recover": ("LCG parameters recovered, next values predicted", False),
    "lcg-recovery": ("LCG (linear congruential generator) recovered", False),
    "mt19937-predict": ("MT19937 state predicted", False),
    "lfsr-known-plaintext": ("LFSR (known plaintext) cracked", False),
    "linear-recurrence-hash-xor": ("linear recurrence + key/hash derived", False),
    "RSA": ("RSA broken (factorization) — message decrypted", False),
    "RSA-extra": ("RSA broken (d / p+q / phi / prime-power / Rabin / small-e)", False),
    "RSA-sum-leak": ("RSA broken via p+q leak (quadratic roots)", False),
    "RSA known p+q": ("RSA broken via p+q leak (quadratic roots)", False),
    "RSA-dp-leak": ("RSA broken via dp/dq leak", False),
    "RSA-shared-prime": ("RSA broken via shared prime (gcd of moduli)", False),
    "rsa-shared-prime": ("RSA broken via shared prime (gcd of moduli)", False),
    "RSA-related-message": ("RSA Franklin-Reiter related-message attack", False),
    "franklin-reiter": ("RSA Franklin-Reiter related-message attack", False),
    "crt": ("Chinese Remainder Theorem combined", False),
    "merkle-hellman": ("Merkle-Hellman knapsack broken", False),
    "new-caesar-b16": ("New-Caesar b16 nibble cipher broken (key {k})", True),
    "New-Caesar b16": ("New-Caesar b16 nibble cipher broken (key {k})", True),
    "hint-secret-xor": ("XOR with a secret recovered from the challenge source", False),
    "hint-caesar": ("Caesar shift from the challenge source", True),
    "hint-vigenere": ("Vigenère key from the challenge source", True),
    "appended-data": ("extra data appended to the payload", False),
    "races": ("timing/race recovery", False),
}


def explain_chain(chain: str) -> str:
    """Turn a chain string into a list of one-line English explanations."""
    if not chain:
        return ["(no recovery chain)"]
    if chain.startswith("as-is"):
        return [_KNOWN.get("as-is", ("the input was already readable", False))[0]]
    out = []
    for tok in chain.split(" -> "):
        base = _strip(tok)
        params = {}
        m = re.search(r"\((.*)\)", tok)
        if m:
            for kv in m.group(1).split(","):
                if "=" in kv:
                    k, v = kv.split("=", 1)
                    params[k.strip()] = v.strip()
        # "RSA factored(...)" and friends: use a plain description instead of a
        # category the recovered d/m/primes that can be very long.
        if base in ("RSA factored", "RSA known-multi-prime",
                    "RSA multi-prime", "RSA even-e roots", "RSA small-e exact"):
            out.append("RSA broken (factorization/known parameters) — message decrypted")
            continue
        if base == "RSA known p+q":
            out.append("RSA broken via p+q leak (quadratic roots)")
            continue
        elif base in _KNOWN:
            tmpl, _ = _KNOWN[base]
            # normalize chr(98) -> 'b' for readability
            def _pretty(v):
                cm = re.fullmatch(r"chr\((\d+)\)", v)
                return chr(int(cm.group(1))) if cm else v
            # map common param names to the {k} placeholder used in templates
            for pk, pv in params.items():
                tmpl = tmpl.replace("{" + pk + "}", _pretty(pv))
            if "{k}" in tmpl:
                k = (params.get("key") or params.get("shift") or params.get("k")
                      or params.get("key_hex") or "")
                if k:
                    tmpl = tmpl.replace("{k}", _pretty(k))
            tmpl = re.sub(r"\{[a-z_]+\}", "", tmpl).replace("  ", " ").strip()
            out.append(tmpl)
        else:
            # Don't echo huge parameter dumps (e.g. recovered RSA values).
            if len(tok) > 60:
                out.append(f"decoded with {base}")
            else:
                out.append(f"decoded with {tok}")
    return out
