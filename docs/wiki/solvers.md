# Solver families

autocrypt's registry holds **146 registered solvers**, each declared with the `@solver(name, matches)` decorator. Each solver has three parts:

- `name` — a stable identifier shown in result chains.
- `matches(fp)` — returns a **prior probability** in `[0,1]` from the input fingerprint (charset, length, entropy, magic bytes, regex encoding classes). Returning `0.0` skips the solver entirely; higher priors schedule the solver earlier in the best-first heap.
- `solve(data, ctx)` — a generator yielding `(plaintext, method, params, claimed_score)` tuples for each candidate.

This page groups them by family. The complete catalog of all 146 individual solvers, with a module map and the "how to add a solver" contract, is in [SOLVERS.md](../SOLVERS.md).

## The families

### Encodings & formats
Pure format conversions and character-level encodings: hex / hex-in-text / hex+rot13, base16/32/64/64url/58/62/85/91/92, binary, octal, decimal, ASCII, hex-le, morse, URL, quoted-printable, a1z26, polybius, bacon, PEM, zlib/gzip, bytes-literal, radix-ascii, word reversals, base45, base36, uuencode, nato-phonetic, brainfuck, zip-archive, html-entities, unicode-escapes, punycode, rot variants, keyboard-shift, t9-phone, tap-code, multi-base64, ebcdic, baudot-ita2, two-symbol-binary, dna-2bit, braille, base-variants, byte-transforms, z85, custom-alphabet-base, integer-to-bytes, gray-code, and more.

### Classical ciphers
Letter-substitution and transposition ciphers: caesar, ROT13, ROT47, atbash, affine, base36-caesar, b16-shift-vigenere, flag-body-decode, vigenere-family (+dictionary, +brute), autokey, rail-fence, scytale, columnar-transposition (+brute), block-transposition, monoalphabetic-substitution (+wordlist), playfair, bifid, trifid, adfgvx, four-square, gronsfeld, straddling-checkerboard, nihilist, beaufort, porta, hill-2×2, hill3-crib, enigma-m3, vigenere-dictionary, autokey-with-crib.

### XOR / stream
Single-byte and repeating XOR, known-plaintext XOR, sample-keystream XOR, many-time-pad, hint-keystream XOR, XOR short, XOR literal pads, LFSR known-plaintext, RC4 / RC4-key.

### Number theory / public-key
RSA and discrete-log attacks: small-e exact root, Wiener, factored RSA, shared-prime gcd, dp/dq leak, known p+q, even-e roots, multi-prime, Franklin-Reiter, common modulus, Hastad-style, Pollard p−1/p+1/rho/ECM, DLP via Pohlig–Hellman, EC arithmetic + BSGS, ECDSA/DSA nonce reuse, LCG recovery, MT19937 prediction, Merkle–Hellman, RSA-sum-leak, RSA-related-message, RSA known prime, RSA dp-leak, and hash cracking (md5/sha1/sha224/sha256/sha384/sha512/ntlm).

### Stego / misc
Hidden-data extraction and container analysis: LSB PNG, WAV LSB, whitespace-stego, pdf-text, docx-text, ecb-repeated-blocks, AES-known-key / aes-key / fernet-key.

## How a solver is chosen

1. `core.fingerprint()` computes cheap structural stats.
2. Each solver's `matches(fp)` returns a prior; non-zero priors are scheduled in a best-first heap.
3. `core.search()` pops nodes and runs the solver's generator for a per-solver time slice (~4s, extensible to 2x if the global deadline has room), scoring each yielded candidate with `scoring.assess()` / `flag_plausibility()` / `plain_text_score()`.
4. Verified exact recoveries are tagged with a higher trust tier and rank above statistical guesses.

## Related pages

- [How results are scored](scoring.md) — how candidates from these solvers are ranked.
- [Command-line reference](cli.md) — running the search.
- Full catalog: [SOLVERS.md](../SOLVERS.md).
