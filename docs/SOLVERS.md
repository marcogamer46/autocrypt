# Solver catalog

autocrypt's registry holds **146 registered solvers**, each declared with the
`@solver(name, matches)` decorator:

- `name` — stable identifier shown in result chains.
- `matches(fp)` — a function returning a **prior probability** in `[0,1]`
  from the input fingerprint (charset, length, entropy, magic bytes, regex
  encoding classes). Returning `0.0` skips the solver entirely; higher priors
  schedule the solver earlier in the best-first heap.
- `solve(data, ctx)` — a generator yielding `(plaintext, method, params,
  claimed_score)` tuples for each candidate.

Solvers are split across modules to keep the core registry readable. The
split is purely organizational; every module is imported and registered by
`solvers.py` at load time.

## Module map

| Module | Count | Contents |
|---|---|---|
| `solvers.py` | 52 | Core encodings, classical ciphers, XOR, number-theory primitives, flag-body decode |
| `solvers_mega.py` | 30 | Extended encodings + more ciphers, stego, compressed formats |
| `solvers_pack7.py` | 24 | RSA attacks, DLP, LCG/MT19937, AES/Fernet, hash cracking, crib ciphers |
| `solvers_pack6.py` | 9 | four-square, gronsfeld, straddling checkerboard, Z85, custom-base, EC-DLP, ECDSA nonce reuse, Merkle–Hellman, Enigma M3 |
| `solvers_pack3.py` | 9 | RSA sum-leak, two-symbol/DNA/braille encodings, RC4, AES-known-key, byte transforms, new-caesar-b16 |
| `solvers_more.py` | 7 | RSA-extra, Hill 2×2, OOK, integer-to-bytes, LFSR known-plaintext, RSA related-message, XOR literal pads |
| `solvers_plus.py` | 7 | RSA shared-prime, RSA dp-leak, discrete log, LCG recovery, MT19937 predict, hash crack, ECB detect |
| `solvers_extra.py` | 6 | base45, base36, uuencode, NATO phonetic, brainfuck, zip-archive |
| `solvers_pack5.py` | 2 | trifid, nihilist |

## Family index (with examples)

### Encodings & formats
hex / hex-in-text / hex+rot13, base16/32/64/64url/58/62/85/91/92, binary,
octal, decimal, decimal-ascii, hex-le, morse, url, quoted-printable, a1z26,
polybius, bacon, PEM, zlib/gzip, bytes-literal, radix-ascii, reverse words,
reverse-each-word, base45, base36, uuencode, nato-phonetic, brainfuck,
zip-archive, html-entities, unicode-escapes, punycode, rot5/18/n-brute,
keyboard-shift, t9-phone, tap-code, multi-base64, ebcdic, baudot-ita2,
two-symbol-binary, dna-2bit, braille, base-variants, byte-transforms, z85,
custom-alphabet-base, integer-to-bytes, gray-code, a1z26-hex, extra-encodings.

### Classical ciphers
caesar, ROT13, ROT47, atbash, affine, base36-caesar, b16-shift-vigenere,
flag-body-decode, vigenere-family (+dictionary, +brute), autokey,
rail-fence, scytale, columnar-transposition (+brute), block-transposition,
monoalphabetic-substitution (+wordlist), playfair, bifid, trifid, adfgvx,
four-square, gronsfeld, straddling-checkerboard, nihilist, beaufort, porta,
hill-2×2, hill3-crib, enigma-m3, vigenere-dictionary, autokey-with-crib,
Braille, morse.

### XOR / stream
xor-single-byte, xor-repeating, known-plaintext-XOR, sample-keystream-xor,
many-time-pad, hint-keystream-xor, xor-short, xor-literal-pads,
lfsr-known-plaintext, rc4 / rc4-key.

### Number theory / public-key
small-e exact root (in `solvers.py` math section), Wiener, factored RSA,
shared-prime gcd, dp/dq leak, known p+q, even-e roots, multi-prime,
Franklin-Reiter, common modulus, Hastad-style (triple labels),
Pollard p−1/p+1/rho/ECM, DLP via Pohlig–Hellman (smooth groups),
EC arithmetic + BSGS, ECDSA/DSA nonce reuse, LCG recovery, MT19937 prediction,
Merkle–Hellman, RSA-sum-leak, RSA-extra, RSA-related-message, RSA known prime,
RSA dp-leak, hash cracking (md5/sha1/sha224/sha256/sha384/sha512/ntlm).

### Stego / misc
LSB PNG, WAV LSB, whitespace-stego, pdf-text, docx-text,
ecb-repeated-blocks, AES-known-key / aes-key / fernet-key, think.

## How a solver is chosen

1. `core.fingerprint()` computes cheap structural stats.
2. Each solver's `matches(fp)` returns a prior; non-zero priors are scheduled
   in a best-first heap.
3. `core.search()` pops nodes, runs the solver's generator for a per-solver
   time slice (~4s, extensible to 2× if the global deadline has room), and
   scores each yielded candidate with `scoring.assess()` /
   `flag_plausibility()` / `plain_text_score()`.
4. Verified exact recoveries are tagged with a higher trust tier and rank above
   statistical guesses.

## Adding a solver

See `README.md` → "How to add a solver". The contract is: write one function +
a prior, `yield` candidates, score honestly (`ctx.assess()`), set
`_statistical` for guesses, and add a regression row to the matching `tests/`
family.
