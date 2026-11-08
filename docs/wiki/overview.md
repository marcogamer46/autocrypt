# What is autocrypt?

Autocrypt is a command-line tool that tries to solve CTF crypto challenges for
you. If you give it a blob of data that hides a secret — usually a flag like
`picoCTF{...}` — it will try to find the plaintext hiding underneath.

## What problem does it solve?

In a CTF, a crypto challenge usually works like this: the organizer encrypts or
encodes a flag with some cipher or encoding, gives you the result, and asks you
to reverse it. The hard and sometimes tedious part is figuring out *what* was
done to the data before you can undo it.

Autocrypt automates that guess-and-check work. It doesn't need you to tell it
the cipher. It looks at the data, forms a hunch about what it might be, and
then tries a lot of candidate decodings and attacks until one of them produces
something that looks like a readable flag.

## What does it do, in one sentence?

It reads an unknown blob, guesses the cipher or encoding that produced it, and
recovers the flag.

## How does it approach the problem?

Autocrypt works in a few broad stages:

1. **Fingerprint the input.** It computes cheap structural stats — character
   set, length, entropy, index of coincidence, magic bytes, and tests for
   common encodings like hex or base64. This narrows down which solvers are
   worth trying.
2. **Search for a decoding.** It runs a best-first layered decode search over
   its registry of solvers. Each solver represents a known decoding, cipher,
   or mathematical attack. The search builds up chains of transforms (for
   example `base64 XOR single-byte`) and keeps exploring the most promising
   ones.
3. **Rank what surfaces.** For every candidate plaintext it computes evidence
   of being human-readable, English-like, and flag-shaped, then ranks the
   results. Verified exact recoveries (where the math checks out) are kept
   above speculative statistical guesses.

## What kinds of challenges can it handle?

The solver registry of **146 solvers** covers a lot of common ground:

- **Encodings & formats** — hex, base16/32/64/58/85, binary, octal, morse,
  URL encoding, gzip/zlib, PEM/JWT, and many more.
- **Classical ciphers** — Caesar / ROT13, atbash, affine, Vigenère, rail
  fence, columnar transposition, playfair, Enigma M3, and others.
- **XOR & stream ciphers** — single-byte XOR, repeating-key XOR, many-time-pad,
  known-plaintext crib.
- **Number theory / public-key** — small-e roots, Wiener's attack, factored
  RSA, shared-prime gcd, DLP, EC arithmetic, LCG recovery, MT19937 prediction,
  and hash cracking.

And it can read a challenge `.py` script **statically** (never executing it)
to pull out labels, constants, and hints that live only in the source.

## What it is not

Autocrypt is honest about its limits. Modern authenticated encryption and
general factoring of large RSA moduli are out of scope. If nothing clears its
quality threshold, it says so — it reports `status: failed` rather than
pretending it found an answer. Results are algorithmic and deterministic:
output is time-bounded and uses fixed budgets, so it does not change when your
machine is busy.

## Ethos

- Results are **algorithmic** — a solver wins because its decoding is sound,
  not because a flag was hardcoded.
- **Flags are never hardcoded** into solvers.
- Output is **deterministic** — same input gives the same ranked answer.

## Where to go next

- Ready to run it? See the [Quickstart](quickstart.md).
- Want the full detail on scoring? Read [SCORING.md](../SCORING.md).
- Curious about every solver? Browse [SOLVERS.md](../SOLVERS.md).
