# real_challenges/online_train — raw CTF training set

Downloaded **raw** challenge files for training autocrypt. Only generator
sources + ciphertext are kept — no solver scripts, no preloaded flags. The
`autocrypt.py` CLI is the only solver (see "Run" below); these files are just
the inputs.

> Policy: a challenge is dropped from training if its bundle leaks the answer
> (embedded `solv.py`, a `flag.txt`, or a README with the plaintext flag).

## How to run autocrypt on a challenge
```bash
PATH="$PWD/.venv/Scripts:$PATH" python autocrypt.py \
    real_challenges/online_train/<challenge>/<file> --timeout 25 --top 5
```

## Inventory

| Challenge | Event | Type | Status / notes |
|---|---|---|---|
| Baby_RSA | CSAW Red 2020 | RSA p/q | ✅ solved |
| Teen_RSA | CSAW Red 2020 | RSA small-e/ no n | ✅ solved |
| Caesar_Salad_Edition | CSAW Red 2020 | mixed-alnum Caesar | ✅ solved (`base36-caesar`) |
| Apple_Cider_Vinegar | CSAW Red 2020 | unknown polyalphabetic | ❌ open gap |
| unary_binary | CSAW Red 2020 | encoding (PDF) | ⛔ excluded — README leaks flag |
| mindreader | CSAW Red 2020 | AES-OFB oracle | 🚫 interactive, out of scope |
| prettyplease | CSAW Red 2020 | AES-CTR oracle | 🚫 interactive, out of scope |
| Mini_RSA | PicoCTF 2021 | RSA e=3 overflow | ✅ solved (small-e cube-root) |
| Easy_Peasy | PicoCTF 2021 | OTP | ⛔ excluded — plaintext flag present |
| New_Caesar | PicoCTF 2021 | b16+shift | ⛔ excluded — source embeds solve code |
| New_Vignere | PicoCTF 2021 | b16+shift-Vigenere | 🕑 has `b16-shift-vigenere` solver; target ciphertext absent |
| Double_DES | PicoCTF 2021 | DES | 🚫 out of scope |
| Sum-O-Primes | PicoCTF 2022 | RSA p+q | ✅ solved |
| Very Smooth | PicoCTF 2022 | RSA smooth p−1 | ✅ solved (p−1) |
| NSA Backdoor | PicoCTF 2022 | DLP | ✅ solved (smooth composite) |
| Sequences | PicoCTF 2022 | linear recurrence | ⏳ heavy compute-and-check, not static decode |
| rotation | PicoCTF 2023 | Caesar | ✅ solved |
| XtraORdinary | redpwn | repeating-key XOR pads | ✅ solved (`xor-literal-pads`) |
| xorly | redpwn | sample-known-pt XOR | ✅ solved (`sample-keystream-xor`) |
| HackUCF_xorly | HackUCF | same as xorly | ⛔ excluded — copy embeds solution |

Legend: ✅ solved by autocrypt · ❌ unresolved · ⛔ excluded (leaks answer) ·
🚫 out of scope · 🕑/⏳ incomplete.

Resolved-gap notes and solver details live in `../../session.md`, `LOGS.md`,
and `things_it_cant_solve.txt`.
