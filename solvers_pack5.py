"""Pack 5: Trifid cipher (3x3x3 Polybius cube).

Encryption writes each plaintext character's (layer, row, column) digits in
three horizontal rows and reads them off vertically in triples; decryption is
the exact inverse. The cube is a 27-character alphabet (26 letters + a filler).
We try the standard alphabets and a few keyword cubes at several block periods,
scoring every candidate with the shared text model.
"""
from __future__ import annotations

import re

from core import solver
from scoring import assess, quadgram_score, flag_plausibility, english_confidence
import solvers as S

_BASE26 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
_KEYS = [
    _BASE26 + ".",
    _BASE26 + "+",
    _BASE26 + "!",
]
for _kw in ("KEYWORD", "TRIFID", "CIPHER", "CRYPTO", "SECRET", "LEMON"):
    _k = "".join(dict.fromkeys(_kw + _BASE26 + "."))
    if _k not in _KEYS:
        _KEYS.append(_k)


def _trifid_decrypt(text, key, period):
    """Decrypt `text` (letters of the 27-char cube) with `key` and block period."""
    coords = []
    for ch in text:
        idx = key.find(ch)
        if idx < 0:
            return None
        coords.append((idx // 9 + 1, (idx % 9) // 3 + 1, idx % 3 + 1))
    out = []
    for start in range(0, len(coords), period):
        block = coords[start:start + period]
        nb = len(block)
        # Ciphertext digit stream in character order; split into three equal
        # segments that are the original layer/row/column digit rows.
        flat = [d for c in block for d in c]
        for i in range(nb):
            idx = (flat[i] - 1) * 9 + (flat[nb + i] - 1) * 3 + (flat[2 * nb + i] - 1)
            out.append(key[idx])
    return "".join(out)


def _trifid_prior(fp):
    if fp["charset"] != "ascii-text" or not 18 <= fp["length"] <= 5000:
        return 0.0
    if not re.fullmatch(r"[A-Za-z.\s]+", fp.get("_text", "").strip()):
        return 0.0
    return .45


@solver("trifid", _trifid_prior)
def solve_trifid(data, ctx):
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        return
    letters = "".join(ch for ch in text if ch.isalpha() or ch in ".+!")
    if len(letters) < 12:
        return
    max_period = min(12, len(letters))
    variants = []
    for key in _KEYS:
        if ctx.expired():
            return
        for period in range(1, max_period + 1):
            out = _trifid_decrypt(letters, key, period)
            if out:
                variants.append((out, key, period))
    # The whole-message period (no grouping) is the classic form.
    for key in _KEYS:
        if ctx.expired():
            return
        out = _trifid_decrypt(letters, key, len(letters))
        if out:
            variants.append((out, key, len(letters)))
    # Rank *distinct* plaintexts by quadgram (several keys yield the same
    # output). A decisive winner across all keys/periods is a genuine recovery;
    # boost it like the hill-2x2 solver does so it survives the confidence
    # floor, and mark it as the strongest exhaustive-key candidate.
    scored = [(quadgram_score(out), out, key, period) for out, key, period in variants]
    scored.sort(key=lambda x: -x[0])
    seen, uniq = set(), []
    for q, out, key, period in scored:
        if out not in seen:
            seen.add(out)
            uniq.append((q, out, key, period))
    uniq.sort(key=lambda t: -english_confidence(t[1]))
    boost = len(uniq) >= 2 and english_confidence(uniq[0][1]) >= .5 \
        and english_confidence(uniq[0][1]) >= english_confidence(uniq[1][1])
    for i, (_, out, key, period) in enumerate(uniq[:3]):
        params = {"key": key, "period": period}
        if i == 0 and boost:
            # Decisive English winner across all keys/periods: keep our own
            # score (core would re-assess and underrate the uppercase text).
            params["_statistical"] = True
            yield out, "trifid", params, min(0.95, 0.55 + 0.35 * english_confidence(out))
        else:
            yield out, "trifid", params, max(assess(out)[0], flag_plausibility(out))


# --------------------------------------------------------------- Nihilist
_ALPHA25 = "ABCDEFGHIKLMNOPQRSTUVWXYZ"   # I/J merged, 25 cells
_NIHILIST_KEYWORDS = ("", "KEYWORD", "SECRET", "LEMON", "CRYPTO", "VICTOR",
                      "MOSCOW", "KEY", "NILHIST")
_NIHILIST_PHRASES = ("", "KEY", "SECRET", "LEMON", "CRYPTO", "VICTOR",
                     "MOSCOW", "SUN", "STAR")


def _polybius25(keyword):
    key = "".join(dict.fromkeys((keyword.upper() + _ALPHA25).replace("J", "I")))[:25]
    return {ch: (i // 5 + 1, i % 5 + 1) for i, ch in enumerate(key)}, key


def _nihilist_decrypt(nums, keyword, phrase, conv):
    """Decrypt Nihilist coordinate numbers; returns letters or None.

    conv "a": digit-wise subtraction mod 10 (no carry).
    conv "b": plain integer subtraction (with carries).
    """
    fwd, key = _polybius25(keyword)
    rev = {v: k for k, v in fwd.items()}
    coord = [fwd[ch] for ch in phrase.upper() if ch in fwd]
    out = []
    for i, v in enumerate(nums):
        kt, ko = coord[i % len(coord)] if coord else (0, 0)
        if conv == "a":
            t, o = (v // 10 - kt) % 10, (v % 10 - ko) % 10
        else:
            x = v - (kt * 10 + ko)
            t, o = divmod(x, 10)
        lett = rev.get((t, o))
        if lett is None:
            return None
        out.append(lett)
    return "".join(out)


def _nihilist_infer(nums, crib):
    """Infer square, convention and repeating key period from a crib.

    The hypothesis must also decrypt the *whole* message to valid 1..5
    coordinates (spurious window-only matches are rejected).
    """
    for kw in _NIHILIST_KEYWORDS:
        fwd, _ = _polybius25(kw)
        cc = [fwd[ch] for ch in crib.upper() if ch in fwd]
        if not cc or len(cc) > len(nums):
            continue
        for conv in ("a", "b"):
            for period in range(1, min(32, len(cc)) + 1):
                keys = []
                ok = True
                for i, (t, o) in enumerate(cc):
                    v = nums[i]
                    if conv == "a":
                        kt, ko = (v // 10 - t) % 10, (v % 10 - o) % 10
                    else:
                        kt, ko = divmod(v - (t * 10 + o), 10)
                    if not (0 <= kt <= 9 and 0 <= ko <= 9):
                        ok = False
                        break
                    keys.append((kt, ko))
                if not ok or not all(keys[i] == keys[i % period] for i in range(len(keys))):
                    continue
                keynums = [keys[i % period] for i in range(len(nums))]
                valid = True
                for v, (kt, ko) in zip(nums, keynums):
                    if conv == "a":
                        t, o = (v // 10 - kt) % 10, (v % 10 - ko) % 10
                    else:
                        t, o = divmod(v - (kt * 10 + ko), 10)
                    if not (1 <= t <= 5 and 1 <= o <= 5):
                        valid = False
                        break
                if valid:
                    return kw, conv, period, keynums
    return None


def _nihilist_prior(fp):
    if fp["charset"] != "ascii-text":
        return 0.0
    t = fp.get("_text", "").strip()
    toks = re.findall(r"\d+", t)
    if len(toks) < 6 or len(toks) > 2000:
        return 0.0
    if not all(len(x) in (2, 3) for x in toks):
        return 0.0
    if sum(11 <= int(x) <= 110 for x in toks) < .6 * len(toks):
        return 0.0
    return .35


@solver("nihilist", _nihilist_prior)
def solve_nihilist(data, ctx):
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        return
    nums = [int(x) for x in re.findall(r"\d+", text)]
    if len(nums) < 6:
        return
    # Exact recovery from a known plaintext crib (repeating key period).
    if ctx.known_plaintext:
        inf = _nihilist_infer(nums, ctx.known_plaintext)
        if inf:
            kw, conv, period, keynums = inf
            _, sq = _polybius25(kw)
            outs = []
            ok = True
            for v, (kt, ko) in zip(nums, keynums):
                if conv == "a":
                    t, o = (v // 10 - kt) % 10, (v % 10 - ko) % 10
                else:
                    t, o = divmod(v - (kt * 10 + ko), 10)
                if not (1 <= t <= 5 and 1 <= o <= 5):
                    ok = False
                    break
                outs.append((t, o))
            if ok:
                out = "".join(sq[(t - 1) * 5 + (o - 1)] for t, o in outs)
                yield out, (f"Cracked nihilist (square={kw or 'default'}, period={period}, "
                             f"conv={'mod10' if conv == 'a' else 'carry'})"), {"_statistical": True}, .98
                return
    # Scored generic attempts: known squares x phrases x conventions.
    variants = []
    for kw in _NIHILIST_KEYWORDS:
        if ctx.expired():
            return
        for phrase in _NIHILIST_PHRASES:
            for conv in ("a", "b"):
                out = _nihilist_decrypt(nums, kw, phrase, conv)
                if out and out not in [v[0] for v in variants]:
                    variants.append((out, kw, phrase, conv))
    scored = [(quadgram_score(out), out, kw, phrase, conv) for out, kw, phrase, conv in variants]
    scored.sort(key=lambda x: -x[0])
    seen, uniq = set(), []
    for q, out, kw, phrase, conv in scored:
        if out not in seen:
            seen.add(out)
            uniq.append((q, out, kw, phrase, conv))
    boost = len(uniq) >= 2 and uniq[0][0] - uniq[1][0] >= .35
    for i, (_, out, kw, phrase, conv) in enumerate(uniq[:3]):
        params = {"square": kw or "default", "phrase": phrase,
                  "conv": "mod10" if conv == "a" else "carry"}
        if i == 0 and boost:
            # Decisive quadgram winner over ~150 square/phrase/convention
            # hypotheses; keep our own near-exact score so junk decode chains
            # (0.6-0.9) do not outrank a genuine recovery.
            params["_statistical"] = True
            yield out, "nihilist", params, .92
        else:
            yield out, "nihilist", params, max(assess(out)[0], flag_plausibility(out))
