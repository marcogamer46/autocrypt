"""Phase 2 tests: unified score(text) + IoC.

Covers:
  - score() ranks real English prose high and random/garbage low.
  - index_of_coincidence() tracks the English/random/identical-letter axis.
  - The large flag bonus fires for flag{...} / CTF{...} and for a
    user-supplied regex, and is *additive* only (never rescues garbage).
  - Invalid user regex degrades gracefully (no exception).
"""
import math
import random
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from autocrypt.scoring import index_of_coincidence, score, assess  # noqa: E402


_GOOD = ("the quick brown fox jumps over the lazy dog and runs away quickly "
         "to the nearby riverbank where the trees make a cool shadow across "
         "the grass in the morning light")


def test_score_english_high():
    assert score(_GOOD) > 0.7
    # as-gained flag also scores high (flag bonus)
    assert score("academy{this_is_a_real_flag}") > 0.7


def test_score_garbage_low():
    rng = random.Random(20261113)
    # 1) random high-entropy bytes (latin-1 so it is ""-able)
    blob = rng.randbytes(160).decode("latin-1")
    assert score(blob) < 0.5
    # 2) uniform random letters — not recognizable prose
    letters = "".join(rng.choice("qzxvkjwpfy") for _ in range(160))
    assert score(letters) < 0.5
    # 3) binary-ish with control chars
    ctrl = "".join(chr(rng.randrange(256)) for _ in range(160))
    assert score(ctrl) < 0.4


def test_score_good_beats_garbage():
    rng = random.Random(7)
    garbage = "".join(rng.choice("qzxvkjwpfy") for _ in range(200))
    assert score(_GOOD) > score(garbage)


def test_ioc_axis():
    # identical letters -> IoC ~ 1.0
    assert index_of_coincidence("aaaaaaa") > 0.9
    # evenly spread letters -> IoC near uniform (0.038)
    spread = "abcdefghijklmnopqrstuvwxyz" * 8
    assert abs(index_of_coincidence(spread) - 0.038) < 0.02
    # English sample sits near 0.066
    assert abs(index_of_coincidence(_GOOD) - 0.066) < 0.03
    # short / non-letter text yields the safe 0.0
    assert index_of_coincidence("") == 0.0
    assert index_of_coincidence("123 !!!") == 0.0


def test_flag_bonus_default_regex():
    # default flag shape gets the bonus above the same words unwrapped (the
    # bonus pushes a genuine flag body to the top of the range)
    plain = "academy this is a real flag"
    flagged = "academy{this_is_a_real_flag}"
    assert score(flagged) > score(plain)
    assert score(flagged) >= 0.95


def test_flag_bonus_user_regex():
    base = score("flag{leet_c4pt_ur3}")
    with_regex = score("flag{leet_c4pt_ur3}",
                       flag_regex=r"flag\{[^}]+\}")
    # explicit regex also recognizes it, at least as strongly as the default
    assert with_regex >= base - 1e-9
    assert with_regex > 0.85
    # a user regex that doesn't match adds nothing
    assert score("hello world", flag_regex=r"CTF\{[^}]+\}") == \
        score("hello world")


def test_flag_bonus_is_additive_not_rescue():
    # garbage that merely *looks* like a flag shape still must score low under
    # the DEFAULT heuristic path: the quality-scaled bonus adds to a near-zero
    # base, it does not promote junk.
    junk = "flag{qzxvkjwpfyqzxvkjwpfyqzxvkjwpfy}"
    assert score(junk) < 0.65
    # ... but the SAME junk with an explicit user regex is authoritative
    # (the user asserted this exact shape) and gets the large flat bonus.
    assert score(junk, flag_regex=r"flag\{[^}]+\}") > 0.7


def test_score_accepts_bytes():
    assert score(_GOOD.encode("utf-8")) > 0.7
    rng = random.Random(3)
    assert score(rng.randbytes(120).decode("latin-1")) < 0.5


def test_score_empty_and_noise():
    assert score("") == 0.0
    assert score("   \t\n") == 0.0
    assert score("!!!!!!!!!:::::") < 0.5


def test_invalid_user_regex_degrades():
    # a malformed regex must not raise; it behaves as "no match"
    # (nothing is added to the base language score)
    base = score("flag{hi}")
    r = score("flag{hi}", flag_regex="[invalid")
    assert isinstance(r, float) and 0.0 <= r <= 1.0
    assert r == base


def test_assess_still_sane_with_ioc():
    # the search pipeline's assess() still ranks English above random
    rng = random.Random(11)
    garbage = "".join(rng.choice("qzxvkjwpfy") for _ in range(200))
    g, _ = assess(_GOOD)
    b, _ = assess(garbage)
    assert g > b and g > 0.6 and b < 0.6


def main():
    test_score_english_high()
    test_score_garbage_low()
    test_score_good_beats_garbage()
    test_ioc_axis()
    test_flag_bonus_default_regex()
    test_flag_bonus_user_regex()
    test_flag_bonus_is_additive_not_rescue()
    test_score_accepts_bytes()
    test_score_empty_and_noise()
    test_invalid_user_regex_degrades()
    test_assess_still_sane_with_ioc()
    print("SCORING: ALL OK")


if __name__ == "__main__":
    main()
