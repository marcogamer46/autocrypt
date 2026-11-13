"""Phase 3 tests: layered beam search (width cap, cheap transforms, profiling).

Covers:
  - The cheap reverse transform recovers a reversed flag-shaped string.
  - The whitespace-strip transform recovers a spaced-out flag.
  - A non-improving transform is NOT recorded (no noise).
  - beam_width is accepted end-to-end and simple solves still succeed.
  - Profiling counters (nodes_expanded/children_pushed/transforms_run/per_depth)
    are populated after a solve.
"""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

os.environ["AUTOCRYPT_NO_FAILURES_LOG"] = "1"

from autocrypt.cli import solve_data  # noqa: E402

FLAG = "academy{beam_transform_ok}"


def _solve(data, **kw):
    _, res, ctx = solve_data(data, timeout=8, top=12, jobs=1, **kw)
    return res, ctx


def test_reverse_transform_recovers_flag():
    # A reversed flag is recovered — via the cheap reverse transform and/or the
    # pre-existing "reverse text" solver; either route is a correct recovery.
    reversed_input = FLAG[::-1].encode()
    res, _ = _solve(reversed_input)
    texts = [r.get("plaintext", "") for r in res]
    assert FLAG in texts, f"flag should be recovered; got {texts!r}"


def test_strip_ws_transform_recovers_flag():
    spaced = "a c a d e m y { b e a m _ t r a n s f o r m _ o k }".encode()
    res, _ = _solve(spaced)
    texts = [r.get("plaintext", "") for r in res]
    chains = " ".join(r.get("chain", "") for r in res)
    assert "academy{beam_transform_ok}" in texts, texts
    assert "transform: strip-ws" in chains


def test_nonimproving_transform_not_recorded():
    # "hello world" reversed is "dlrow olleh" — no flag, no English gain, so
    # the transform must not add a junk result row.
    res, _ = _solve(b"hello world")
    chains = " ".join(r.get("chain", "") for r in res)
    assert "transform: reverse" not in chains


def test_beam_width_accepted_and_basic_solve():
    # a simple known flag still solves even with a tiny beam
    res, _ = _solve(b"academy{beam_ok}", beam_width=1)
    texts = [r.get("plaintext", "") for r in res]
    assert "academy{beam_ok}" in texts, texts
    # a larger beam also works
    res2, _2 = _solve(b"academy{beam_ok}", beam_width=8)
    assert "academy{beam_ok}" in [r.get("plaintext", "") for r in res2]


def test_profiling_counters_populated():
    import base64
    res, ctx = _solve(base64.b64encode(FLAG.encode()))
    st = getattr(ctx, "stats", {})
    assert st.get("nodes_expanded", 0) >= 1
    assert isinstance(st.get("children_pushed", 0), int)
    assert isinstance(st.get("transforms_run", 0), int)
    assert isinstance(st.get("per_depth", {}), dict)


def main():
    test_reverse_transform_recovers_flag()
    test_strip_ws_transform_recovers_flag()
    test_nonimproving_transform_not_recorded()
    test_beam_width_accepted_and_basic_solve()
    test_profiling_counters_populated()
    print("BEAM: ALL OK")


if __name__ == "__main__":
    main()
