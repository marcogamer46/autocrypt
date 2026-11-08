"""Regression tests for UI encode-safety, results_panel preview behavior, and
timeout-invariance of the top-1 result.

Run:  PYTHONPATH=. .venv/Scripts/python.exe test_ui_safety.py
"""
import codecs
import io
import json
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))

# A plaintext that ms NOT representable in cp1252 (exercises the encode-safety
# guarantee: recovered flags may contain arbitrary Unicode/bytes).
NASTY_FLAG = "academy{λ_ok_emoji_\U0001F600}"


def test_verdict_banner_self_safe():
    """verdict_banner must never raise on a non-cp1252-encodable flag, even
    when stdout has NOT been reconfigured (as when ui is embedded)."""
    import ui
    rows = [{"confidence": 0.98, "is_flag": True, "plaintext": NASTY_FLAG}]
    text = ui.verdict_banner(rows)
    assert isinstance(text, str) and text
    # The banner is self-safe: it must survive strict cp1252 encoding.
    text.encode("cp1252")  # raises if any unencodable char leaked through
    assert NASTY_FLAG[:8] in text or "academy" in text
    print("OK  verdict_banner self-safe with non-cp1252 flag")


def test_results_panel_preview_and_notes():
    import ui
    rows = [{"chain": f"c{i}", "confidence": 0.9, "is_flag": False,
             "plaintext": "hello world " * 20} for i in range(5)]
    text = ui.results_panel(rows, width=70, preview_boxes=2)
    assert "Ranked results (5)" in text
    # Only the top 2 plaintext boxes are shown; a note announces the rest.
    assert text.count("Plaintext #") == 2
    assert "more plaintexts" in text
    assert "Raising the timeout" in text
    # Long plaintext is truncated at 2400 chars with a preview note.
    long_row = [{"chain": "c", "confidence": 0.9, "is_flag": False,
                 "plaintext": "z" * 5000}]
    t2 = ui.results_panel(long_row, width=70, preview_boxes=1)
    assert "[preview truncated; save results for full plaintext]" in t2
    print("OK  results_panel preview + notes")


def test_panels_render_under_reconfigured_stdout():
    """Under the CLI's stdout.reconfigure(errors='replace'), all panels render
    without raising even with non-ASCII plaintext."""
    import ui
    buf = io.BytesIO()
    old = sys.stdout
    sys.stdout = io.TextIOWrapper(buf, encoding="cp1252", errors="replace")
    try:
        rows = [{"chain": "c", "confidence": 0.95, "is_flag": True,
                 "plaintext": NASTY_FLAG}]
        ui.verdict_banner(rows)
        ui.results_panel(rows, width=70)
        fp = {"length": 12, "entropy": 3.1, "charset": "ascii-text",
              "ic": 0.05, "hypotheses": [], "magic": [], "hashes": []}
        ui.fingerprint_panel(fp)
        ui.empty_panel("NOT_FOUND")
    finally:
        sys.stdout.flush()
        sys.stdout = old
    print("OK  panels render under reconfigured cp1252 stdout")


def _run_jobs(path, timeout):
    r = subprocess.run(
        [sys.executable, str(HERE / "autocrypt.py"), str(path),
         "--timeout", str(timeout), "--json", "--top", "3"],
        capture_output=True, text=True, timeout=timeout + 30, cwd=HERE)
    m = re.search(r"\{.*\}", r.stdout, re.S)
    d = json.loads(m.group(0)) if m else {}
    rows = d.get("results", [])
    if not rows:
        return (d.get("status"), None, None)
    return (rows[0].get("chain"), rows[0].get("plaintext"),
            rows[0].get("confidence"))


def test_no_color_flag_disables_ansi():
    """--no-color (wired via ui.COLOR_ENABLED) must disable ANSI even when
    the environment would otherwise enable it."""
    import ui
    ui.COLOR_ENABLED = False
    try:
        assert ui._color_on() is False
        assert ui.paint("x", "green") == "x"
    finally:
        ui.COLOR_ENABLED = None
    print("OK  --no-color disables ANSI paint")


def test_timeout_invariance():
    """A larger timeout may surface MORE lower-ranked candidates but must never
    change (or downgrade) the top-1 result: chain+plaintext+confidence."""
    # Reuse a known-solvable layered input (hex -> flag).
    path = HERE / "tm_timeout_invar.txt"
    path.write_text("Check this: 61636164656d797b6836785f6c617965727d")
    try:
        a = _run_jobs(path, 10)
        b = _run_jobs(path, 20)
        assert a[0] is not None, f"t=10 returned no top-1: {a}"
        assert a[0] == b[0] and a[1] == b[1] and a[2] == b[2], \
            f"top-1 differs across timeouts: t=10 {a} vs t=20 {b}"
    finally:
        path.unlink(missing_ok=True)
    print(f"OK  timeout-invariance: top-1 stable t=10 vs 20 ({a[0]})")


def main():
    test_verdict_banner_self_safe()
    test_results_panel_preview_and_notes()
    test_panels_render_under_reconfigured_stdout()
    test_no_color_flag_disables_ansi()
    test_timeout_invariance()
    print("UI_SAFETY: ALL OK")


if __name__ == "__main__":
    main()
