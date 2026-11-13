"""Phase 5 tests: UI input modes — paste ciphertext + key, key passed through
to the decoders, blank key = auto-crack.

Covers:
  - `ui._solve` forwards `settings["key"]` into `autocrypt.solve_data(key=...)`.
  - A blank key is forwarded as "" (auto-crack) and does not error.
  - `ui._settings` accepts and stores a cipher-key value.
"""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

os.environ["AUTOCRYPT_NO_FAILURES_LOG"] = "1"

_FP = {"length": 0, "entropy": 0.0, "charset": "", "ic": 0.0,
       "hypotheses": [], "magic": [], "hashes": []}
_R = {"status": "FOUND", "failures": [], "__iter__": lambda s: iter([])}
_C = {"findings": [], "failures": []}


def _fake_solve(**kw):
    captured = dict(kw)
    return _FP, type("R", (), _R)(), type("C", (), _C)()


def _capture_key(key_value):
    import autocrypt
    import autocrypt.ui as ui
    calls = []
    orig = autocrypt.solve_data

    def patched(data, **kw):
        calls.append(kw)
        return _fake_solve(**kw)

    autocrypt.solve_data = patched
    try:
        settings = {"flag_format": r"\w{1,40}\{.*?\}", "flag_format_explicit": False,
                    "timeout": 5.0, "top": 5, "known_plaintext": "",
                    "wordlist": "", "key": key_value}
        ui._solve(b"some ciphertext", settings, params="")
        return calls
    finally:
        autocrypt.solve_data = orig


def test_key_forwarded_to_solve_data():
    calls = _capture_key("lemon")
    assert calls, "solve_data was not called"
    assert calls[0]["key"] == "lemon"


def test_blank_key_forwarded_as_empty():
    calls = _capture_key("")
    assert calls, "solve_data was not called"
    assert calls[0]["key"] == ""


def test_settings_menu_accepts_key(monkeypatch=None):
    import autocrypt.ui as ui
    # Exercise _settings internals: simulate choosing option 6 and typing a key.
    import builtins
    inputs = iter(["6", "lemon", "0"])
    real_input = builtins.input
    builtins.input = lambda prompt="": next(inputs)
    try:
        settings = {"flag_format": r"\w{1,40}\{.*?\}", "flag_format_explicit": False,
                    "timeout": 5.0, "top": 5, "known_plaintext": "",
                    "wordlist": "", "key": ""}
        ok = ui._settings(settings)
        assert ok is True
        assert settings["key"] == "lemon"
    finally:
        builtins.input = real_input


def main():
    test_key_forwarded_to_solve_data()
    test_blank_key_forwarded_as_empty()
    test_settings_menu_accepts_key()
    print("UI-PHASE5: ALL OK")


if __name__ == "__main__":
    main()
