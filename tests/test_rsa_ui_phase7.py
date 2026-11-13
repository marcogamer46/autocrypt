"""Phase 7 tests: RSA UI mode with an optional supplied private exponent (d).

The interactive RSA menu accepts n/e/c (required) and optional p/q/d. When a
`d` is supplied, the RSA solver decrypts directly with m = c^d mod n instead
of factoring or attacking. Covers:
  - solve_data with a `params` spec containing d decrypts to the flag.
  - The _params spec parser accepts a labelled d.
  - The RSA solver's ascii scan reads d from a label-style data blob.
  - CLI `--params` with d decrypts to the flag (end-to-end).
"""
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

os.environ["AUTOCRYPT_NO_FAILURES_LOG"] = "1"

from autocrypt.cli import _params, solve_data  # noqa: E402

# Fixed 160-bit RSA example (p, q prime; e=65537; d = e^-1 mod phi).
_N = 1529126172105859265296750435999243616292734566641993528351400573286353450778757371251991073199901
_E = 65537
_D = 5343087010577868559027051129038967119810736160648917032256124552140856679176367969171590563841
_C = 1104974295606153792856111660558223963524164748301831197722079801379508532840183434301534090891720
_FLAG = "academy{rsa_known_d_ok}"


def _solve(data, **kw):
    _, res, _ = solve_data(data, timeout=12, top=12, jobs=1, **kw)
    return res


def _has_flag(res, flag):
    flag = flag.lower()
    return any(flag in r.get("plaintext", "").lower() for r in res)


def test_solve_data_param_with_d():
    spec = f"n={_N},e={_E},c={_C},d={_D}"
    res = _solve(spec.encode())
    assert _has_flag(res, _FLAG), [r.get("plaintext", "")[:40] for r in res]


def test_solve_data_ascii_scan_d():
    # No d via rsa_params: the solver must still read d from the ascii blob.
    blob = f"n={_N}\ne={_E}\nc={_C}\nd={_D}\n".encode()
    res = _solve(blob)
    assert _has_flag(res, _FLAG), [r.get("plaintext", "")[:40] for r in res]


def test_params_spec_parses_d():
    spec = f"n={_N},e={_E},c={_C},d={_D}"
    p = _params(spec)
    assert p["n"] == _N
    assert p["e"] == _E
    assert p["c"] == _C
    assert p["d"] == _D


def test_hex_d_parses():
    p = _params(f"d={hex(_D)}")
    assert p["d"] == _D


def test_cli_params_with_d():
    # UI flow: the RSA spec string itself is the input blob (ascii scan reads
    # n/e/c/d from it); the flag must survive to stdout.
    spec = f"n={_N},e={_E},c={_C},d={_D}\n"
    p = subprocess.run(
        [sys.executable, "-m", "autocrypt", "--json"],
        input=spec.encode(), capture_output=True)
    assert p.returncode == 0, p.stderr.decode(errors="replace")
    payload = json.loads(p.stdout.decode("utf-8"))
    texts = " ".join(r.get("plaintext", "") for r in payload["results"]).lower()
    assert _FLAG in texts, [r.get("plaintext", "") for r in payload["results"]]


def main():
    test_solve_data_param_with_d()
    test_solve_data_ascii_scan_d()
    test_params_spec_parses_d()
    test_hex_d_parses()
    test_cli_params_with_d()
    print("RSA-UI-PHASE7: ALL OK")


if __name__ == "__main__":
    main()
