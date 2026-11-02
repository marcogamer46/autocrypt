"""Challenge-file support: read a CTF source .py (statically, never executed) plus its
output .txt, and turn unlabeled output numbers into labeled `name=value` input."""
from __future__ import annotations
import ast
import re
from pathlib import Path


def _label(node, seen):
    """Map a print() argument expression to a solver-friendly label."""
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Sub):
        return "diff"
    if isinstance(node, ast.Call) and node.args and getattr(node.func, "id", "") in (
            "str", "hex", "int", "bytes_to_long", "long_to_bytes", "repr"):
        return _label(node.args[0], seen)
    if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "pow" and len(node.args) == 3:
        return "c"
    name = node.id if isinstance(node, ast.Name) else (
        node.attr if isinstance(node, ast.Attribute) else "x")
    low = name.lower()
    if low in ("n", "modulus", "mod"):
        return "n"
    if low in ("e", "exponent"):
        return "e"
    if any(k in low for k in ("cipher", "cypher", "enc", "ct")) or low in ("c", "c1", "c2", "ct"):
        return "c"
    return low


def _number(node):
    try:
        v = ast.literal_eval(node)
        return v if isinstance(v, int) and not isinstance(v, bool) else None
    except Exception:
        return None


def analyze_source(src: str):
    """Returns (constants, print_labels, findings, hex_labels, dlp_hint). Static only."""
    consts, labels, findings = {}, [], []
    hex_labels = set()
    dlp_hint = {}
    try:
        tree = ast.parse(src)
    except SyntaxError as exc:
        return consts, labels, [f"source not parseable: {exc.msg}"], set(), {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            v = _number(node.value)
            if v is not None:
                consts[node.targets[0].id.lower()] = v
        if isinstance(node, ast.Call):
            fn = getattr(node.func, "id", getattr(node.func, "attr", ""))
            if fn == "getPrime" and node.args and _number(node.args[0]):
                findings.append(f"getPrime({_number(node.args[0])}) — prime size from source")
            if fn in ("seed", "randint", "getrandbits", "urandom"):
                findings.append(f"{fn}() used — check for predictable randomness")
            # DLP hint: pow(g, SECRET, n)
            if fn == "pow" and len(node.args) == 3:
                gnode, enode, nnode = node.args
                if isinstance(enode, ast.Name) and enode.id.upper() in (
                        "FLAG", "SECRET", "M", "MSG", "SEC", "X") or (
                        isinstance(enode, ast.Call) and getattr(enode.func, "id", "") in
                        ("int", "bytes_to_long")):
                    g = _number(gnode)
                    if isinstance(gnode, ast.Name):
                        g = consts.get(gnode.id.lower())
                    dlp_hint["g"] = g
                    dlp_hint["secret"] = enode.id if isinstance(enode, ast.Name) else "secret"
    prints = sorted((n for n in ast.walk(tree) if isinstance(n, ast.Call)
                     and getattr(n.func, "id", "") == "print"), key=lambda n: (n.lineno, n.col_offset))
    seen = {}
    for call in prints:
        for arg in call.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                continue                      # banner text, not data
            lab = _label(arg, seen)
            labels.append(lab)
            if _is_hex_format(arg):
                hex_labels.add(lab)
    # number duplicate labels: c, c -> c1, c2
    total = {l: labels.count(l) for l in set(labels)}
    idx = {}
    out = []
    for l in labels:
        if total[l] > 1:
            idx[l] = idx.get(l, 0) + 1
            out.append(f"{l}{idx[l]}")
        else:
            out.append(l)
    for m in re.finditer(r"\b(?:xor|AES|DES|Fernet|ChaCha|random|LFSR|lfsr|pow\(|getPrime|DSA|ECC|elgamal)\b", src):
        findings.append(f"source mentions '{m.group(0)}'")
    return consts, out, list(dict.fromkeys(findings)), hex_labels, dlp_hint


def _is_hex_format(node) -> bool:
    """True if the AST expression formats its value as hex (.digits(16), .hex(),
    format(x,'x'), f'{x:x}'...)."""
    if isinstance(node, ast.Call):
        fn = getattr(node.func, "attr", None)
        if fn == "hex":
            return True
        if fn == "digits" and node.args and _number(node.args[0]) == 16:
            return True
        if getattr(node.func, "id", "") == "format":
            for kw in node.keywords:
                if kw.arg and "x" in str(kw.value).lower():
                    return True
    if isinstance(node, ast.JoinedStr):
        for v in node.values:
            if isinstance(v, ast.FormattedValue):
                spec = v.format_spec
                if spec is not None and "x" in ast.unparse(spec).lower():
                    return True
    return False


def load(paths):
    """paths: list of files (.py and/or data). Returns (data_bytes, findings, source_text)."""
    src = ""
    blobs = []
    for p in paths:
        b = Path(p).read_bytes()
        if str(p).lower().endswith(".py"):
            src += b.decode("utf-8", "replace") + "\n"
        else:
            blobs.append(b)
    if not src:
        return b"\n".join(blobs), [], ""
    consts, labels, findings, hex_labels, dlp_hint = analyze_source(src)
    data = b"\n".join(blobs)
    text = data.decode("utf-8", "ignore")
    # Direct labeled-line extraction ("n = 8c...", "c = ...") independent of
    # print-order counting.
    labeled_lines = []
    for m in re.finditer(r"(?m)^\s*([A-Za-z_]\w*)\s*=\s*([0-9a-fA-F]+)\s*$", text):
        k, raw = m.group(1).lower(), m.group(2)
        if k in ("n", "modulus", "c", "ct", "c1", "c2", "g", "m", "x", "secret"):
            val = int(raw, 16) if re.search(r"[a-fA-F]", raw) else int(raw, 10)
            labeled_lines.append(f"{k}=0x{raw}" if re.search(r"[a-fA-F]", raw)
                                 else f"{k}={val}")
    if labeled_lines:
        for k, v in consts.items():
            if k in ("e", "exponent") and "e" not in {l.split("=")[0] for l in labeled_lines}:
                labeled_lines.append(f"e={v}")
        if dlp_hint.get("g") is not None and "g" not in {l.split("=")[0] for l in labeled_lines}:
            labeled_lines.append(f"g={dlp_hint['g']}")
        if "dlp_secret" not in "\n".join(labeled_lines) and dlp_hint.get("g") is not None:
            labeled_lines.append("dlp_secret=1")
        return ("\n".join(labeled_lines) + "\n").encode(), findings, src
    toks = re.findall(r"[0-9a-fA-F]+", text) if blobs else []
    lines = []
    if toks and labels and len(toks) == len(labels):
        for l, t in zip(labels, toks):
            if l in hex_labels or (l in ("n", "c", "c1", "c2", "m", "ct") and re.search(r"[a-fA-F]", t)):
                # hex (no 0x) output
                lines.append(f"{l}=0x{t}")
                findings.insert(0, f"hex-formatted label {l}")
            else:
                # decimal-first, with hex as a second hypothesis
                lines.append(f"{l}={int(t, 10) if t.isdigit() else int(t, 16)}")
                if t.isdigit():
                    lines.append(f"{l}_hex=0x{t}")
        findings.insert(0, "labeled output from print() order: " + ", ".join(labels))
    elif toks and labels:
        findings.insert(0, f"print() has {len(labels)} values but output has {len(toks)}; "
                           "using output as-is")
    have = {l.split("=")[0].rstrip("0123456789") for l in lines}
    for k, v in consts.items():     # constants such as e = 0x11 that are not printed
        if k in ("e", "exponent") and "e" not in have:
            lines.append(f"e={v}")
        elif k in ("n", "p", "q", "phi") and k not in have and v > 255:
            lines.append(f"{k}={v}")
    if dlp_hint.get("g") is not None:
        lines.append(f"g={dlp_hint['g']}")
        lines.append("dlp_secret=1")
    if lines:
        return ("\n".join(lines) + "\n").encode(), findings, src
    return (data or src.encode()), findings, src
