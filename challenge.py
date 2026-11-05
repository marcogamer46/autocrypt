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


def _print_data_args(args):
    """Yield (expr, is_hex) for each data-bearing AST expression in print() args.

    Handles the common real-challenge shapes that a naive ``arg in call.args``
    loop misses:
      * f-strings -- ``print(f"n = {n}")`` is a single JoinedStr; yield each
        interpolated FormattedValue.value as its own data label (banner
        segments are skipped), and mark it hex when the field spec is ``:x``.
      * list/tuple prints -- ``print((n, e, c))`` / ``print([n, e, c])``
        yield each element so n/e/c line up with output tokens in order.
    """
    def fmt_spec_hex(v):
        spec = v.format_spec
        return spec is not None and "x" in ast.unparse(spec).lower()

    for arg in args:
        if isinstance(arg, ast.JoinedStr):
            for v in arg.values:
                if isinstance(v, ast.FormattedValue) and v.value is not None:
                    yield v.value, fmt_spec_hex(v)
            continue
        if isinstance(arg, (ast.Tuple, ast.List)):
            yield from _print_data_args(arg.elts)
            continue
        # plain constant banner text is not data
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            continue
        yield arg, _is_hex_format(arg)


def _number(node):
    try:
        v = ast.literal_eval(node)
        return v if isinstance(v, int) and not isinstance(v, bool) else None
    except Exception:
        return None


_STR_BYTES_HINT_NAMES = {"key", "secret", "password", "salt"}


def analyze_source(src: str):
    """Returns (constants, print_labels, findings, hex_labels, dlp_hint, byte_hints).

    `byte_hints` maps lowercased secret names (key/secret/password/salt) to the
    utf-8/raw hex of constant str/bytes assignments. `dlp_hint` may additionally
    carry {"a": int} for pow(g, <int literal>, n) calls (inline private exponent).
    """
    consts, labels, findings = {}, [], []
    hex_labels = set()
    dlp_hint = {}
    byte_hints = {}
    try:
        tree = ast.parse(src)
    except SyntaxError as exc:
        return consts, labels, [f"source not parseable: {exc.msg}"], set(), {}, {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            v = _number(node.value)
            low = node.targets[0].id.lower()
            if v is not None:
                consts[low] = v
            elif isinstance(node.value, ast.Constant) and low in _STR_BYTES_HINT_NAMES:
                val = node.value.value
                if isinstance(val, str):
                    b = val.encode("utf-8", "replace")
                elif isinstance(val, bytes):
                    b = val
                else:
                    b = None
                if b:
                    byte_hints[low] = b.hex()
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
                elif isinstance(enode, ast.Constant) and isinstance(enode.value, int) \
                        and not isinstance(enode.value, bool):
                    # pow(g, <inline int literal>, n) -> private exponent marker.
                    # Keep the FIRST inline exponent (the source's private key for
                    # `A = pow(g, a, p)`) — the DH solver pairs it with the public
                    # value of the other party to recover the shared secret.
                    dlp_hint.setdefault("a", enode.value)
    prints = sorted((n for n in ast.walk(tree) if isinstance(n, ast.Call)
                     and getattr(n.func, "id", "") == "print"), key=lambda n: (n.lineno, n.col_offset))
    seen = {}
    for call in prints:
        for arg, arg_hex in _print_data_args(call.args):
            lab = _label(arg, seen)
            labels.append(lab)
            if arg_hex:
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
    return consts, out, list(dict.fromkeys(findings)), hex_labels, dlp_hint, byte_hints


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


def _hint_lines(text, consts, byte_hints, dlp_hint):
    """Build additive `name=value` hint lines (never executed; safe to append).

    Emits only whitelisted secret constants plus the inline-pow exponent. For a
    DH source (inline pow literal exponent) it also restores p/g/A/B/enc from
    the output text so the Diffie-Hellman solver receives every parameter.
    """
    hints = []
    shift = consts.get("shift")
    if isinstance(shift, int) and 1 <= shift <= 25:
        hints.append(f"shift={shift}")
    seed = consts.get("seed")
    if isinstance(seed, int) and seed > 0:
        hints.append(f"seed={seed}")
    key = consts.get("key")
    if isinstance(key, int):
        hints.append(f"key=0x{key:x}")
    for name in ("key", "secret", "password", "salt"):
        hx = byte_hints.get(name)
        if hx:
            hints.append(f"{name}_bytes=0x{hx}")
    # Multi-prime RSA: propagate explicitly-given prime factors (p1..pN /
    # q1..qN) as hints so the solver can compute phi(n) without factoring.
    prime_factors = []
    for nm in sorted(consts, key=lambda s: (s.rstrip("0123456789"), len(s))):
        base = nm.rstrip("0123456789")
        if base in ("p", "q") and nm != base and isinstance(consts[nm], int) \
                and consts[nm] > 1000:
            prime_factors.append((nm, consts[nm]))
    if len(prime_factors) >= 2 and not any(l.startswith("p1=") or l.startswith("q1=")
                                          for l in hints):
        for nm, pv in prime_factors:
            hints.append(f"{nm}={pv}")
    if dlp_hint.get("a") is not None and not any(l.startswith("a=") for l in hints):
        hints.append(f"a={dlp_hint['a']}")
    if dlp_hint.get("a") is not None:
        # The labeled-line path drops non-whitelisted numeric lines; restore the
        # DH parameters the solver needs (p, g, A, B, and the ciphertext as enc).
        for nm, rx in (
                ("p", r"(?im)^\s*p\s*=\s*((?:0x)?[0-9a-fA-F]+)"),
                ("g", r"(?im)^\s*g\s*=\s*((?:0x)?[0-9a-fA-F]+)"),
                ("A", r"(?im)^\s*A\s*=\s*((?:0x)?[0-9a-fA-F]+)"),
                ("B", r"(?im)^\s*B\s*=\s*((?:0x)?[0-9a-fA-F]+)"),
                ("enc", r"(?im)^\s*(?:ct|c|enc)\s*=\s*((?:0x)?[0-9a-fA-F]+)")):
            m = re.search(rx, text)
            if m:
                raw = m.group(1).strip()
                if nm == "enc":
                    raw = raw[2:] if raw.lower().startswith("0x") else raw
                    hints.append(f"enc=0x{raw}")
                else:
                    hints.append(f"{nm}={raw}")
    return hints


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
    consts, labels, findings, hex_labels, dlp_hint, byte_hints = analyze_source(src)
    data = b"\n".join(blobs)
    text = data.decode("utf-8", "ignore")
    hint_lines = _hint_lines(text, consts, byte_hints, dlp_hint)
    # Direct labeled-line extraction ("n = 8c...", "c = ...") independent of
    # print-order counting.
    labeled_lines = []
    known_labels = set(labels)
    for m in re.finditer(r"(?m)^\s*([A-Za-z_]\w*)\s*=\s*((?:0x)?[0-9a-fA-F]+)\s*$", text):
        k, raw = m.group(1).lower(), m.group(2)
        # Accept the built-in whitelist OR any name the source actually prints as
        # a data label (e.g. n1/n2/n3/c3 in a broadcast). For standalone .txt
        # inputs labels is empty, so behavior is unchanged.
        if k in ("n", "modulus", "c", "ct", "c1", "c2", "ciphertext", "enc",
                 "msg", "message", "g", "m", "p", "q", "s", "e", "x", "secret") \
                or k in known_labels:
            # A value the source formats as hex (e.g. f"{e:x}") is hex even
            # when it happens to contain only digits (0x10001 -> "10001").
            is_hex = (raw.lower().startswith("0x")
                      or bool(re.search(r"[a-fA-F]", raw))
                      or k in hex_labels)
            if raw.lower().startswith("0x"):
                val = int(raw, 16)
                labeled_lines.append(f"{k}=0x{raw[2:]}")
            elif is_hex:
                val = int(raw, 16)
                labeled_lines.append(f"{k}=0x{raw}")
            else:
                val = int(raw, 10)
                labeled_lines.append(f"{k}={val}")
    if labeled_lines:
        for k, v in consts.items():
            if k in ("e", "exponent") and "e" not in {l.split("=")[0] for l in labeled_lines}:
                labeled_lines.append(f"e={v}")
        if dlp_hint.get("g") is not None and "g" not in {l.split("=")[0] for l in labeled_lines}:
            labeled_lines.append(f"g={dlp_hint['g']}")
        if "dlp_secret" not in "\n".join(labeled_lines) and dlp_hint.get("g") is not None:
            labeled_lines.append("dlp_secret=1")
        return ("\n".join(labeled_lines + hint_lines) + "\n").encode(), findings, src
    # Strip `name = ` assignment prefixes before scanning for value tokens.
    # Otherwise hex-looking label names ("c1", "e", "c2" ...) are themselves
    # matched by the hex token regex and corrupt label<->value alignment
    # (seen on c10's broadcast output, where the labels/values stopped lining up).
    stripped = re.sub(r"(?m)^\s*[A-Za-z_]\w*\s*=\s*", "", text)
    # Only value-like tokens (must contain a digit). Prose words in banner
    # text such as "params:" otherwise contribute spurious all-letter tokens
    # ("p","a","a") that break label<->token alignment for tuple/list prints.
    toks = [t for t in re.findall(r"[0-9a-fA-F]+", stripped)
            if re.search(r"\d", t)] if blobs else []
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
        return ("\n".join(lines + hint_lines) + "\n").encode(), findings, src
    if hint_lines:
        tail = ("\n" + "\n".join(hint_lines)).encode()
        return (data or src.encode()) + tail, findings, src
    return (data or src.encode()), findings, src
