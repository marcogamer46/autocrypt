"""Interactive terminal UI for autocrypt; kept separate from search and solvers."""
from __future__ import annotations

import glob
import json
import os
import re
import shutil
import sys
import textwrap
import threading
import time
from pathlib import Path

VERSION = "1.1"
_ANSI = {"cyan": "\033[36m", "green": "\033[32m", "yellow": "\033[33m",
         "red": "\033[31m", "dim": "\033[90m", "reset": "\033[0m"}

def _width(): return max(1, shutil.get_terminal_size((80, 24)).columns)

# Set by autocrypt.py from the CLI: None = auto-detect (default), True/False
# = force on/off (e.g. `--no-color`). `--no-color` and the NO_COLOR env var
# always win over auto-detection.
COLOR_ENABLED = None

def _color_on():
    if COLOR_ENABLED is not None:
        return bool(COLOR_ENABLED)
    return bool(getattr(sys.stdout, "isatty", lambda: False)()) and "NO_COLOR" not in os.environ

def paint(text, color):
    return f"{_ANSI[color]}{text}{_ANSI['reset']}" if _color_on() else str(text)

def _safe(text):
    """Coerce text to something the console can encode; never raise on a
    legacy (e.g. cp1252) terminal even in non-color mode."""
    try:
        return str(text).encode(sys.stdout.encoding or "utf-8", "replace").decode(
            sys.stdout.encoding or "utf-8")
    except (LookupError, UnicodeEncodeError):
        return str(text)

def _unicode():
    try: "┌─│└─┘─┐░█".encode(getattr(sys.stdout, "encoding", None) or "utf-8"); return True
    except (LookupError, UnicodeEncodeError): return False

def _fit(text, width): return text[:max(0, width)]

def banner(width=None):
    width = max(1, width or _width())
    if width >= 40:
        art = [
            "  _   _ _   _ _____ ___  ____  _____",
            " /_\\ | | | | |_   _/ _ \\|  _ \\|_   _|",
            "/ _ \\| |_| | | | || (_) | |_) | | |",
            "/_/ \\_\\___/|_| |_| \\___/|  __/  |_|",
        ]
    else:
        art = ["autocrypt"]
    tag = f"autocrypt v{VERSION} — CTF crypto triage"
    tag = tag.encode("ascii", "replace").decode("ascii")
    lines = [_fit(line, width) for line in art]
    lines.extend(_fit(line, width) for line in textwrap.wrap(tag, width=max(1, width)))
    return "\n".join(paint(line, "cyan") for line in lines)

def confidence_bar(value, width=10):
    value = max(0.0, min(1.0, float(value)))
    filled = round(value * width)
    glyphs = ("█", "░") if _unicode() else ("#", ".")
    bar = f"[{glyphs[0] * filled}{glyphs[1] * (width - filled)}] {value:.2f}"
    color = "green" if value >= .75 else "yellow" if value >= .4 else "red"
    return paint(bar, color)

def _wrap_lines(lines, width):
    output = []
    for line in lines:
        if not line:
            output.append("")
        else:
            output.extend(textwrap.wrap(str(line), width=max(1, width),
                                        break_long_words=True, break_on_hyphens=False) or [""])
    return output

def box(title, lines, width=None, color="cyan"):
    width = max(1, width or _width())
    inner = max(1, width - 4)
    contents = _wrap_lines(lines, inner)
    if width < 6:
        return "\n".join(_fit(s, width) for s in [title, *contents])
    if _unicode():
        top, side, bottom = "┌", "│", "└"
        horiz = "─"
    else:
        top, side, bottom = "+", "|", "+"
        horiz = "-"
    head = f"{top}{horiz} {title} "
    head = head + horiz * max(0, width - len(head) - 1) + ("┐" if _unicode() else "+")
    rows = [head[:width]]
    rows.extend(f"{side} {line:<{inner}} {side}" for line in contents)
    rows.append(f"{bottom}{horiz * (width - 2)}" + ("┘" if _unicode() else "+"))
    return "\n".join(paint(row, color) for row in rows)

def fingerprint_panel(fp, width=None):
    encodings = ", ".join(f"{name} {prior:.2f}" for name, prior in fp["hypotheses"]) or "none detected"
    return box("Fingerprint", [
        f"Length: {fp['length']} bytes   Entropy: {fp['entropy']:.3f} bits/byte",
        f"Charset: {fp['charset']}   IC: {fp['ic']:.4f}",
        "Detected encodings (prior): " + encodings,
        *(["Tells: " + ", ".join(fp["magic"])] if fp["magic"] else []),
        *(["Hash hints: " + ", ".join(fp["hashes"])] if fp["hashes"] else []),
    ], width)

def empty_panel(status, width=None):
    messages = {
        "TIMEOUT": ("Timed out", "Time budget expired before a result was recovered."),
        "TOO_SHORT": ("Input too short to judge", "Not enough text for reliable statistical evidence."),
        "SOLVER_FAILED": ("Solver failed", "A solver failed or was cut short, so this result is unreliable"),
        "NOT_FOUND": ("No weakness found", "Looks like properly encrypted or random data."),
    }
    title, message = messages.get(status, messages["NOT_FOUND"])
    color = "yellow" if status in ("TIMEOUT", "TOO_SHORT", "SOLVER_FAILED") else "green"
    return box(title, [message], width, color)

def verdict_banner(results):
    """A one-line headline verdict for the ranked results."""
    if not results:
        return ""
    top = results[0]
    conf = top.get("confidence", 0.0)
    plain = str(top.get("plaintext", "")).strip()
    if top.get("is_flag") and conf >= 0.80:
        msg = "Flag-like result at rank 1 (confidence {:.2f})".format(conf)
        if plain and len(plain) <= 200 and "\n" not in plain:
            return _safe(paint(msg + "\n" + plain, "green"))
        return _safe(paint(msg, "green"))
    if conf >= 0.80:
        return _safe(paint("Best guess at rank 1 (confidence {:.2f})".format(conf), "yellow"))
    return _safe(paint("Low-confidence candidates only - treat with caution.", "yellow"))

def results_panel(results, width=None, preview_boxes=3):
    width = max(1, width or _width())
    lines, plaintext_boxes = [], []
    for rank, item in enumerate(results, 1):
        badge = paint(" FLAG", "green") if item.get("is_flag") else ""
        lines.append(f"#{rank} {confidence_bar(item.get('confidence', 0))}{badge}")
        lines.extend("  " + part for part in _wrap_lines(
            ["Chain: " + item.get("chain", "")], max(1, width - 4)))
        reason = item.get("_reason", "")
        if reason:
            color = ("yellow" if reason.startswith(("LOW CONFIDENCE", "Partial solve:"))
                     else "dim")
            lines.extend("  " + paint(part, color) for part in _wrap_lines([reason], max(1, width - 4)))
        plain = str(item.get("plaintext", ""))
        shown = plain[:2400]
        chunks = _wrap_lines(shown.splitlines() or [""], max(1, width - 6))
        if len(plain) > len(shown):
            chunks.append("[preview truncated; save results for full plaintext]")
        plaintext_boxes.append(box(f"Plaintext #{rank}", chunks, width, "cyan"))
    sections = [box(f"Ranked results ({len(results)})", lines, width, "cyan")]
    # By default only preview the top few full plaintexts; the summaries above
    # always list every rank, and "save" writes all of them regardless.
    sections.extend(plaintext_boxes[:max(1, preview_boxes)])
    if len(plaintext_boxes) > max(1, preview_boxes):
        sections.append(paint(f"(... {len(plaintext_boxes) - max(1, preview_boxes)} more plaintexts; "
                              "use save to write them all)", "dim"))
    # A higher timeout budget can surface additional lower-ranked candidates
    # (best-first search runs more solvers) — never changes the top result.
    sections.append(paint("Raising the timeout may reveal more lower-ranked candidates "
                          "(never changes the top).", "dim"))
    return "\n".join(sections)

def _valid_regex(pattern):
    try: re.compile(pattern, re.DOTALL); return True, ""
    except re.error as exc: return False, str(exc)

def _tab_completion():
    try:
        import readline; readline.set_completer(lambda t, s: (lambda m: m[s] if s < len(m) else None)(glob.glob(t + "*"))); readline.parse_and_bind("tab: complete")
    except (ImportError, AttributeError): pass

def _settings(settings):
    while True:
        print(box("Settings", [
            f"1. Flag format: {settings['flag_format']}",
            f"2. Timeout: {settings['timeout']} seconds",
            f"3. Top-N: {settings['top']}",
            f"4. Known-plaintext crib: {settings['known_plaintext'] or '(none)'}",
            f"5. Wordlist: {settings['wordlist'] or '(none)'}",
            "0. Back",
        ]))
        try:
            choice = input("Change setting: ").strip().lower()
        except EOFError:
            return False
        if choice in ("0", "b", "back"):
            return True
        try:
            if choice in ("1", "f"):
                value = input("Flag regex: ")
                valid, error = _valid_regex(value)
                if not valid:
                    print(paint(f"Invalid regex: {error}", "red"))
                else:
                    settings["flag_format"] = value
                    settings["flag_format_explicit"] = True
            elif choice in ("2", "t"):
                value = float(input("Timeout seconds: "))
                if value <= 0:
                    raise ValueError("timeout must be positive")
                settings["timeout"] = value
            elif choice in ("3", "n"):
                value = int(input("Top-N: "))
                if value < 0:
                    raise ValueError("top-N must be nonnegative")
                settings["top"] = value
            elif choice in ("4", "k"):
                settings["known_plaintext"] = input("Known plaintext (empty clears): ")
            elif choice in ("5", "w"):
                settings["wordlist"] = input("Wordlist path (empty clears): ").strip()
            else:
                print(paint("Choose 0–5.", "yellow"))
        except (ValueError, EOFError) as exc:
            if isinstance(exc, EOFError): return False
            print(paint(f"Invalid value: {exc}", "red"))

_HELP = {
    "base16": ("Hex bytes", "48656c6c6f"), "base32": ("RFC 4648 base32", "JBSWY3DP"),
    "base64": ("Base64/base64url", "SGVsbG8="), "base58": ("Bitcoin base58", "JxF12TrwUP45BMd"),
    "base85": ("Base85/ASCII85", "NM&qn"), "url": ("Percent URL encoding", "hello%20world"),
    "binary": ("Eight-bit binary bytes", "01001000 01101001"), "octal": ("Octal byte values", "110 145 154"),
    "decimal": ("Decimal byte values", "72 101 108"), "morse": ("Morse letters/words", ".... . .-.. .-.. ---"),
    "quoted-printable": ("Quoted-printable bytes", "hello=20world"), "a1z26": ("A1Z26 mapping", "8-5-12-12-15"),
    "bacon": ("Bacon A/B groups", "AABBA ABBAA"), "polybius": ("Polybius coordinate pairs", "23 15"),
    "PEM": ("PEM body/base64 extraction", "-----BEGIN PUBLIC KEY-----"), "zlib/gzip": ("Magic decompression", "gzip bytes"),
    "reverse": ("Reverse text", "!dlrow olleH"), "caesar": ("All Caesar shifts", "synt{...}"),
    "ROT13": ("ROT13 transformation", "synt{...}"), "ROT47": ("Printable-ASCII ROT47", "w6==@"),
    "atbash": ("Alphabet reversal", "zgyzhs"), "affine": ("Brute-force affine keys", "Ihhwvc swfrcpu"),
    "vigenere-family": ("Vigenere/Beaufort variants", "ciphertext; optional crib"),
    "autokey": ("Autokey, optionally cribbed", "ciphertext + known plaintext"),
    "rail-fence": ("Rail-fence transposition", "Wrivdlaneaedsoee"), "scytale": ("Scytale transposition", "transposed text"),
    "columnar-transposition": ("Columnar transposition", "long transposed text"),
    "monoalphabetic-substitution": ("Substitution hill-climb", "long English-like ciphertext"),
    "playfair": ("Playfair square hill-climb", "BMODZBXDNABEKUDMUIXMMOUVIF"),
    "xor-single-byte": ("Single-byte XOR", "hex or binary ciphertext"),
    "xor-repeating": ("Repeating-key XOR", "1e2b2027... (hex bytes)"),
    "known-plaintext-XOR": ("XOR crib recovery", "ciphertext + --known-plaintext"),
    "many-time-pad": ("Crib-drag multiple hex ciphertexts", "hex-cipher-1\\nhex-cipher-2"),
    "JWT": ("Decode JWT; try none/HS256 wordlist", "header.payload.signature"),
    "hash-identification": ("Identify/crack hash with wordlist", "5ebe2294ecd0e0f08eab7690d2a6ee69"),
    "RSA": ("Small-e, factoring, and related attacks", "n=...,e=3,c=..."),
}

def _help():
    import solvers
    from core import REGISTRY
    lines = (f"{x.name}: {d} Example: {e}" for x in REGISTRY
             for d, e in [_HELP.get(x.name, ("Registered solver.", "unknown ciphertext"))])
    print(box("Solver help", list(lines), color="cyan"))

def _save(results):
    try:
        path = input("Save path (.txt or .json): ").strip()
    except EOFError:
        return
    if not path:
        return
    public = [{k: row[k] for k in ("chain", "plaintext", "confidence", "is_flag")}
              for row in results]
    try:
        if Path(path).suffix.lower() == ".json":
            Path(path).write_text(json.dumps(public, ensure_ascii=False, indent=2) + "\n",
                                  encoding="utf-8")
        else:
            text = "\n\n".join(
                f"{i}. {row['chain']}\nConfidence: {row['confidence']:.2f}"
                f"{' FLAG' if row['is_flag'] else ''}\n{row['plaintext']}"
                for i, row in enumerate(results, 1))
            Path(path).write_text(text + "\n", encoding="utf-8")
        print(paint(f"Saved full results to {path}", "green"))
    except OSError as exc:
        print(paint(f"Could not save: {exc}", "red"))

def _solve(data, settings, params=""):
    import autocrypt
    active = ["starting"]
    stop = threading.Event()
    tty = bool(getattr(sys.stdout, "isatty", lambda: False)())

    def progress(name):
        active[0] = name or "searching"

    def animate():
        start = time.monotonic()
        frames = "|/-\\"
        i = 0
        while not stop.wait(.12):
            raw = f" {frames[i % 4]} Solving: {active[0]}  {time.monotonic() - start:5.1f}s"
            sys.stdout.write("\r" + paint(_fit(raw, _width()), "cyan"))
            sys.stdout.flush()
            i += 1

    thread = None
    if tty:
        thread = threading.Thread(target=animate, daemon=True)
        thread.start()
    try:
        return autocrypt.solve_data(
            data, flag_format=settings["flag_format"], timeout=settings["timeout"],
            top=settings["top"], known_plaintext=settings["known_plaintext"],
            wordlist_path=settings["wordlist"], params=params,
            progress_callback=progress, flag_format_explicit=settings["flag_format_explicit"],
        )
    finally:
        if thread:
            stop.set()
            thread.join()
            sys.stdout.write("\r" + " " * _width() + "\r")
            sys.stdout.flush()

def _show(data, settings, params=""):
    _t0 = time.monotonic()
    fp, results, ctx = _solve(data, settings, params)
    _elapsed = time.monotonic() - _t0
    print(fingerprint_panel(fp))
    verdict = verdict_banner(results)
    if verdict:
        print(verdict)
    print("\n".join(paint("Finding: " + f, "yellow") for f in dict.fromkeys(ctx.findings)))
    print("\n".join(paint("Solver failure: " + f, "red") for f in dict.fromkeys(ctx.failures)))
    if results:
        print(results_panel(results))
    else:
        print(empty_panel(results.status))
    print(paint(f"Solved in {_elapsed:.1f}s (budget {settings['timeout']:.0f}s).", "dim"))
    return results

def _paste():
    print(paint("Paste ciphertext; finish with an empty line or Ctrl-D.", "dim"))
    lines = []
    while True:
        try:
            line = input()
        except EOFError: break
        if not line: break
        lines.append(line)
    return "\n".join(lines).encode("utf-8")

def _rsa_input():
    first = input("Paste n=..., e=..., c=... (or enter n): ").strip()
    if not first:
        return "", b""
    if "=" in first: return first, first.encode()
    n, e, c = first, input("e: ").strip(), input("c: ").strip()
    spec = f"n={n},e={e},c={c}"
    return spec, spec.encode()

def _post_solve(results, settings):
    while True:
        print(paint("What next? [1] solve  [2] re-run top  [3] save  [4] settings  [5] quit", "dim"))
        try:
            choice = input("> ").strip().lower()
        except EOFError:
            return "quit"
        if choice in ("1", "s", "solve"):
            return "menu"
        if choice in ("2", "r", "rerun"):
            return ("rerun", results[0]["plaintext"].encode("utf-8")) if results else "menu"
        if choice in ("3", "w", "save"):
            _save(results)
        elif choice in ("4", "c", "settings"):
            if not _settings(settings):
                return "quit"
        elif choice in ("5", "q", "quit"):
            return "quit"
        else:
            print(paint("Choose 1–5.", "yellow"))

def interactive():
    if os.name == "nt":
        try:
            os.system("")
            import colorama
            colorama.just_fix_windows_console()
        except (ImportError, AttributeError):
            pass
    settings = {"flag_format": r"\w{1,40}\{.*?\}", "flag_format_explicit": False, "timeout": 20.0,
                "top": 5, "known_plaintext": "", "wordlist": ""}
    last = {}
    print(banner())
    _tab_completion()
    while True:
        print(box("Main menu", [
            "1. Paste ciphertext", "2. Load from file", "3. Enter RSA parameters",
            "4. Settings", "5. Help", "6. Quit"]))
        try:
            choice = input("Select 1–6 (or a letter): ").strip().lower()
        except EOFError:
            return 0
        except KeyboardInterrupt:
            try:
                quit_now = input("\nQuit autocrypt? [y/N] ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                return 0
            if quit_now in ("y", "yes"):
                return 0
            continue
        try:
            params = ""
            if choice in ("1", "p"):
                data = _paste()
                last.update(notes=[], source="")
            elif choice in ("2", "f"):
                import shlex, challenge
                raw = input("File path(s) — data .txt and/or challenge .py (space-separated): ").strip()
                try:
                    data, notes, source = challenge.load(shlex.split(raw))
                except (OSError, ValueError) as exc:
                    print(paint(f"Cannot load file: {exc}", "red"))
                    continue
                last.update(notes=notes, source=source)
                for n in notes:
                    print(paint("Challenge: " + n, "yellow"))
            elif choice in ("3", "r"):
                params, data = _rsa_input()
            elif choice in ("4", "s"):
                if not _settings(settings):
                    return 0
                continue
            elif choice in ("5", "h"):
                _help()
                continue
            elif choice in ("6", "q"):
                return 0
            else:
                print(paint("Choose 1–6.", "yellow"))
                continue
            while True:
                try:
                    results = _show(data, settings, params)
                    last.update(data=data, results=results)
                except KeyboardInterrupt:
                    print(paint("\nSolve cancelled; returning to the menu.", "yellow"))
                    break
                action = _post_solve(results, settings)
                if action == "quit":
                    return 0
                if action == "menu":
                    break
                _, data = "rerun", action[1]
                params = ""
        except EOFError:
            return 0
        except KeyboardInterrupt:
            print(paint("\nCancelled; returning to the menu.", "yellow"))
        except Exception as exc:
            print(paint(f"Error: {exc}", "red"))
