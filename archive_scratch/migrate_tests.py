#!/usr/bin/env python3
"""One-time migration: move test_*.py -> tests/ and fix path bootstraps.

Called from the repo root. Uses git mv for the move (preserves history) and
in-place rewrites for the bootstrap lines.
"""
import pathlib, re, subprocess, sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
os.chdir(ROOT) if False else None  # noqa

# heavy: git mv each test file, then rewrite
test_files = sorted(ROOT.glob("test_*.py"))
tests_dir = ROOT / "tests"
tests_dir.mkdir(exist_ok=True)

rewritten = []
for f in test_files:
    dest = tests_dir / f.name
    # git mv if tracked, else plain move
    r = subprocess.run(["git", "mv", str(f), str(dest)], capture_output=True)
    if r.returncode != 0:
        # untracked; do a plain filesystem move
        f.rename(dest)
    text = dest.read_text(encoding="utf-8", errors="replace")
    # parent -> parents[1] (repo root) for every bootstrap/ROOT/TMP reference
    new = text.replace('Path(__file__).resolve().parent', 'Path(__file__).resolve().parents[1]')
    # make hardcoded Linux absolute paths portable
    new = new.replace('"/home/chillinmalware/Documents/autocrypt"',
                      'str(Path(__file__).resolve().parents[1])')
    if new != text:
        dest.write_text(new, encoding="utf-8")
        rewritten.append(f.name)

print(f"moved {len(test_files)} test files -> tests/")
print(f"rewritten bootstraps: {rewritten}")
