"""Regression test for autocrypt's self-updater (autocrypt/updater.py).

Covers the git-update path (`_update_git`), which previously crashed with
AttributeError: 'CompletedProcess' object has no attribute 'std' because the
code used `.std` instead of `.stdout`. The bug only surfaced when the
dirty-tree guard did NOT return early, so a plain import/refusal test could
not catch it — we must actually perform a fast-forward pull.
"""
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import autocrypt.updater as updater  # noqa: E402


def _git(*args, cwd):
    r = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True)
    assert r.returncode == 0, f"git {' '.join(args)} failed: {r.stderr}"
    return r.stdout.strip()


def main():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        remote = tmp / "remote.git"
        # Build the remote from a seed repo, then clone both worktrees from it.
        seed = tmp / "seed"
        seed.mkdir()
        _git("init", "-q", "-b", "main", str(seed), cwd=tmp)
        (seed / "seed.txt").write_text("seed", encoding="utf-8")
        _git("add", "seed.txt", cwd=seed)
        _git("-c", "user.email=t@t", "-c", "user.name=t",
             "commit", "-qm", "seed", cwd=seed)
        _git("clone", "-q", "--bare", str(seed), str(remote), cwd=tmp)
        # Two worktrees: "upstream" (has new commits) and "installed" (the
        # checkout the updater is asked to update).
        upstream = tmp / "upstream"
        installed = tmp / "installed"
        for w in (upstream, installed):
            _git("clone", "-q", str(remote), str(w), cwd=tmp)

        # Upstream makes a new commit (the "update").
        (upstream / "new.txt").write_text("new", encoding="utf-8")
        _git("add", "new.txt", cwd=upstream)
        _git("-c", "user.email=t@t", "-c", "user.name=t",
             "commit", "-qm", "new", cwd=upstream)
        _git("push", "-q", "origin", "main", cwd=upstream)

        before = _git("rev-parse", "HEAD", cwd=installed)
        code = updater._update_git(installed, installed)
        after = _git("rev-parse", "HEAD", cwd=installed)
        assert code == 0, f"expected exit 0, got {code}"
        assert before != after, "fast-forward pull did not advance HEAD"
        assert (installed / "new.txt").exists(), "pulled file missing"
        print(f"PASS: updater git-pull advanced {before[:7]} -> {after[:7]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
