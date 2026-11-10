"""Regression test for autocrypt's self-updater (autocrypt/updater.py).

Covers the git-update path (`_update_git`), which previously crashed with
AttributeError: 'CompletedProcess' object has no attribute 'std' because the
code used `.std` instead of `.stdout`. The bug only surfaced when the
dirty-tree guard did NOT return early, so a plain import/refusal test could
not catch it — we must actually perform a fast-forward pull.

Also covers the reinstall step: a failed ``pip install`` after a successful
pull must surface as a nonzero exit (it used to be silently swallowed and
reported as a successful update), and an editable install (the installer's
layout) must skip the reinstall and return success.
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
        # The installer installs the package editable (pip install -e), so
        # _is_editable_install() is True and the post-pull reinstall is
        # skipped. Simulate that so the git-pull path returns success.
        _orig_editable = updater._is_editable_install
        updater._is_editable_install = lambda: True
        try:
            code = updater._update_git(installed)
        finally:
            updater._is_editable_install = _orig_editable
        after = _git("rev-parse", "HEAD", cwd=installed)
        assert code == 0, f"expected exit 0, got {code}"
        assert before != after, "fast-forward pull did not advance HEAD"
        assert (installed / "new.txt").exists(), "pulled file missing"
        print(f"PASS: updater git-pull advanced {before[:7]} -> {after[:7]}")

        # Non-editable install: after the pull, the reinstall runs. A failed
        # `pip install` must surface as a nonzero exit, not be swallowed.
        # Push another upstream commit so the installed checkout is behind again
        # and the pull path is actually exercised.
        (upstream / "new2.txt").write_text("new2", encoding="utf-8")
        _git("add", "new2.txt", cwd=upstream)
        _git("-c", "user.email=t@t", "-c", "user.name=t",
             "commit", "-qm", "new2", cwd=upstream)
        _git("push", "-q", "origin", "main", cwd=upstream)
        updater._is_editable_install = lambda: False
        _real_run = updater.subprocess.run
        def _fake_pip(cmd, **kw):
            if cmd[:2] == [updater.sys.executable, "-m"] and "pip" in cmd:
                return updater.subprocess.CompletedProcess(cmd, 1, "", "boom\n")
            return _real_run(cmd, **kw)
        updater.subprocess.run = _fake_pip
        try:
            code = updater._update_git(installed)
        finally:
            updater.subprocess.run = _real_run
            updater._is_editable_install = _orig_editable
        assert code == 1, f"expected exit 1 when reinstall fails, got {code}"
        print("PASS: updater surfaces a failed post-pull reinstall (exit 1)")

        # Untracked scratch files must NOT block a fast-forward update. (The
        # user hit this as "refusing to update: working tree has uncommitted
        # changes" from a build/ or stray file.)
        installed2 = tmp / "installed2"
        _git("clone", "-q", str(remote), str(installed2), cwd=tmp)
        (installed2 / "scratch.txt").write_text("local scratch", encoding="utf-8")
        (upstream / "new3.txt").write_text("new3", encoding="utf-8")
        _git("add", "new3.txt", cwd=upstream)
        _git("-c", "user.email=t@t", "-c", "user.name=t",
             "commit", "-qm", "new3", cwd=upstream)
        _git("push", "-q", "origin", "main", cwd=upstream)
        before2 = _git("rev-parse", "HEAD", cwd=installed2)
        updater._is_editable_install = lambda: True
        try:
            code2 = updater._update_git(installed2)
        finally:
            updater._is_editable_install = _orig_editable
        after2 = _git("rev-parse", "HEAD", cwd=installed2)
        assert code2 == 0, f"expected exit 0 with only untracked files, got {code2}"
        assert before2 != after2, "untracked file blocked the update"
        print("PASS: updater ignores untracked files (ff-pull succeeds)")

        # A *tracked* local modification must still refuse (HEAD unchanged).
        installed3 = tmp / "installed3"
        _git("clone", "-q", str(remote), str(installed3), cwd=tmp)
        (installed3 / "seed.txt").write_text("local tracked change", encoding="utf-8")
        (upstream / "new4.txt").write_text("new4", encoding="utf-8")
        _git("add", "new4.txt", cwd=upstream)
        _git("-c", "user.email=t@t", "-c", "user.name=t",
             "commit", "-qm", "new4", cwd=upstream)
        _git("push", "-q", "origin", "main", cwd=upstream)
        before3 = _git("rev-parse", "HEAD", cwd=installed3)
        updater._is_editable_install = lambda: True
        try:
            code3 = updater._update_git(installed3)
        finally:
            updater._is_editable_install = _orig_editable
        after3 = _git("rev-parse", "HEAD", cwd=installed3)
        assert code3 == 1, f"expected exit 1 with a tracked modification, got {code3}"
        assert before3 == after3, "tracked modification did not refuse (HEAD moved)"
        print("PASS: updater still refuses on tracked local modifications")
    return 0


if __name__ == "__main__":
    sys.exit(main())
