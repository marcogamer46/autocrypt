"""Self-update support for ``autocrypt --update``.

The updater is deliberately stdlib-only and imported lazily (inside the
``--update`` branch) so the CLI stays light. It dispatches on how the
installed copy was created:

* **git checkout** — running straight from a clone (package dir sits inside a
  git tree). We ``git fetch`` + ``git pull --ff-only`` and, if the install is a
  non-editable pip copy, reinstall from the source dir.
* **installer-created venv** — the provided ``install.sh`` / ``install.ps1``
  write ``<venv>/autocrypt.json`` with a ``repo`` key. We ``git pull`` there
  and reinstall the editable package into the active venv.
* **pip-installed from GitHub** — ``direct_url.json`` (in the dist-info)
  records a vcs/archive URL. We upgrade with ``pip install --upgrade``.
* **unknown** — print a clear instruction instead of failing cryptically.

No destructive operation is ever performed: only ``git fetch``,
``git pull --ff-only`` and ``pip install --upgrade`` run. In git mode we
refuse to touch a dirty working tree.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from urllib.parse import unquote, urlparse
from urllib.request import url2pathname

FALLBACK_UPSTREAM = "https://github.com/marcogamer46/autocrypt"


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def _find_git_root(start: Path):
    """Walk up from ``start`` until a directory containing ``.git`` is found."""
    for p in (start, *start.parents):
        if (p / ".git").exists():
            return p
    return None


def _run(cmd, cwd=None):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)


def current_version():
    try:
        from importlib.metadata import version
        return version("autocrypt")
    except Exception:
        pass
    try:
        from autocrypt._version import __version__
        return __version__
    except Exception:
        return None


def _direct_url():
    try:
        from importlib.metadata import distribution
        dist = distribution("autocrypt")
        p = Path(dist.locate_file("")) / "direct_url.json"
        return json.loads(p.read_text()) if p.exists() else None
    except Exception:
        return None


def _read_cfg():
    """Read the installer-written <venv>/autocrypt.json (BOM-safe)."""
    cfg = Path(sys.prefix) / "autocrypt.json"
    if not cfg.is_file():
        return None
    try:
        return json.loads(cfg.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        return None


# --------------------------------------------------------------------------
# git mode
# --------------------------------------------------------------------------
def _update_git(root: Path, package_dir: Path):
    """Update a git checkout at ``root``. Returns a process exit code."""
    dirty = _run(["git", "status", "--porcelain"], cwd=root)
    if dirty.stdout.strip():
        print("autocrypt: refusing to update: working tree has uncommitted "
              "changes (commit or stash first).", file=sys.stderr)
        return 1
    branch = _run(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=root)
    branch = branch.stdout.strip() or "main"
    if _run(["git", "fetch", "origin", branch], cwd=root).returncode != 0:
        print("autocrypt: git fetch failed (online? remote configured?).",
              file=sys.stderr)
        return 1
    head = _run(["git", "rev-parse", "HEAD"], cwd=root).std.strip()
    up = _run(["git", "rev-parse", f"origin/{branch}"], cwd=root).std.strip()
    old = current_version() or head[:7]
    if head == up:
        print(f"autocrypt: already latest ({old}).")
        return 0
    pr = _run(["git", "pull", "--ff-only", "origin", branch], cwd=root)
    if pr.returncode != 0:
        print(f"autocrypt: update failed (not a fast-forward):\n{pr.stderr.strip()}",
              file=sys.stderr)
        return 1
    _maybe_reinstall_after_pull(package_dir)
    print(f"autocrypt: updated from {old} -> {current_version() or up[:7]}.")
    return 0


def _is_editable_install():
    du = _direct_url()
    if du is None:
        return False
    return bool(du.get("dir") or du.get("dir_info", {}).get("editable"))


def _maybe_reinstall_after_pull(package_dir):
    if _is_editable_install():
        return  # editable installs share the checkout's files
    subprocess.run([sys.executable, "-m", "pip", "install", "--upgrade",
                    "--no-deps", "."], cwd=package_dir)


# --------------------------------------------------------------------------
# pip mode
# --------------------------------------------------------------------------
def _update_pip():
    old = current_version()
    du = _direct_url()
    if du is None:
        cfg = _read_cfg()
        if cfg and cfg.get("repo"):
            repo = Path(cfg["repo"])
            if repo.is_dir() and _find_git_root(repo):
                return _update_git(repo, repo)
        print("autocrypt: cannot determine how this install was created; "
              "update with: pip install --upgrade autocrypt", file=sys.stderr)
        return 2
    if du.get("dir") or du.get("dir_info", {}).get("editable"):
        url = du.get("url", "")
        if url.startswith("file://"):
            # file:///C:/dev/autocrypt -> C:\dev\autocrypt. Blindly slicing
            # "file://" gives "/C:/..." which WindowsPath misinterprets as a
            # drive-relative path (\C:\...) that never exists, so the git
            # update silently never runs on Windows. Use url2pathname.
            try:
                root = Path(url2pathname(unquote(urlparse(url).path)))
            except Exception:
                root = Path(url[len("file://"):])
            git_root = root if (root / ".git").exists() else _find_git_root(root)
            if git_root:
                return _update_git(git_root, root)
        print("autocrypt: editable install; cannot auto-update (run: "
              "pip install -U -e .)", file=sys.stderr)
        return 1
    url = du.get("url")
    if not url:
        print("autocrypt: install URL unknown; cannot auto-update",
              file=sys.stderr)
        return 2
    spec = f"autocrypt @ {url}"
    print(f"autocrypt: installing {spec}")
    r = subprocess.run([sys.executable, "-m", "pip", "install", "--upgrade", spec])
    if r.returncode != 0:
        return r.returncode
    print(f"autocrypt: updated from {old} -> {current_version()}.")
    return 0


# --------------------------------------------------------------------------
# entry
# --------------------------------------------------------------------------
def do_update():
    """Perform a self-update and return a process exit code."""
    package_dir = Path(__file__).resolve().parent
    # Prefer *recorded* install sources over guessing from an ancestor .git.
    # A non-editable pip install whose site-packages happens to sit under some
    # git repo (e.g. a venv inside a project clone) must NOT be treated as a
    # checkout of autocrypt itself.
    cfg = _read_cfg()
    if cfg and cfg.get("repo"):
        repo = Path(cfg["repo"])
        if repo.is_dir() and _find_git_root(repo):
            return _update_git(repo, repo)
    if _direct_url() is not None:
        # pip-managed install: pip mode handles editable file://, vcs, archive.
        return _update_pip()
    # No pip metadata -> assume a bare source checkout (repo root == git_root).
    git_root = _find_git_root(package_dir)
    if git_root is not None:
        return _update_git(git_root, package_dir)
    return _update_pip()
