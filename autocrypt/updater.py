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
refuse to touch a working tree with *tracked* local modifications; stray
untracked files do not block a fast-forward update.
"""

from __future__ import annotations

import json
import re
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


def _print_whats_new(root: Path):
    """Print the newest changelog section from ``LOGS.md`` after an update.

    LOGS.md appends one section per release, so the newest notes are at the
    end. If the file is missing/unreadable, stay silent (the version delta is
    still reported).
    """
    try:
        txt = (root / "LOGS.md").read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return
    lines = txt.splitlines()
    markers = [i for i, ln in enumerate(lines)
               if ln.startswith("- S40.") or ln.startswith("## Session")]
    start = markers[-1] if markers else max(0, len(lines) - 12)
    section = "\n".join(lines[start:]).strip()
    if not section:
        return
    print("autocrypt: what's new (LOGS.md):")
    print(section[:1200])


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
    """Read the PEP 610 ``direct_url.json`` from the installed dist-info.

    ``importlib.metadata.Distribution.locate_file("")`` returns the
    site-packages root (the *parent* of the ``.dist-info`` directory), so
    appending ``/direct_url.json`` there never finds the file pip writes inside
    ``<name>-<ver>.dist-info/``. ``read_text`` reads from the right place.
    """
    try:
        from importlib.metadata import distribution
        dist = distribution("autocrypt")
        txt = dist.read_text("direct_url.json")
        if txt is None:
            return None
        return json.loads(txt)
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
def _update_git(root: Path):
    """Update a git checkout at ``root``. Returns a process exit code."""
    # Ignore *untracked* files: a stray scratch/build file (e.g. build/,
    # .venv/, a loose note) must not block a fast-forward pull. Only tracked
    # local modifications are dangerous (a pull could conflict with them), so
    # those still refuse.
    dirty = _run(["git", "status", "--porcelain", "--untracked-files=no"],
                 cwd=root)
    if dirty.stdout.strip():
        print("autocrypt: refusing to update: tracked files have local "
              "modifications (commit or stash first).", file=sys.stderr)
        return 1
    branch = _run(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=root)
    branch = branch.stdout.strip() or "main"
    if branch == "HEAD":
        # A detached HEAD (e.g. the user pinned a release tag with
        # `git checkout v1.2`) is not on a branch; there is no branch to
        # fast-forward, and `git pull --ff-only origin HEAD` fails. Refuse
        # with a clear message instead of erroring cryptically.
        print("autocrypt: refusing to update: HEAD is detached (checked out a "
              "tag/commit). Run 'git checkout <branch>' (e.g. main) first.",
              file=sys.stderr)
        return 1
    if _run(["git", "fetch", "origin", branch], cwd=root).returncode != 0:
        print("autocrypt: git fetch failed (online? remote configured?).",
              file=sys.stderr)
        return 1
    head = _run(["git", "rev-parse", "HEAD"], cwd=root).stdout.strip()
    up = _run(["git", "rev-parse", f"origin/{branch}"], cwd=root).stdout.strip()
    if not up:
        # Fetch succeeded but the remote ref is missing (renamed/removed
        # branch, or a bare mirror). Report instead of failing cryptically
        # in the pull below.
        print(f"autocrypt: remote branch 'origin/{branch}' not found after fetch.",
              file=sys.stderr)
        return 1
    old = current_version() or head[:7]
    if head == up:
        print(f"autocrypt: already latest ({old}).")
        return 0
    pr = _run(["git", "pull", "--ff-only", "origin", branch], cwd=root)
    if pr.returncode != 0:
        print(f"autocrypt: update failed (not a fast-forward):\n{pr.stderr.strip()}",
              file=sys.stderr)
        return 1
    if not _maybe_reinstall_after_pull(root):
        # The git pull succeeded; report clearly that the installed copy is
        # stale until the reinstall is fixed, and exit nonzero so scripts know.
        print("autocrypt: code updated but reinstall failed; run "
              "'pip install --upgrade .' from the repo to finish.", file=sys.stderr)
        return 1
    print(f"autocrypt: updated from {old} -> {current_version() or up[:7]}.")
    _print_whats_new(root)
    return 0


def _is_editable_install():
    du = _direct_url()
    if du is None:
        return False
    return bool(du.get("dir") or du.get("dir_info", {}).get("editable"))


def _maybe_reinstall_after_pull(package_dir):
    """Reinstall a non-editable copy after a pull. Returns success bool.

    For editable installs there is nothing to do (they share the checkout's
    files). For non-editable copies we pip-install from the repo root; the
    return code is honored so a failed reinstall is never reported as success.
    """
    if _is_editable_install():
        return True
    r = subprocess.run([sys.executable, "-m", "pip", "install", "--upgrade",
                        "--no-deps", "."], cwd=package_dir,
                       capture_output=True, text=True)
    if r.returncode != 0:
        print("autocrypt: pip reinstall after pull failed "
              f"(exit {r.returncode}):\n{r.stderr.strip()}", file=sys.stderr)
        return False
    return True


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
            # Trust the recorded clone root only when it is *itself* a git
            # root. _find_git_root(repo) could walk up to an unrelated
            # ancestor repository and update the wrong project.
            if repo.is_dir() and (repo / ".git").exists():
                return _update_git(repo)
        print("autocrypt: cannot determine how this install was created; "
              "update with: pip install --upgrade autocrypt", file=sys.stderr)
        return 2
    url = du.get("url", "")
    vcs = du.get("vcs_info", {}) or {}
    editable = bool(du.get("dir") or du.get("dir_info", {}).get("editable"))

    if editable:
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
                return _update_git(git_root)
        if vcs.get("vcs") == "git" or url.startswith("git+"):
            # An editable VCS install (`pip install -e git+...`) keeps its
            # checkout under <venv>/src/<project>; fast-forward it in place.
            src_dir = Path(sys.prefix) / "src"
            for cand in (src_dir / "autocrypt", src_dir):
                if cand.is_dir():
                    g = _find_git_root(cand)
                    if g:
                        return _update_git(g)
        print("autocrypt: editable install; cannot auto-update (run: "
              "pip install -U -e .)", file=sys.stderr)
        return 1

    if not url:
        print("autocrypt: install URL unknown; cannot auto-update",
              file=sys.stderr)
        return 2
    if vcs.get("vcs") == "git" or url.startswith("git+"):
        # PEP 610 stores the *resolved commit* as an @ref on the stored URL
        # (git+https://host/repo.git@<sha>). Reinstalling that verbatim pins
        # us to the old commit forever; strip it to fetch latest.
        url = _strip_vcs_ref(url)
    spec = f"autocrypt @ {url}"
    print(f"autocrypt: installing {_redact(spec)}")
    r = subprocess.run([sys.executable, "-m", "pip", "install", "--upgrade", spec])
    if r.returncode != 0:
        # Normalize to the documented exit 1 (updatable-failure): 2 is
        # reserved for "cannot determine install source". Pip's raw code
        # (commonly 1, sometimes other) must not leak through.
        print("autocrypt: pip install --upgrade failed "
              f"(exit {r.returncode}).", file=sys.stderr)
        return 1
    print(f"autocrypt: updated from {old} -> {current_version()}.")
    return 0


def _redact(text):
    """Redact `user:password@` credentials in a URL/command string."""
    return re.sub(r"(://[^:/@]+):([^@]+)@", r"\1:****@", text)


def _strip_vcs_ref(url):
    """Drop the pinned ``@<commit>`` suffix from a VCS URL.

    ``direct_url.json`` for a non-editable VCS install stores the resolved
    commit as an ``@ref`` (e.g. ``git+https://host/repo.git@abc123``). Keep
    any credentials (``user@host``) that precede the path; strip only an
    ``@`` that appears after the repo path.
    """
    sep = url.find("://")
    if sep == -1:
        return url
    host_path = sep + 3
    slash = url.find("/", host_path)
    if slash == -1:
        return url
    at = url.rfind("@", slash)
    if at == -1:
        return url
    return url[:at]


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
        # The installers record the *clone root*; only trust a path that is
        # itself a git checkout. Falling back to guessing at an unrelated
        # ancestor git repo could update the wrong repository.
        if repo.is_dir() and (repo / ".git").exists():
            return _update_git(repo)
    if _direct_url() is not None:
        # pip-managed install: pip mode handles editable file://, vcs, archive.
        return _update_pip()
    # No pip metadata -> assume a bare source checkout, but ONLY when the
    # package dir is a direct child of the git root (<repo>/autocrypt). A
    # non-editable index install whose site-packages merely sits inside some
    # unrelated git repo (e.g. a venv in a project clone) must not be treated
    # as an autocrypt checkout.
    git_root = _find_git_root(package_dir)
    if git_root is not None and package_dir.parent == git_root:
        return _update_git(git_root)
    return _update_pip()
