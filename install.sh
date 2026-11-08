#!/usr/bin/env bash
# install.sh - make "autocrypt" a global command on PATH (Linux/macOS).
# Idempotent: safe to re-run. Installs into a dedicated venv under $HOME.
set -euo pipefail

# Directory of THIS script = the repo root.
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_ROOT="${AUTOCRYPT_HOME:-$HOME/.autocrypt}"
VENV_DIR="$INSTALL_ROOT/venv"
CFG="$VENV_DIR/autocrypt.json"

# If this script was downloaded standalone (curl ... | bash), there is no repo
# next to it — clone the source into the install root first.
if [ ! -f "$REPO_DIR/pyproject.toml" ]; then
  echo "==> autocrypt installer (bootstrapping from github)"
  mkdir -p "$INSTALL_ROOT"
  SRC="$INSTALL_ROOT/src"
  if [ ! -d "$SRC/.git" ]; then
    command -v git >/dev/null 2>&1 || { echo "error: git is required for the curl installer." >&2; exit 1; }
    git clone --depth 1 https://github.com/marcogamer46/autocrypt.git "$SRC" \
      || { echo "error: could not clone autocrypt." >&2; exit 1; }
  else
    # A diverged/force-pushed shallow clone makes a fast-forward pull fail; do
    # not swallow that — a stale install reported as success is worse than a
    # loud failure.
    if ! git -C "$SRC" pull --ff-only >/dev/null 2>&1; then
      echo "error: could not fast-forward existing clone at $SRC (diverged?)." >&2
      echo "       Fix or remove it and re-run the installer." >&2
      exit 1
    fi
  fi
  REPO_DIR="$SRC"
fi

echo "==> autocrypt installer"
echo "    repo : $REPO_DIR"
echo "    home : $INSTALL_ROOT"

# ---------------------------------------------------------------------------
# 1. Resolve a real Python (prefer explicit override, then python3, then python)
# ---------------------------------------------------------------------------
PY=""
for cand in "${AUTOCRYPT_PYTHON:-}" python3 python; do
  if [ -n "$cand" ] && command -v "$cand" >/dev/null 2>&1; then
    PY="$cand"
    break
  fi
done
if [ -z "$PY" ]; then
  echo "error: no python3/python found on PATH. Install Python 3.12+." >&2
  exit 1
fi

# Require Python >= 3.12 (the project does too).
ver="$("$PY" -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
major="${ver%%.*}"; minor="${ver#*.}"; minor="${minor%%.*}"
if [ "$major" -lt 3 ] || { [ "$major" -eq 3 ] && [ "$minor" -lt 12 ]; }; then
  echo "error: autocrypt needs Python >=3.12 (found $ver)." >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# 2. Create the venv (once) and install the package from the local repo
# ---------------------------------------------------------------------------
mkdir -p "$INSTALL_ROOT"

# Detect the venv's script directory (bin/ on POSIX, Scripts/ on Windows-style builds).
if [ -x "$VENV_DIR/bin/python" ]; then
  VPY="$VENV_DIR/bin/python"; BIN="$VENV_DIR/bin"
elif [ -x "$VENV_DIR/Scripts/python.exe" ]; then
  VPY="$VENV_DIR/Scripts/python.exe"; BIN="$VENV_DIR/Scripts"
else
  echo "==> creating venv at $VENV_DIR"
  "$PY" -m venv "$VENV_DIR"
  if [ -x "$VENV_DIR/bin/python" ]; then
    VPY="$VENV_DIR/bin/python"; BIN="$VENV_DIR/bin"
  else
    VPY="$VENV_DIR/Scripts/python.exe"; BIN="$VENV_DIR/Scripts"
  fi
fi

echo "==> installing package (editable) from local repo"
"$VPY" -m pip install --disable-pip-version-check --quiet -e "$REPO_DIR"

# Record where the source lives so "autocrypt --update" can git pull + reinstall.
# Write proper JSON via Python (guaranteed present) so repo paths containing
# quotes/backslashes stay parseable by the updater's json.loads.
"$PY" -c 'import json,sys; json.dump({"repo": sys.argv[1]}, open(sys.argv[2], "w"))' "$REPO_DIR" "$CFG"

# ---------------------------------------------------------------------------
# 3. Put the console-script directory on PATH
# ---------------------------------------------------------------------------
# Apply to the current shell (this script's child process only).
export PATH="$BIN:$PATH"

# Persist for future shells: append one guarded export line to each existing
# profile/shellrc. Fully idempotent (checked with grep -Fqx).
line="export PATH=\"$BIN:\$PATH\""
for rc in "$HOME/.profile" "$HOME/.bashrc" "$HOME/.zshrc"; do
  if [ -f "$rc" ] && ! grep -Fqx -- "$line" "$rc"; then
    printf '\n%s\n' "$line" >> "$rc"
    echo "    added PATH line to $rc"
  fi
done

# ---------------------------------------------------------------------------
# 4. Report
# ---------------------------------------------------------------------------
echo ""
echo "Installed. 'autocrypt' is available in NEW shells."
echo "To use it in THIS terminal now, run one of:  source ~/.bashrc   |   source ~/.profile   |   source ~/.zshrc"
if command -v autocrypt >/dev/null 2>&1; then
  echo "Verify:  autocrypt --help"
fi
echo ""
echo "Uninstall:"
echo "  rm -rf \"$INSTALL_ROOT\""
echo "  # and remove the line(s) printed above from ~/.profile / ~/.bashrc / ~/.zshrc;"
echo "  # or simply:  \"$VPY\" -m pip uninstall autocrypt"
