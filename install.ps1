# install.ps1 - make "autocrypt" a global command on PATH (Windows).
# Idempotent: safe to re-run. Installs into a dedicated venv under $HOME.
# Usage:  powershell -ExecutionPolicy Bypass -File .\install.ps1
param(
  [string]$RepoDir = "",
  [string]$InstallRoot = ""
)
$ErrorActionPreference = 'Stop'

if (-not $RepoDir) {
  $RepoDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
}
if (-not $InstallRoot) {
  $InstallRoot = if ($env:AUTOCRYPT_HOME) { $env:AUTOCRYPT_HOME } else { Join-Path $HOME '.autocrypt' }
}
$VenvDir = Join-Path $InstallRoot 'venv'
$VenvPy = Join-Path $VenvDir 'Scripts\python.exe'
$Bin     = Join-Path $VenvDir 'Scripts'
$Cfg     = Join-Path $VenvDir 'autocrypt.json'

# --- 0. Resolve a real Python first (skip the broken Microsoft Store aliases).
# Do this BEFORE any clone: a machine without Python >=3.12 should fail fast
# with a clear message rather than half-install (clone but no venv) and leave
# the user with a silently-missing "autocrypt" command.
function Get-RealPython($repoDir) {
  $cands = New-Object System.Collections.ArrayList
  if ($env:AUTOCRYPT_PYTHON) { [void]$cands.Add($env:AUTOCRYPT_PYTHON) }
  # PATH lookups, dropping the "Run as alias" Store stubs under WindowsApps.
  foreach ($name in @('python', 'python3', 'py')) {
    $cmd = Get-Command $name -ErrorAction SilentlyContinue
    if ($cmd -and $cmd.Source -and $cmd.Source -notlike '*WindowsApps*') {
      [void]$cands.Add($cmd.Source)
    }
  }
  # Common official-installer locations.
  foreach ($p in @(
      (Join-Path $env:LOCALAPPDATA 'Programs\Python'),
      (Join-Path $HOME 'AppData\Local\Programs\Python'))
  ) {
    if (Test-Path $p) {
      Get-ChildItem $p -Filter python.exe -Recurse -ErrorAction SilentlyContinue |
        ForEach-Object { [void]$cands.Add($_.FullName) }
    }
  }
  # Last resort: the repo's own dev venv, if it exists.
  $repoVenv = Join-Path $repoDir '.venv\Scripts\python.exe'
  if (Test-Path $repoVenv) { [void]$cands.Add($repoVenv) }

  # Walk candidates in priority order; return the first that both exists AND
  # actually meets the Python >=3.12 gate (in case an old build appears earlier).
  foreach ($c in $cands) {
    if (-not ($c -and (Test-Path $c))) { continue }
    $v = & $c -c "import sys; print('%d.%d' % sys.version_info[:2])" 2>$null
    # A candidate may emit nothing (path lookup fails in a child shell), so
    # guard against $null before calling .Split().
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($v)) { continue }
    $p2 = $v.Trim().Split('.')
    if ($p2.Count -lt 2) { continue }
    $maj = 0; $min = 0
    if (-not [int]::TryParse($p2[0], [ref]$maj) -or -not [int]::TryParse($p2[1], [ref]$min)) { continue }
    if ($maj -gt 3 -or ($maj -eq 3 -and $min -ge 12)) {
      return $c
    }
  }
  return $null
}

$py = Get-RealPython $RepoDir
if (-not $py) {
  Write-Host "error: no Python >=3.12 found (Microsoft Store alias or old version detected)." -ForegroundColor Red
  Write-Host "       Install Python 3.12+ from https://www.python.org/downloads/ and re-run." -ForegroundColor Red
  exit 1
}

# If this script was downloaded standalone (irm ... | iex), there is no repo
# next to it — clone the source into the install root first.
if (-not (Test-Path (Join-Path $RepoDir 'pyproject.toml'))) {
  Write-Host "==> autocrypt installer (bootstrapping from github)"
  New-Item -ItemType Directory -Force -Path $InstallRoot | Out-Null
  $Src = Join-Path $InstallRoot 'src'
  if (-not (Test-Path (Join-Path $Src '.git'))) {
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
      Write-Host "error: git is required for the irm installer." -ForegroundColor Red
      exit 1
    }
    git clone --depth 1 https://github.com/marcogamer46/autocrypt.git $Src
    if ($LASTEXITCODE -ne 0) { Write-Host "error: could not clone autocrypt." -ForegroundColor Red; exit 1 }
  } else {
    git -C $Src pull --ff-only 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) {
      Write-Host "error: could not fast-forward existing clone at $Src (diverged?)." -ForegroundColor Red
      Write-Host "       Fix or remove it and re-run the installer." -ForegroundColor Red
      exit 1
    }
  }
  $RepoDir = $Src
}

Write-Host "==> autocrypt installer"
Write-Host "    repo : $RepoDir"
Write-Host "    home : $InstallRoot"

# --- 2. Create venv (once) and install from the local repo -------------------
if (-not (Test-Path $VenvPy)) {
  Write-Host "==> creating venv at $VenvDir"
  New-Item -ItemType Directory -Force -Path $InstallRoot | Out-Null
  & $py -m venv $VenvDir
  if ($LASTEXITCODE -ne 0) { Write-Host "error: venv creation failed." -ForegroundColor Red; exit 1 }
}

Write-Host "==> installing package (editable) from local repo"
& $VenvPy -m pip install --disable-pip-version-check --quiet -e $RepoDir
if ($LASTEXITCODE -ne 0) { Write-Host "error: pip install failed." -ForegroundColor Red; exit 1 }

# Record where the source lives so "autocrypt --update" can git pull + reinstall.
@{ repo = $RepoDir } | ConvertTo-Json | Set-Content -Encoding utf8 -Path $Cfg

# --- 3. Put the console-script directory on PATH -----------------------------
# Current session:
$env:Path = "$Bin;$env:Path"
# Persistent (User scope) - affects all future terminals, idempotent:
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
# Idempotency via exact per-entry equality (split on ';'), NOT substring match:
# a substring check wrongly treats "C:\x\Scripts2" as already containing
# "C:\x\Scripts". PowerShell's -notcontains is case-insensitive by default.
$entries = if ([string]::IsNullOrWhiteSpace($userPath)) { @() } else { $userPath -split ';' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } }
if ($entries -notcontains $Bin) {
  $newPath = if ($entries.Count -eq 0) { $Bin } else { ($entries + $Bin) -join ';' }
  [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
  Write-Host "    added $Bin to User PATH (new terminals will pick it up)"
} else {
  Write-Host "    $Bin already on User PATH"
}

# --- 4. Report ---------------------------------------------------------------
Write-Host ""
Write-Host "Installed. 'autocrypt' is available in NEW terminals."
Write-Host "To use it in THIS terminal now, run:"
Write-Host "  `$env:Path = `"$Bin;`$env:Path`""
if (Get-Command autocrypt -ErrorAction SilentlyContinue) {
  Write-Host "Verify:  autocrypt --help"
}
Write-Host ""
Write-Host "Uninstall:"
Write-Host "  - remove '$Bin' from PATH (Settings > System > About > Advanced system settings > Environment Variables),"
Write-Host "  - delete '$InstallRoot',"
Write-Host "  - or run:  & '$VenvPy' -m pip uninstall autocrypt"
