<#
  isitsecure installer (Windows, PowerShell)

  Verifies Python 3.11+ and git (and tells you exactly how to install them if
  they're missing), then does everything else: clones the repo, creates an
  isolated virtual environment, installs isitsecure and its extras, and runs
  first-time setup.

  Usage (from a PowerShell window):
    ./install.ps1                # full install + interactive setup
    ./install.ps1 -SkipSetup     # install only

  Prefer to read before you run (good habit for a security tool):
    irm https://raw.githubusercontent.com/jaurakunal/isitsecure/main/install.ps1 -OutFile install.ps1
    notepad install.ps1 ; ./install.ps1
#>
param([switch]$SkipSetup)

$ErrorActionPreference = "Stop"
$RepoUrl = "https://github.com/jaurakunal/isitsecure.git"

function Ok  ($m) { Write-Host "  [ok] $m"   -ForegroundColor Green }
function Warn($m) { Write-Host "  [--] $m"   -ForegroundColor Yellow }
function Fail($m) { Write-Host "  [xx] $m"   -ForegroundColor Red }
function Step($m) { Write-Host "  -> $m"     -ForegroundColor Magenta }

Write-Host ""
Write-Host "isitsecure installer" -ForegroundColor Magenta
Write-Host "Sets up isitsecure and checks its prerequisites." -ForegroundColor DarkGray
Write-Host ""

# --- 1. Python 3.11+ -------------------------------------------------------
$py = $null
foreach ($cand in @("python", "py", "python3")) {
  if (Get-Command $cand -ErrorAction SilentlyContinue) {
    & $cand -c "import sys; sys.exit(0 if sys.version_info[:2] >= (3, 11) else 1)" 2>$null
    if ($LASTEXITCODE -eq 0) { $py = $cand; break }
  }
}
if (-not $py) {
  Fail "Python 3.11+ was not found."
  Write-Host "     Install it, then re-run this script:"
  Write-Host "       winget install Python.Python.3.12" -ForegroundColor White
  Write-Host "     (or download from https://python.org)" -ForegroundColor DarkGray
  exit 1
}
Ok ("Python: " + (& $py --version))

# --- 2. git ----------------------------------------------------------------
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
  Fail "git was not found."
  Write-Host "     Install it, then re-run: winget install Git.Git" -ForegroundColor White
  exit 1
}
Ok "git installed"

# --- 3. get the source -----------------------------------------------------
if ((Test-Path "pyproject.toml") -and (Select-String -Path "pyproject.toml" -Pattern 'name = "isitsecure"' -Quiet)) {
  $dir = (Get-Location).Path
  Ok "Using this checkout: $dir"
} else {
  $dir = Join-Path (Get-Location).Path "isitsecure"
  if (Test-Path (Join-Path $dir ".git")) {
    Ok "Found existing clone: $dir"
    git -C $dir pull --ff-only 2>$null | Out-Null
  } else {
    Step "Cloning isitsecure..."
    git clone --depth 1 $RepoUrl $dir
    Ok "Cloned to $dir"
  }
}

# --- 4. virtual environment + install --------------------------------------
$venv = Join-Path $dir ".venv"
if (-not (Test-Path $venv)) { Step "Creating virtual environment..."; & $py -m venv $venv }
$vpy  = Join-Path $venv "Scripts\python.exe"
$vexe = Join-Path $venv "Scripts\isitsecure.exe"
Ok "Virtual environment: $venv"

Step "Installing isitsecure and its dependencies (this can take a minute)..."
& $vpy -m pip install --quiet --upgrade pip
& $vpy -m pip install --quiet -e "$dir[all]"
Ok "isitsecure installed"

# --- 5. first-time setup ---------------------------------------------------
if (-not $SkipSetup) {
  Write-Host ""
  Write-Host "Running first-time setup..." -ForegroundColor White
  & $vexe setup
}

# --- 6. done ---------------------------------------------------------------
Write-Host ""
Write-Host "Done! isitsecure is installed in $dir" -ForegroundColor Green
Write-Host ""
Write-Host "Start the web UI:"
Write-Host "    $vexe launch" -ForegroundColor White
Write-Host ""
Write-Host "Tip: add $venv\Scripts to your PATH to run 'isitsecure' from anywhere." -ForegroundColor DarkGray
Write-Host ""
