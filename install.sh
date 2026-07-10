#!/usr/bin/env bash
#
# isitsecure installer (macOS / Linux)
#
# Verifies Python 3.11+ and git (and tells you exactly how to install them if
# they're missing), then does everything else for you: clones the repo, creates
# an isolated virtual environment, installs isitsecure and its extras, and runs
# first-time setup.
#
# Usage:
#   ./install.sh                 # full install + interactive setup
#   ./install.sh --skip-setup    # install only, skip the interactive setup step
#
# Prefer to read before you run (good habit for a security tool):
#   curl -fsSLo install.sh https://raw.githubusercontent.com/jaurakunal/isitsecure/main/install.sh
#   less install.sh && bash install.sh

set -euo pipefail

REPO_URL="https://github.com/jaurakunal/isitsecure.git"
SKIP_SETUP=0
[ "${1:-}" = "--skip-setup" ] && SKIP_SETUP=1

# --- pretty output ---------------------------------------------------------
if [ -t 1 ]; then
  B=$'\033[1m'; D=$'\033[2m'; G=$'\033[32m'; Y=$'\033[33m'; R=$'\033[31m'; M=$'\033[95m'; X=$'\033[0m'
else
  B=""; D=""; G=""; Y=""; R=""; M=""; X=""
fi
ok()   { printf "  ${G}✓${X} %s\n" "$*"; }
warn() { printf "  ${Y}•${X} %s\n" "$*"; }
fail() { printf "  ${R}✗${X} %s\n" "$*" >&2; }
step() { printf "  ${M}→${X} %s\n" "$*"; }

OS="linux"; [ "$(uname -s)" = "Darwin" ] && OS="macos"

printf "\n${M}${B}isitsecure installer${X}\n"
printf "${D}Sets up isitsecure and checks its prerequisites.${X}\n\n"

# --- 1. Python 3.11+ -------------------------------------------------------
PY=""
for cand in python3.13 python3.12 python3.11 python3 python; do
  command -v "$cand" >/dev/null 2>&1 || continue
  if "$cand" -c 'import sys; sys.exit(0 if sys.version_info[:2] >= (3, 11) else 1)' 2>/dev/null; then
    PY="$cand"; break
  fi
done
if [ -z "$PY" ]; then
  fail "Python 3.11+ was not found."
  echo   "     Install it, then re-run this script:"
  if [ "$OS" = "macos" ]; then
    printf "       ${B}brew install python${X}   ${D}(or download from https://python.org)${X}\n"
  else
    printf "       ${B}sudo apt install python3 python3-venv${X}   ${D}(Debian/Ubuntu; use your distro's package manager otherwise)${X}\n"
  fi
  exit 1
fi
ok "Python: $("$PY" --version 2>&1 | awk '{print $2}')"

# --- 2. git ----------------------------------------------------------------
if ! command -v git >/dev/null 2>&1; then
  fail "git was not found."
  if [ "$OS" = "macos" ]; then
    printf "     Install it, then re-run: ${B}xcode-select --install${X}   ${D}(or brew install git)${X}\n"
  else
    printf "     Install it, then re-run: ${B}sudo apt install git${X}\n"
  fi
  exit 1
fi
ok "git: $(git --version | awk '{print $3}')"

# --- 3. get the source (use an existing checkout, else clone) --------------
if [ -f "pyproject.toml" ] && grep -q 'name *= *"isitsecure"' pyproject.toml 2>/dev/null; then
  DIR="$(pwd)"
  ok "Using this checkout: $DIR"
else
  DIR="$(pwd)/isitsecure"
  if [ -d "$DIR/.git" ]; then
    ok "Found existing clone: $DIR"
    git -C "$DIR" pull --ff-only >/dev/null 2>&1 || true
  else
    step "Cloning isitsecure…"
    git clone --depth 1 "$REPO_URL" "$DIR"
    ok "Cloned to $DIR"
  fi
fi

# --- 4. virtual environment + install --------------------------------------
VENV="$DIR/.venv"
[ -d "$VENV" ] || { step "Creating virtual environment…"; "$PY" -m venv "$VENV"; }
ok "Virtual environment: $VENV"

step "Installing isitsecure and its dependencies (this can take a minute)…"
"$VENV/bin/python" -m pip install --quiet --upgrade pip
"$VENV/bin/python" -m pip install --quiet -e "${DIR}[all]"
ok "isitsecure installed"

# --- 5. first-time setup (API key, browser, language servers) --------------
if [ "$SKIP_SETUP" -eq 0 ]; then
  printf "\n${B}Running first-time setup…${X}\n"
  "$VENV/bin/isitsecure" setup || warn "Setup didn't finish — run it later: $VENV/bin/isitsecure setup"
fi

# --- 6. done ---------------------------------------------------------------
printf "\n${G}${B}Done!${X} isitsecure is installed in ${B}%s${X}\n\n" "$DIR"
echo   "Start the web UI:"
printf "    ${B}%s/bin/isitsecure launch${X}\n\n" "$VENV"
echo   "Prefer to type just 'isitsecure' from anywhere? Add an alias:"
printf "    ${D}echo 'alias isitsecure=\"%s/bin/isitsecure\"' >> ~/.zshrc && source ~/.zshrc${X}\n\n" "$VENV"
