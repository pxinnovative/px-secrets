#!/usr/bin/env bash
# PX Secrets — One-command Installer
# SPDX-License-Identifier: AGPL-3.0-or-later
# https://github.com/pxinnovative/px-secrets
#
# Compatible with bash 3.2+ (macOS default)

# ── Constants ─────────────────────────────────────────────────────────────────
APP_NAME="PX Secrets"
APP_VERSION="1.3.0"
REPO_URL="https://github.com/pxinnovative/px-secrets"
MIN_PYTHON_VERSION="3.9"
INSTALL_DIR="${HOME}/.local/bin"
SCRIPT_NAME="px-secrets"
PIP_DEPS="flask pyyaml"
PIP_DEPS_OPTIONAL="pywebview"

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { printf "${BLUE}[info]${RESET}  %s\n" "$1"; }
ok()      { printf "${GREEN}[  ok]${RESET}  %s\n" "$1"; }
warn()    { printf "${YELLOW}[warn]${RESET}  %s\n" "$1"; }
fail()    { printf "${RED}[fail]${RESET}  %s\n" "$1" >&2; }
step()    { printf "\n${BOLD}── Step %s ──────────────────────────────────────────${RESET}\n" "$1"; }
die()     { fail "$1"; echo ""; echo "  Aborting. Fix the issue above and re-run install.sh"; exit 1; }

# ── CLI flags ─────────────────────────────────────────────────────────────────
AUTO_YES=false
SKIP_OPTIONAL=false

usage() {
  cat <<EOF
Usage: $0 [options]

Options:
  -y, --yes            Skip all confirmations (auto-yes)
  --skip-optional      Skip optional dependency (pywebview native window)
  -h, --help           Show this help message

Examples:
  bash install.sh            Interactive install
  bash install.sh -y         Unattended install
EOF
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -y|--yes)           AUTO_YES=true; shift ;;
    --skip-optional)    SKIP_OPTIONAL=true; shift ;;
    -h|--help)          usage ;;
    *)                  echo "Unknown option: $1"; usage ;;
  esac
done

# Prompt — returns 0 (yes) or 1 (no). Respects --yes flag.
confirm() {
  local msg="$1"
  local default="${2:-y}"
  if $AUTO_YES; then return 0; fi
  local prompt
  if [[ "$default" == "y" ]]; then prompt="[Y/n]"; else prompt="[y/N]"; fi
  read -r -p "$(printf "${YELLOW}?${RESET}  $msg $prompt ") " reply
  reply="${reply:-$default}"
  [[ "$reply" =~ ^[Yy]$ ]]
}

# ── Banner ────────────────────────────────────────────────────────────────────
printf "\n"
printf "  ╔═══════════════════════════════════════════╗\n"
printf "  ║   ${BOLD}PX Secrets${RESET} — SOPS + AGE Vault Manager   ║\n"
printf "  ║   v${APP_VERSION}   •   Free & Open Source (AGPL-3.0)  ║\n"
printf "  ╚═══════════════════════════════════════════╝\n"
printf "\n"

# ── Step 1: OS check ──────────────────────────────────────────────────────────
step "1: System check"

OS="$(uname -s)"
case "$OS" in
  Darwin) ok "macOS detected" ;;
  Linux)  ok "Linux detected" ;;
  *)      warn "Unsupported OS: $OS — proceeding anyway, results may vary" ;;
esac

# ── Step 2: Python ────────────────────────────────────────────────────────────
step "2: Python $MIN_PYTHON_VERSION+"

PYTHON=""
for cmd in python3 python; do
  if command -v "$cmd" &>/dev/null; then
    ver="$($cmd --version 2>&1 | awk '{print $2}')"
    major="${ver%%.*}"
    minor="${ver#*.}"; minor="${minor%%.*}"
    if [[ "$major" -ge 3 && "$minor" -ge 9 ]]; then
      PYTHON="$cmd"
      ok "Found $cmd $ver"
      break
    else
      warn "$cmd $ver is too old (need $MIN_PYTHON_VERSION+)"
    fi
  fi
done

if [[ -z "$PYTHON" ]]; then
  die "Python $MIN_PYTHON_VERSION+ not found. Install it from https://python.org or via Homebrew: brew install python"
fi

# ── Step 3: Homebrew (macOS only) ─────────────────────────────────────────────
if [[ "$OS" == "Darwin" ]]; then
  step "3: Homebrew"
  if command -v brew &>/dev/null; then
    ok "Homebrew found at $(brew --prefix)"
  else
    warn "Homebrew not found."
    if confirm "Install Homebrew? (recommended for SOPS + AGE)"; then
      info "Installing Homebrew..."
      /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)" || die "Homebrew installation failed"
      ok "Homebrew installed"
    else
      info "Skipping Homebrew. You'll need to install SOPS and AGE manually."
    fi
  fi
else
  step "3: Homebrew (skipped — Linux)"
  info "Install SOPS and AGE from their GitHub releases if not already installed."
fi

# ── Step 4: SOPS ──────────────────────────────────────────────────────────────
step "4: SOPS"
if command -v sops &>/dev/null; then
  ok "SOPS found: $(sops --version 2>&1 | head -1)"
else
  warn "SOPS not found."
  if [[ "$OS" == "Darwin" ]] && command -v brew &>/dev/null; then
    if confirm "Install SOPS via Homebrew?"; then
      brew install sops || die "Failed to install SOPS"
      ok "SOPS installed"
    else
      die "SOPS is required. Install it with: brew install sops"
    fi
  else
    die "SOPS is required. Install from: https://github.com/getsops/sops/releases"
  fi
fi

# ── Step 5: AGE ───────────────────────────────────────────────────────────────
step "5: AGE"
if command -v age &>/dev/null && command -v age-keygen &>/dev/null; then
  ok "AGE found: $(age --version 2>&1 | head -1)"
else
  warn "AGE not found."
  if [[ "$OS" == "Darwin" ]] && command -v brew &>/dev/null; then
    if confirm "Install AGE via Homebrew?"; then
      brew install age || die "Failed to install AGE"
      ok "AGE installed"
    else
      die "AGE is required. Install it with: brew install age"
    fi
  else
    die "AGE is required. Install from: https://github.com/FiloSottile/age/releases"
  fi
fi

# ── Step 6: Python dependencies ───────────────────────────────────────────────
step "6: Python dependencies"

PIP_CMD="$PYTHON -m pip"
info "Installing: $PIP_DEPS"
$PIP_CMD install --quiet $PIP_DEPS || die "Failed to install Python dependencies"
ok "flask, pyyaml installed"

if ! $SKIP_OPTIONAL; then
  echo ""
  info "Optional: pywebview enables a native app window (no browser tab needed)"
  if confirm "Install pywebview? (optional, ~50 MB)"; then
    $PIP_CMD install --quiet pywebview && ok "pywebview installed" || warn "pywebview install failed — app will open in browser instead"
  else
    info "Skipping pywebview — app will open in your default browser"
  fi
fi

# ── Step 7: Install px-secrets command ────────────────────────────────────────
step "7: Install px-secrets command"

SCRIPT_SRC="$(cd "$(dirname "$0")/core/code" && pwd)/px_secrets.py"
if [[ ! -f "$SCRIPT_SRC" ]]; then
  # Fallback: look relative to script location
  SCRIPT_SRC="$(cd "$(dirname "$0")" && pwd)/px_secrets.py"
fi

if [[ ! -f "$SCRIPT_SRC" ]]; then
  die "Cannot find px_secrets.py. Run install.sh from the repo root directory."
fi

mkdir -p "$INSTALL_DIR"

DEST="$INSTALL_DIR/$SCRIPT_NAME"
cp "$SCRIPT_SRC" "$DEST"
chmod +x "$DEST"
ok "Copied px_secrets.py → $DEST"

# Ensure INSTALL_DIR is in PATH
if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
  warn "$INSTALL_DIR is not in your PATH."
  SHELL_RC=""
  case "$SHELL" in
    */zsh)  SHELL_RC="$HOME/.zshrc" ;;
    */bash) SHELL_RC="$HOME/.bash_profile" ;;
  esac
  if [[ -n "$SHELL_RC" ]]; then
    echo "" >> "$SHELL_RC"
    echo "# PX Secrets" >> "$SHELL_RC"
    echo "export PATH=\"\$HOME/.local/bin:\$PATH\"" >> "$SHELL_RC"
    ok "Added ~/.local/bin to PATH in $SHELL_RC"
    info "Run: source $SHELL_RC   (or open a new terminal)"
  else
    warn "Add this to your shell profile: export PATH=\"\$HOME/.local/bin:\$PATH\""
  fi
fi

# ── Done ──────────────────────────────────────────────────────────────────────
printf "\n"
printf "  ╔════════════════════════════════════════════════════╗\n"
printf "  ║   ${GREEN}${BOLD}Installation complete!${RESET}                             ║\n"
printf "  ╚════════════════════════════════════════════════════╝\n"
printf "\n"
printf "  ${BOLD}Quick start:${RESET}\n"
printf "\n"
printf "    px-secrets                  Launch the GUI (opens in browser)\n"
printf "    px-secrets --native         Launch as native window (requires pywebview)\n"
printf "    px-secrets --get <svc> <key>  Fetch a secret from the CLI\n"
printf "    px-secrets --list           List all services\n"
printf "\n"
printf "  ${BOLD}First time?${RESET} Open the app and click the ⚙️ Settings icon to configure\n"
printf "  your vault path and AGE key. Need help? ${REPO_URL}\n"
printf "\n"
