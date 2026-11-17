#!/usr/bin/env bash
# ============================================================
#  DeupGaming Free Panel — Premium Installation Suite
#  Usage:  bash install.sh [OPTIONS]
#
#  This is a thin bootstrap wrapper that ensures Python 3 is available
#  and delegates to installer.py (the real installer engine).
# ============================================================
set -uo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_DIR" || exit 1

# ---------------- pretty output ----------------
if [ -t 1 ]; then
  BOLD=$'\033[1m'; DIM=$'\033[2m'; RED=$'\033[31m'; GRN=$'\033[32m'
  YEL=$'\033[33m'; BLU=$'\033[36m'; NC=$'\033[0m'
else
  BOLD=""; DIM=""; RED=""; GRN=""; YEL=""; BLU=""; NC=""
fi
info() { echo -e "${BLU}[*]${NC} $*"; }
ok()   { echo -e "${GRN}[OK]${NC} $*"; }
warn() { echo -e "${YEL}[!]${NC} $*"; }
err()  { echo -e "${RED}[x]${NC} $*"; }
die()  { err "$*"; exit 1; }

# ---------------- bootstrap Python ----------------
ensure_python() {
  if command -v python3 >/dev/null 2>&1; then
    local ver
    ver=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null)
    local major minor
    major=$(echo "$ver" | cut -d. -f1)
    minor=$(echo "$ver" | cut -d. -f2)
    if [ "${major:-0}" -ge 3 ] && [ "${minor:-0}" -ge 8 ]; then
      ok "Python $ver detected"
      return 0
    fi
    warn "Python $ver found but 3.8+ required"
  fi

  # Try to install Python
  if command -v apt-get >/dev/null 2>&1; then
    info "Installing Python 3..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq >/dev/null 2>&1 || true
    apt-get install -y -qq python3 python3-venv python3-pip python3-full \
      >/dev/null 2>&1 || true
  elif command -v yum >/dev/null 2>&1; then
    info "Installing Python 3..."
    yum install -y python3 python3-pip >/dev/null 2>&1 || true
  elif command -v dnf >/dev/null 2>&1; then
    info "Installing Python 3..."
    dnf install -y python3 python3-pip >/dev/null 2>&1 || true
  fi

  if command -v python3 >/dev/null 2>&1; then
    ver=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null)
    ok "Python $ver installed"
    return 0
  fi

  die "Python 3.8+ is required but could not be installed. Please install it manually."
}

# ---------------- sudo elevation ----------------
if [ "$(id -u)" -ne 0 ]; then
  if command -v sudo >/dev/null 2>&1; then
    exec sudo -E bash "$REPO_DIR/install.sh" "$@"
  else
    err "This installer needs root. Run: sudo bash install.sh"
    exit 1
  fi
fi

# ---------------- bootstrap ----------------
echo ""
echo -e "${BOLD}  DeupGaming Free Panel — Premium Installation Suite${NC}"
echo -e "${DIM}  Bootstrapping...${NC}"
echo ""

ensure_python

# Verify installer.py exists
if [ ! -f "$REPO_DIR/installer.py" ]; then
  die "installer.py not found in $REPO_DIR. Is this the right directory?"
fi

# Delegate to the Python installer, passing all arguments
exec python3 "$REPO_DIR/installer.py" "$@"