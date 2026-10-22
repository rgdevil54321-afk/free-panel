#!/usr/bin/env bash
# DeupGaming Free Panel — one-click installer
# Usage:
#   sudo bash install.sh            # interactive menu
#   sudo bash install.sh --install  # install deps + LXD + python packages
#   sudo bash install.sh --create-admin
#   sudo bash install.sh --service  # install + enable systemd service
#   sudo bash install.sh --all      # install + admin + service
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
PYTHON="${PYTHON:-python3}"

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: run as root (sudo bash install.sh)"
    exit 1
  fi
}

install_deps() {
  require_root
  echo "==> Updating packages"
  apt-get update -y
  echo "==> Installing system dependencies"
  apt-get install -y python3 python3-pip lxd iptables zfsutils-linux wget openssl curl

  echo "==> Enabling IP forwarding"
  echo 1 > /proc/sys/net/ipv4/ip_forward
  grep -q '^net.ipv4.ip_forward=1' /etc/sysctl.conf || echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
  sysctl -p >/dev/null 2>&1 || true

  echo "==> Initializing LXD (if needed)"
  if ! lxc storage list 2>/dev/null | grep -q zfs-new; then
    lxd init --auto >/dev/null 2>&1 || true
    lxc image copy ubuntu:22.04 local: --alias ubuntu/22.04 >/dev/null 2>&1 || true
    lxc storage create zfs-new zfs size=6144GB >/dev/null 2>&1 || true
  fi

  echo "==> Installing Python packages"
  pip3 install --upgrade pip
  if [ -f "$REPO_DIR/requirements.txt" ]; then
    pip3 install -r "$REPO_DIR/requirements.txt"
  else
    pip3 install flask flask-login werkzeug requests pylxd
  fi

  echo "==> Done. Next: sudo bash install.sh --create-admin"
}

create_admin() {
  cd "$REPO_DIR"
  "$PYTHON" setup.py
}

install_service() {
  require_root
  cat > /etc/systemd/system/deup-panel.service <<EOF
[Unit]
Description=DeupGaming Free Panel
After=network.target

[Service]
Type=simple
WorkingDirectory=$REPO_DIR
ExecStart=$PYTHON -u app.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now deup-panel
  echo "==> Service installed & started. Status:"
  systemctl --no-pager status deup-panel || true
  echo "==> Panel: http://$(hostname -I | awk '{print $1}'):5000"
}

show_menu() {
  echo ""
  echo "  DeupGaming Free Panel — Installer"
  echo "  ---------------------------------"
  echo "  1) Install dependencies (LXD + packages)"
  echo "  2) Create admin account"
  echo "  3) Install & start systemd service"
  echo "  4) Run panel in foreground (debug)"
  echo "  5) Exit"
  echo ""
  read -rp "  Choose [1-5]: " choice
  case "$choice" in
    1) install_deps ;;
    2) create_admin ;;
    3) install_service ;;
    4) cd "$REPO_DIR"; "$PYTHON" -u app.py ;;
    5) exit 0 ;;
    *) echo "Invalid choice"; show_menu ;;
  esac
}

# --- argument handling ---
case "${1:-}" in
  --install) install_deps ;;
  --create-admin) create_admin ;;
  --service) install_service ;;
  --all)
    install_deps
    create_admin
    install_service
    ;;
  --start)
    cd "$REPO_DIR"; "$PYTHON" -u app.py
    ;;
  "")
    show_menu
    ;;
  *)
    echo "Unknown option: $1"
    echo "Use: --install | --create-admin | --service | --all | --start"
    exit 1
    ;;
esac
EOF
chmod +x install.sh