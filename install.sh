#!/usr/bin/env bash
# ============================================================
#  DeupGaming Free Panel — Management Suite
#  Usage:  bash install.sh
#  Everything is automatic and self-healing.
# ============================================================
set -uo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_DIR" || exit 1

SERVICE="deup-panel"
SERVICE_FILE="/etc/systemd/system/${SERVICE}.service"
VENV="$REPO_DIR/venv"
PY="$VENV/bin/python"
PIP="$VENV/bin/pip"
PORT_FILE="$REPO_DIR/.panel-port"
CRED_FILE="/root/.deup-panel-credentials"
BACKUP_DIR="/root/deup-backups"
POOL="${VPS_STORAGE_POOL:-zfs-new}"
IMAGE_ALIAS="ubuntu/22.04"
DEFAULT_PORT=5000

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

banner() {
  echo ""
  echo -e "${BOLD}  ____                  ____       _                ${NC}"
  echo -e "${BOLD} |  _ \\  ___ _   _ _ __ / ___| __ _ _ __ ___   ___ _ __ ${NC}"
  echo -e "${BOLD} | | | |/ _ \\ | | | '_ \\ |  _ / _\` | '_ \` _ \\ / _ \\ '__|${NC}"
  echo -e "${BOLD} | |_| |  __/ |_| | |_) | |_| | (_| | | | | | |  __/ |   ${NC}"
  echo -e "${BOLD} |____/ \\___|\\__,_| .__/ \\____|\\__,_|_| |_| |_|\\___|_|   ${NC}"
  echo -e "${BOLD}                 |_|   Free Panel — Management Suite${NC}"
  echo -e "${DIM} ------------------------------------------------------------${NC}"
}

# ---------------- helpers ----------------
have() { command -v "$1" >/dev/null 2>&1; }

retry() {
  local tries=$1; shift
  local i=1
  until "$@"; do
    if [ "$i" -ge "$tries" ]; then
      return 1
    fi
    warn "attempt $i/$tries failed: $*"
    sleep $((i * 2))
    i=$((i + 1))
  done
}

apt_update() {
  DEBIAN_FRONTEND=noninteractive retry 3 \
    apt-get -o DPkg::Lock::Timeout=180 -o Acquire::Retries=3 update -y >/dev/null 2>&1
}

apt_install() {
  DEBIAN_FRONTEND=noninteractive retry 3 \
    apt-get -o DPkg::Lock::Timeout=180 -o Acquire::Retries=3 -y install "$@"
}

# install each package separately so one missing package can't kill the run
install_pkgs() {
  local p
  for p in "$@"; do
    if dpkg -s "$p" >/dev/null 2>&1; then continue; fi
    if ! apt_install "$p" >/dev/null 2>&1; then
      warn "package '$p' failed to install — continuing (fallbacks will handle it)"
      apt-get -f -y install >/dev/null 2>&1 || true
    fi
  done
}

need_root() {
  if [ "$(id -u)" -ne 0 ]; then
    die "this action needs root. Try:  sudo bash install.sh"
  fi
}

panel_port() {
  if [ -f "$PORT_FILE" ]; then
    cat "$PORT_FILE"
  else
    echo "$DEFAULT_PORT"
  fi
}

public_ip() {
  local ip
  ip=$(curl -fsS --max-time 4 https://api.ipify.org 2>/dev/null || true)
  [ -z "$ip" ] && ip=$(hostname -I 2>/dev/null | awk '{print $1}')
  echo "${ip:-127.0.0.1}"
}

svc_active() { systemctl is-active --quiet "$SERVICE"; }

wait_http() {
  local port=$1 i code
  for i in $(seq 1 45); do
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "http://127.0.0.1:${port}/" 2>/dev/null || true)
    case "$code" in
      2*|3*) return 0 ;;
    esac
    sleep 1
  done
  return 1
}

http_ok() {
  local code
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "http://127.0.0.1:${1}/" 2>/dev/null || true)
  case "$code" in 2*|3*) return 0 ;; *) return 1 ;; esac
}

port_busy() {
  local port=$1
  if have ss; then
    ss -lnt 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${port}$"
  else
    netstat -lnt 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${port}$"
  fi
}

pick_port() {
  local p
  for p in $(seq "$DEFAULT_PORT" $((DEFAULT_PORT + 100))); do
    if ! port_busy "$p"; then echo "$p"; return 0; fi
  done
  echo "$DEFAULT_PORT"
}

# ---------------- system / LXD ----------------
ensure_system_deps() {
  need_root
  info "Refreshing package lists"
  apt_update || warn "apt-get update failed — trying with existing lists"

  info "Installing system packages"
  install_pkgs ca-certificates curl wget git openssl python3 python3-venv python3-pip \
               iptables iproute2 net-tools debootstrap openssh-client openssh-server tar
}

ensure_ip_forward() {
  info "Enabling IPv4 forwarding"
  echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
  cat > /etc/sysctl.d/99-deup-panel.conf <<'EOF'
net.ipv4.ip_forward=1
EOF
  sysctl --system >/dev/null 2>&1 || true
}

lxd_ready() { lxc info >/dev/null 2>&1; }

ensure_lxd_running() {
  if lxd_ready; then
    ok "LXD daemon is running"
    return 0
  fi

  info "Starting LXD daemon"
  export PATH="/snap/bin:$PATH"

  systemctl enable --now lxd >/dev/null 2>&1 || true
  systemctl enable --now snap.lxd.daemon >/dev/null 2>&1 || true

  # last resort: install LXD from snap
  if ! have lxd && ! have lxc && have snap; then
    warn "LXD package missing — installing from snap"
    snap install lxd >/dev/null 2>&1 || true
    systemctl enable --now snap.lxd.daemon >/dev/null 2>&1 || true
  fi

  local i
  for i in $(seq 1 60); do
    lxd_ready && { ok "LXD is ready"; return 0; }
    sleep 1
  done
  return 1
}

ensure_lxd_init() {
  if ! lxd_ready; then
    warn "LXD not responding — cannot initialize"
    return 1
  fi

  if lxc profile list --format csv 2>/dev/null | grep -qi '^default'; then
    ok "LXD already initialized"
    return 0
  fi

  info "Initializing LXD (auto)"
  retry 3 lxd init --auto >/dev/null 2>&1 && ok "LXD initialized" || warn "lxd init --auto failed"
}

ensure_pool() {
  lxd_ready || return 1

  if lxc storage list --format csv 2>/dev/null | cut -d, -f1 | grep -qx "$POOL"; then
    ok "Storage pool '$POOL' already exists"
    return 0
  fi

  info "Creating storage pool '$POOL'"

  # Prefer ZFS, fall back to dir (works everywhere, including Debian without zfsutils)
  local free_gb size_gb
  free_gb=$(df -Pk /var/lib/lxd 2>/dev/null | awk 'NR==2{print int($4/1024/1024)}')
  [ -z "${free_gb:-}" ] && free_gb=$(df -Pk / 2>/dev/null | awk 'NR==2{print int($4/1024/1024)}')
  [ -z "${free_gb:-}" ] && free_gb=50
  size_gb=$(( free_gb * 80 / 100 ))
  [ "$size_gb" -lt 10 ] && size_gb=10

  if modprobe zfs >/dev/null 2>&1; then
    if retry 2 lxc storage create "$POOL" zfs size="${size_gb}GB" >/dev/null 2>&1; then
      ok "ZFS pool '$POOL' created (${size_gb}GB)"
      return 0
    fi
  fi

  if retry 2 lxc storage create "$POOL" dir >/dev/null 2>&1; then
    ok "Directory pool '$POOL' created"
    return 0
  fi

  # If the pool name is taken by the default pool created by lxd init, reuse it
  local existing
  existing=$(lxc storage list --format csv 2>/dev/null | cut -d, -f1 | head -n1)
  if [ -n "$existing" ]; then
    warn "Could not create '$POOL' — using existing pool '$existing'"
    echo "$existing" > "$REPO_DIR/.storage-pool"
    return 0
  fi

  warn "No storage pool available — VPS creation will fail until one exists"
  return 1
}

panel_pool() {
  if [ -f "$REPO_DIR/.storage-pool" ]; then cat "$REPO_DIR/.storage-pool"; else echo "$POOL"; fi
}

ensure_image() {
  lxd_ready || return 1

  if lxc image list local: 2>/dev/null | grep -q "$IMAGE_ALIAS"; then
    ok "Base image $IMAGE_ALIAS present"
    return 0
  fi

  info "Downloading base image $IMAGE_ALIAS (may take a few minutes)"
  if retry 3 lxc image copy ubuntu:22.04 local: --alias "$IMAGE_ALIAS" >/dev/null 2>&1; then
    ok "Image $IMAGE_ALIAS imported"
    return 0
  fi
  if retry 2 lxc image copy images:ubuntu/22.04 local: --alias "$IMAGE_ALIAS" >/dev/null 2>&1; then
    ok "Image $IMAGE_ALIAS imported (mirror)"
    return 0
  fi

  warn "Could not download image now — the panel will retry when a VPS is created"
  return 1
}

setup_lxd() {
  ensure_lxd_running || { warn "LXD is not ready — panel will still install, VPS features need LXD"; return 1; }
  ensure_lxd_init
  ensure_pool
  ensure_image
  return 0
}

# ---------------- chroot VPS backend ----------------
CHROOT_ROOT="${VPS_CHROOT_ROOT:-/var/lib/deup-vps}"

setup_vps_backend() {
  need_root
  info "Preparing chroot VPS backend"

  mkdir -p "$CHROOT_ROOT/meta" "$CHROOT_ROOT/logs"
  chmod 711 "$CHROOT_ROOT" 2>/dev/null || true

  # mount capability probe (needed for /proc and PTY allocation inside jails)
  local mtest="$CHROOT_ROOT/.mounttest"
  mkdir -p "$mtest"
  if mount --bind /dev/pts "$mtest" >/dev/null 2>&1; then
    umount -l "$mtest" >/dev/null 2>&1 || true
    ok "Mount support: yes (SSH PTY + /proc enabled)"
  else
    warn "Mount support: NO - SSH logins will work but without a PTY"
    warn "Ask your provider for a privileged container (CAP_SYS_ADMIN) if you need PTYs"
  fi
  rmdir "$mtest" >/dev/null 2>&1 || true

  info "Preparing base rootfs (first run only - takes 1-3 minutes)"
  if ( cd "$REPO_DIR" && VPS_CHROOT_ROOT="$CHROOT_ROOT" python3 -c \
        'import vps,sys; sys.exit(0 if vps.ensure_base_rootfs() else 1)' ); then
    ok "Base rootfs ready ($CHROOT_ROOT/base)"
  else
    warn "Base rootfs not ready - the panel will retry when the first VPS is created"
  fi

  echo "$CHROOT_ROOT" > "$REPO_DIR/.chroot-root"
}

chroot_vps_count() {
  [ -d "$CHROOT_ROOT" ] || { echo 0; return; }
  find "$CHROOT_ROOT" -maxdepth 1 -type d -name 'vps-*' 2>/dev/null | wc -l | tr -d ' '
}

# ---------------- python ----------------
ensure_venv() {
  if [ -x "$PY" ] && "$PY" -c 'import sys' >/dev/null 2>&1; then
    return 0
  fi

  info "Creating Python virtual environment"
  rm -rf "$VENV"
  if ! python3 -m venv "$VENV" >/dev/null 2>&1; then
    warn "venv creation failed — installing python3-venv/python3-full"
    install_pkgs python3-venv python3-full python3-pip
    rm -rf "$VENV"
    python3 -m venv "$VENV" >/dev/null 2>&1 || die "could not create virtualenv at $VENV"
  fi

  "$PY" -m pip install --upgrade pip setuptools wheel >/dev/null 2>&1 || true
}

install_python_deps() {
  ensure_venv

  info "Installing Python requirements"
  if ! retry 3 "$PIP" install -q --disable-pip-version-check -r "$REPO_DIR/requirements.txt"; then
    warn "requirements.txt install failed — installing core packages directly"
    retry 3 "$PIP" install -q --disable-pip-version-check \
      flask flask-login werkzeug requests pylxd \
      || die "could not install Python dependencies (check internet access)"
  fi

  "$PY" -c 'import flask, flask_login, werkzeug, requests' >/dev/null 2>&1 \
    || die "Python dependencies are broken"
  ok "Python environment ready"
}

write_config_files() {
  local pool port
  pool="$(panel_pool)"
  port="$(panel_port)"

  cat > "$REPO_DIR/.env" <<EOF
# Generated by install.sh - do not commit
VPS_BACKEND=chroot
VPS_CHROOT_ROOT=$CHROOT_ROOT
PANEL_PORT=$port
PANEL_HOST=0.0.0.0
# Anti-abuse: set to 1 to block multiple VPSes from the same IP (breaks
# behind NAT / shared hosting / Cloudflare). Default off.
# IP_ABUSE_CHECK_ENABLED=1
# Never enable external IP lookups unless you explicitly want them:
# IP_INTEL_ENABLED=1
EOF
  chmod 600 "$REPO_DIR/.env" 2>/dev/null || true
}

install_cli() {
  need_root
  cat > /usr/local/bin/panel <<EOF
#!/usr/bin/env bash
exec bash "$REPO_DIR/install.sh" "\$@"
EOF
  chmod +x /usr/local/bin/panel
  ok "Command 'panel' installed — type 'panel' any time to open this menu"
}

# ---------------- admin account ----------------
db_admin_exists() {
  [ -f "$REPO_DIR/panel.db" ] || return 1
  "$PY" -c 'import sqlite3,sys
c=sqlite3.connect("panel.db")
sys.exit(0 if c.execute("select count(*) from users where is_admin=1").fetchone()[0] else 1)' 2>/dev/null
}

gen_password() {
  if have openssl; then
    openssl rand -base64 18 | tr -dc 'A-Za-z0-9' | head -c 16
  else
    head -c 64 /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 16
  fi
}

ask_admin() {
  ADMIN_USER="${PANEL_USER:-}"
  ADMIN_PASS="${PANEL_PASS:-}"
  PANEL_CPU="${VPS_CPU:-}"
  PANEL_RAM="${VPS_RAM:-}"
  PANEL_DISK="${VPS_DISK:-}"

  if [ ! -t 0 ]; then
    [ -z "$ADMIN_USER" ] && ADMIN_USER="admin"
    [ -z "$ADMIN_PASS" ] && ADMIN_PASS="$(gen_password)"
    return 0
  fi

  echo ""
  echo -e "${BOLD}  Panel administrator${NC}"
  if [ -z "$ADMIN_USER" ]; then
    read -rp "  Username [admin]: " ADMIN_USER
    ADMIN_USER="${ADMIN_USER:-admin}"
  fi
  if [ -z "$ADMIN_PASS" ]; then
    read -rsp "  Password (blank = auto-generate): " ADMIN_PASS
    echo ""
    if [ -z "$ADMIN_PASS" ]; then
      ADMIN_PASS="$(gen_password)"
      ok "Generated password: ${BOLD}${ADMIN_PASS}${NC}"
    fi
  fi
}

create_admin() {
  if db_admin_exists; then
    ok "Administrator account already exists — keeping current login"
    return 0
  fi
  ask_admin

  info "Creating administrator account"
  PANEL_USER="$ADMIN_USER" \
  PANEL_PASS="$ADMIN_PASS" \
  VPS_CPU="${PANEL_CPU:-}" \
  VPS_RAM="${PANEL_RAM:-}" \
  VPS_DISK="${PANEL_DISK:-}" \
  "$PY" "$REPO_DIR/setup.py" --auto || die "admin setup failed"

  {
    echo "Panel URL      : http://$(public_ip):$(panel_port)"
    echo "Admin username : $ADMIN_USER"
    echo "Admin password : $ADMIN_PASS"
    echo "Generated      : $(date -Is)"
  } > "$CRED_FILE"
  chmod 600 "$CRED_FILE" 2>/dev/null || true
  ok "Credentials saved to $CRED_FILE"
}

reset_admin_password() {
  ensure_venv
  local user pass
  if [ -t 0 ]; then
    read -rp "  Username [admin]: " user
    user="${user:-admin}"
    read -rsp "  New password (blank = auto-generate): " pass
    echo ""
  else
    user="${RESET_USER:-admin}"
    pass="${RESET_PASS:-}"
  fi
  [ -z "$pass" ] && pass="$(gen_password)"
  "$PY" "$REPO_DIR/setup.py" --reset-pass "$user" "$pass" || die "password reset failed"
  echo ""
  ok "New password for '$user': ${BOLD}${pass}${NC}"
}

# ---------------- service ----------------
write_service() {
  need_root
  local port pool
  port="$(panel_port)"
  pool="$(panel_pool)"

  cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=DeupGaming Free Panel
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=root
KillMode=process
TasksMax=infinity
WorkingDirectory=$REPO_DIR
Environment=PYTHONUNBUFFERED=1
Environment=PANEL_HOST=0.0.0.0
Environment=PANEL_PORT=$port
Environment=VPS_STORAGE_POOL=$pool
Environment=VPS_BACKEND=chroot
Environment=VPS_CHROOT_ROOT=$CHROOT_ROOT
Environment=MIN_FREE_DISK_GB=5
ExecStart=$PY -u app.py
Restart=always
RestartSec=3
TimeoutStopSec=20

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable "$SERVICE" >/dev/null 2>&1 || true
}

start_panel() {
  need_root
  if [ ! -x "$PY" ]; then
    warn "Panel is not installed yet — running installer first"
    install_all
    return $?
  fi
  if [ ! -f "$SERVICE_FILE" ]; then
    write_service
  fi

  local port
  port="$(panel_port)"

  if port_busy "$port" && ! svc_active; then
    local newport
    newport="$(pick_port)"
    if [ "$newport" != "$port" ]; then
      warn "Port $port is already in use — switching to $newport"
      echo "$newport" > "$PORT_FILE"
      port="$newport"
      write_service
    fi
  fi

  info "Starting panel"
  systemctl restart "$SERVICE" 2>/dev/null || systemctl start "$SERVICE" 2>/dev/null

  if wait_http "$port"; then
    ok "Panel is up on http://127.0.0.1:${port}"
    return 0
  fi

  warn "Panel did not answer — attempting automatic repair"
  repair_panel
}

stop_panel() {
  need_root
  info "Stopping panel"
  systemctl stop "$SERVICE" 2>/dev/null || true
  ok "Stopped"
}

restart_panel() {
  need_root
  stop_panel >/dev/null 2>&1
  start_panel
}

repair_panel() {
  need_root
  install_python_deps
  write_config_files
  write_service

  local port
  port="$(panel_port)"

  systemctl reset-failed "$SERVICE" >/dev/null 2>&1 || true
  systemctl restart "$SERVICE" >/dev/null 2>&1 || true

  if wait_http "$port"; then
    ok "Repair successful — panel is running"
    return 0
  fi

  err "Repair failed. Last 40 log lines:"
  journalctl -u "$SERVICE" -n 40 --no-pager 2>/dev/null || true
  return 1
}

# ---------------- cloudflare tunnel ----------------
setup_cloudflare() {
  need_root
  banner
  info "Cloudflare Tunnel setup (ingress to the panel on port $(panel_port))"

  local token="${CLOUDFLARE_TOKEN:-}"
  if [ -z "$token" ] && [ -t 0 ]; then
    echo ""
    echo -e "  ${DIM}Get the token from Cloudflare Zero Trust -> Networks -> Tunnels ->${NC}"
    echo -e "  ${DIM}your tunnel -> Configure -> token (starts with eyJ...).${NC}"
    echo -e "  ${DIM}You can paste the full command 'sudo cloudflared service install eyJ...'${NC}"
    echo -e "  ${DIM}or just the token itself.${NC}"
    echo ""
    read -rp "  Tunnel token (paste, or Enter to skip): " token
  fi

  # Strip common prefixes if user pasted a full command
  token="${token#sudo cloudflared service install }"
  token="${token#cloudflared service install }"
  token="${token#sudo }"
  token="$(echo "$token" | tr -d '[:space:]')"

  # Validate: token should start with eyJ (JWT)
  if [ -z "$token" ]; then
    warn "No token provided - skipping Cloudflare setup"
    return 1
  fi
  if [[ ! "$token" =~ ^eyJ ]]; then
    warn "Token doesn't look like a valid Cloudflare token (should start with eyJ...)"
    warn "Make sure you copied just the token, not the full command"
    return 1
  fi

  # --- install cloudflared if missing ---
  if ! have cloudflared; then
    info "Installing cloudflared"
    if have apt-get; then
      if ! apt_install cloudflared >/dev/null 2>&1; then
        local arch url tmpbin
        arch="$(uname -m)"
        case "$arch" in
          x86_64|amd64) arch="amd64" ;;
          aarch64|arm64) arch="arm64" ;;
          armv7l|armhf)  arch="arm" ;;
          *) arch="amd64" ;;
        esac
        url="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${arch}"
        tmpbin="/tmp/cloudflared.$$"
        if retry 3 curl -fsSL "$url" -o "$tmpbin"; then
          chmod +x "$tmpbin"
          mv "$tmpbin" /usr/local/bin/cloudflared
          ok "cloudflared installed (binary)"
        else
          rm -f "$tmpbin"
          err "Could not download cloudflared - install it manually and re-run"
          return 1
        fi
      else
        ok "cloudflared installed (apt)"
      fi
    else
      err "apt-get not found - install cloudflared manually"
      return 1
    fi
  else
    ok "cloudflared already installed"
  fi

  # --- store token ---
  mkdir -p /etc/cloudflared
  printf '%s' "$token" > /etc/cloudflared/token
  chmod 600 /etc/cloudflared/token
  ok "Token stored at /etc/cloudflared/token"

  # --- remove stale units and processes ---
  info "Cleaning up stale cloudflared units"
  for u in cloudflared cloudflared-update; do
    systemctl stop "$u" >/dev/null 2>&1 || true
    systemctl disable "$u" >/dev/null 2>&1 || true
  done
  rm -f /etc/systemd/system/cloudflared.service \
        /etc/systemd/system/cloudflared-update.service \
        /lib/systemd/system/cloudflared.service \
        /lib/systemd/system/cloudflared-update.service
  pkill -f "cloudflared tunnel" 2>/dev/null || true
  sleep 1

  # --- create the custom unit (force http2: QUIC/UDP 7844 is blocked on this host) ---
  local port
  port="$(panel_port)"
  local cfd_bin
  cfd_bin="$(command -v cloudflared)"
  [ -z "$cfd_bin" ] && cfd_bin="/usr/local/bin/cloudflared"

  cat > /etc/systemd/system/cloudflared.service <<EOF
[Unit]
Description=Cloudflare Tunnel (DeupGaming Free Panel)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=${cfd_bin} --no-autoupdate tunnel --protocol http2 run --token-file /etc/cloudflared/token
Restart=always
RestartSec=5
TimeoutStopSec=10

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable cloudflared >/dev/null 2>&1 || true

  info "Starting cloudflared tunnel"
  systemctl restart cloudflared 2>/dev/null || systemctl start cloudflared 2>/dev/null

  # --- verify ---
  local i
  for i in $(seq 1 20); do
    if systemctl is-active --quiet cloudflared; then
      ok "Cloudflare tunnel is running (protocol: http2)"
      echo ""
      echo -e "  ${DIM}Make sure your Cloudflare tunnel route points to:${NC}"
      echo -e "  ${BOLD}http://127.0.0.1:${port}${NC}  ${DIM}(use 127.0.0.1, not localhost)${NC}"
      echo ""
      return 0
    fi
    sleep 1
  done

  warn "Cloudflared did not start - check: journalctl -u cloudflared -n 30"
  echo -e "  ${DIM}Last 10 lines of cloudflared log:${NC}"
  journalctl -u cloudflared -n 10 --no-pager 2>/dev/null || true
  return 1
}

open_firewall() {
  local port
  port="$(panel_port)"

  if have ufw && ufw status 2>/dev/null | grep -qi "Status: active"; then
    ufw allow 22/tcp >/dev/null 2>&1 || true
    ufw allow "${port}/tcp" >/dev/null 2>&1 || true
    ok "ufw: allowed port $port"
  fi

  if have firewall-cmd && firewall-cmd --state >/dev/null 2>&1; then
    firewall-cmd --permanent --add-port="${port}/tcp" >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
    ok "firewalld: allowed port $port"
  fi
}

show_summary() {
  local port ip user pass
  port="$(panel_port)"
  ip="$(public_ip)"
  user="$(awk -F': *' '/Admin username/{print $2}' "$CRED_FILE" 2>/dev/null)"
  pass="$(awk -F': *' '/Admin password/{print $2}' "$CRED_FILE" 2>/dev/null)"

  echo ""
  echo -e "${GRN}${BOLD}  ================================================${NC}"
  echo -e "${GRN}${BOLD}             INSTALLATION COMPLETE${NC}"
  echo -e "${GRN}${BOLD}  ================================================${NC}"
  echo -e "   Panel URL : ${BOLD}http://${ip}:${port}${NC}"
  [ -n "${user:-}" ] && echo -e "   Username  : ${BOLD}${user}${NC}"
  [ -n "${pass:-}" ] && echo -e "   Password  : ${BOLD}${pass}${NC}"
  echo -e "   ${DIM}Also saved in ${CRED_FILE}${NC}"
  echo ""
  echo -e "   ${DIM}If the browser cannot reach it, open TCP ${port} in your${NC}"
  echo -e "   ${DIM}hosting provider firewall / security group.${NC}"
  echo ""
  echo -e "   Manage it later with:  ${BOLD}bash install.sh${NC}"
  echo ""
}

# ---------------- main actions ----------------
install_all() {
  need_root
  banner
  info "Starting full installation (this can take a few minutes)"
  echo ""

  ensure_system_deps
  ensure_ip_forward

  info "Preparing chroot VPS backend"
  if ! setup_vps_backend; then
    warn "VPS backend setup incomplete - the panel will still be installed"
  fi

  install_python_deps

  local port
  if [ ! -f "$PORT_FILE" ]; then
    port="$(pick_port)"
    echo "$port" > "$PORT_FILE"
  fi
  port="$(panel_port)"

  # free port selection if something else already holds ours
  if port_busy "$port" && ! svc_active; then
    local newport
    newport="$(pick_port)"
    if [ "$newport" != "$port" ]; then
      warn "Port $port is already in use — switching to $newport"
      port="$newport"
      echo "$port" > "$PORT_FILE"
    fi
  fi

  write_config_files
  create_admin
  write_service
  install_cli
  open_firewall

  info "Starting panel service"
  systemctl daemon-reload
  systemctl restart "$SERVICE" 2>/dev/null || true

  if ! wait_http "$port"; then
    warn "Panel did not come up on first try — repairing"
    repair_panel || die "installation failed (see logs above)"
  fi

  # --- optional Cloudflare Tunnel setup ---
  if [ -t 0 ]; then
    echo ""
    read -rp "  Connect Cloudflare Tunnel now? [y/N]: " cf_ans
    case "$cf_ans" in y|Y|yes|YES)
      setup_cloudflare || warn "Cloudflare setup failed - run 'panel' -> 15 later"
      ;;
    esac
  elif [ -n "${CLOUDFLARE_TOKEN:-}" ]; then
    setup_cloudflare || warn "Cloudflare setup failed"
  fi

  show_summary
}

reinstall_all() {
  need_root
  banner
  warn "Reinstall keeps your database (users + VPS records)."
  if [ -t 0 ]; then
    read -rp "  Continue? [y/N]: " ans
    case "$ans" in y|Y|yes|YES) ;; *) info "Cancelled"; return 0 ;; esac
  fi

  systemctl stop "$SERVICE" >/dev/null 2>&1 || true
  [ -f "$REPO_DIR/panel.db" ] && cp -f "$REPO_DIR/panel.db" "$REPO_DIR/panel.db.pre-reinstall" 2>/dev/null || true

  ensure_system_deps
  ensure_ip_forward
  setup_vps_backend || true
  install_python_deps
  write_config_files

  # schema + limits first; admin handled by create_admin (keeps an existing one)
  "$PY" "$REPO_DIR/setup.py" --ensure --no-admin >/dev/null 2>&1 || true
  create_admin

  write_service
  install_cli
  open_firewall
  systemctl daemon-reload
  systemctl restart "$SERVICE" >/dev/null 2>&1 || true

  if wait_http "$(panel_port)"; then
    ok "Reinstall complete"
    show_summary
  else
    repair_panel || die "reinstall failed (see logs above)"
  fi
}

update_panel() {
  need_root
  info "Updating panel"
  if [ -d "$REPO_DIR/.git" ]; then
    if ! retry 2 git -C "$REPO_DIR" pull --ff-only; then
      warn "git pull failed — keeping current code"
    fi
  else
    warn "Not a git checkout — skipping source update"
  fi

  install_python_deps
  write_config_files
  write_service
  systemctl restart "$SERVICE" >/dev/null 2>&1 || true
  if wait_http "$(panel_port)"; then ok "Panel updated and running"; else repair_panel; fi
}

show_status() {
  local port
  port="$(panel_port)"

  echo ""
  echo -e "${BOLD}  Panel status${NC}"
  echo -e "  ${DIM}----------------------------------------------${NC}"

  if svc_active; then
    echo -e "  Service     : ${GRN}running${NC}"
  else
    echo -e "  Service     : ${RED}stopped${NC}"
  fi

  if http_ok "$port"; then
    echo -e "  HTTP        : ${GRN}ok${NC} (http://127.0.0.1:${port})"
  else
    echo -e "  HTTP        : ${RED}no response${NC}"
  fi

  echo -e "  Public URL  : http://$(public_ip):${port}"
  echo -e "  Directory   : $REPO_DIR"
  echo -e "  Python      : $([ -x "$PY" ] && echo "$VENV" || echo "${RED}missing${NC}")"
  echo -e "  Data dir    : $CHROOT_ROOT"

  local nvps bstate
  nvps="$(chroot_vps_count)"
  if [ -d "$CHROOT_ROOT/base/usr/sbin" ]; then bstate="ready"; else bstate="${RED}not built${NC}"; fi
  echo -e "  Backend     : chroot (${nvps} VPS, base ${bstate})"

  if [ -f "$REPO_DIR/panel.db" ]; then
    local counts
    counts=$("$PY" -c 'import sqlite3
c=sqlite3.connect("panel.db")
print("{}/{}".format(c.execute("select count(*) from users").fetchone()[0],
                     c.execute("select count(*) from vps").fetchone()[0]))' 2>/dev/null || echo "?/?")
    echo -e "  Users / VPS : ${counts}"
  fi
  echo ""
}

show_logs() {
  need_root
  if [ -t 0 ]; then
    info "Showing live logs (Ctrl+C to exit)"
    journalctl -u "$SERVICE" -f -n 80 --no-pager
  else
    journalctl -u "$SERVICE" -n 120 --no-pager
  fi
}

change_port() {
  need_root
  local cur new
  cur="$(panel_port)"
  new="${PANEL_PORT:-}"
  if [ -z "$new" ] && [ -t 0 ]; then
    read -rp "  New panel port [$cur]: " new
  fi
  new="${new:-$cur}"
  if ! [[ "$new" =~ ^[0-9]+$ ]] || [ "$new" -lt 1 ] || [ "$new" -gt 65535 ]; then
    err "Invalid port"; return 1
  fi
  echo "$new" > "$PORT_FILE"
  write_config_files
  write_service
  open_firewall
  systemctl restart "$SERVICE" >/dev/null 2>&1 || true
  if wait_http "$new"; then ok "Panel now on port $new"; else warn "Panel not responding on $new — check logs"; fi
}

backup_now() {
  need_root
  mkdir -p "$BACKUP_DIR"
  local ts f
  ts="$(date +%Y%m%d-%H%M%S)"
  f="$BACKUP_DIR/panel-$ts.tar.gz"
  local items=()
  [ -f "$REPO_DIR/panel.db" ] && items+=("panel.db")
  [ -f "$REPO_DIR/secret.key" ] && items+=("secret.key")
  [ -f "$PORT_FILE" ] && items+=(".panel-port")
  [ -f "$REPO_DIR/.env" ] && items+=(".env")
  if [ ${#items[@]} -eq 0 ]; then warn "Nothing to back up yet"; return 0; fi
  tar -czf "$f" -C "$REPO_DIR" "${items[@]}" 2>/dev/null || { err "backup failed"; return 1; }
  ok "Backup: $f"
  ls -1t "$BACKUP_DIR"/panel-*.tar.gz 2>/dev/null | tail -n +11 | xargs -r rm -f
}

restore_backup() {
  need_root
  local f
  if [ -n "${1:-}" ]; then
    f="$1"
  elif [ -t 0 ]; then
    echo ""
    ls -1t "$BACKUP_DIR"/panel-*.tar.gz 2>/dev/null | head -n 10 | nl -w2 -s') '
    read -rp "  Backup number or path: " pick
    if [[ "$pick" =~ ^[0-9]+$ ]]; then
      f="$(ls -1t "$BACKUP_DIR"/panel-*.tar.gz 2>/dev/null | sed -n "${pick}p")"
    else
      f="$pick"
    fi
  fi

  [ -f "${f:-}" ] || { err "Backup not found"; return 1; }
  systemctl stop "$SERVICE" >/dev/null 2>&1 || true
  backup_now >/dev/null 2>&1 || true
  tar -xzf "$f" -C "$REPO_DIR" || { err "extract failed"; return 1; }
  systemctl start "$SERVICE" >/dev/null 2>&1 || true
  ok "Restored from $f"
}

uninstall_panel() {
  need_root
  banner
  warn "This removes the panel service"
  local purge=0
  if [ "${1:-}" = "--purge" ] || [ "${PURGE:-0}" = "1" ]; then
    purge=1
  elif [ -t 0 ]; then
    read -rp "  Also delete database, venv and containers? [y/N]: " ans
    case "$ans" in y|Y|yes|YES) purge=1 ;; esac
  fi

  systemctl stop "$SERVICE" >/dev/null 2>&1 || true
  systemctl disable "$SERVICE" >/dev/null 2>&1 || true
  rm -f "$SERVICE_FILE"
  rm -f /usr/local/bin/panel
  systemctl daemon-reload
  ok "Service removed"

  if [ "$purge" = "1" ]; then
    if [ -d "$CHROOT_ROOT" ]; then
      info "Stopping and deleting VPS jails"
      for d in "$CHROOT_ROOT"/vps-*; do
        [ -d "$d" ] || continue
        for pr in /proc/[0-9]*; do
          [ "$(readlink "$pr/root" 2>/dev/null)" = "$d" ] && kill -9 "${pr#/proc/}" 2>/dev/null || true
        done
        for mnt in proc dev/pts dev/shm; do umount -l "$d/$mnt" >/dev/null 2>&1 || true; done
        rm -rf "$d"
      done
      rm -rf "$CHROOT_ROOT"
    fi
    rm -rf "$VENV" "$REPO_DIR/panel.db" "$REPO_DIR/secret.key" "$REPO_DIR/.env" \
           "$REPO_DIR/.panel-port" "$REPO_DIR/.storage-pool" "$REPO_DIR/__pycache__" \
           "$REPO_DIR/panel.db.pre-reinstall"
    ok "Panel data deleted"
  else
    ok "Panel data kept (database at $REPO_DIR/panel.db)"
  fi

  echo ""
  info "Source files remain in: $REPO_DIR"
  info "Reinstall any time with: bash install.sh"
}

open_shell() {
  info "Opening shell in $REPO_DIR (type 'exit' to return)"
  ( cd "$REPO_DIR" && exec "${SHELL:-bash}" ) || true
}

# ---------------- menu ----------------
menu() {
  while true; do
    banner
    if svc_active; then
      echo -e "  Panel: ${GRN}running${NC} on port ${BOLD}$(panel_port)${NC}  ($REPO_DIR)"
    else
      echo -e "  Panel: ${YEL}not running${NC}  ($REPO_DIR)"
    fi
    echo ""
    echo -e "  ${BOLD}1)${NC} Install panel        ${DIM}(full automatic setup)${NC}"
    echo -e "  ${BOLD}2)${NC} Reinstall panel      ${DIM}(keeps database)${NC}"
    echo -e "  ${BOLD}3)${NC} Update panel         ${DIM}(git pull + deps)${NC}"
    echo -e "  ${BOLD}4)${NC} Start panel"
    echo -e "  ${BOLD}5)${NC} Stop panel"
    echo -e "  ${BOLD}6)${NC} Restart panel"
    echo -e "  ${BOLD}7)${NC} Status"
    echo -e "  ${BOLD}8)${NC} Logs"
    echo -e "  ${BOLD}9)${NC} Reset admin password"
    echo -e " ${BOLD}10)${NC} Change panel port"
    echo -e " ${BOLD}11)${NC} Backup now"
    echo -e " ${BOLD}12)${NC} Restore backup"
    echo -e " ${BOLD}13)${NC} Uninstall panel"
    echo -e " ${BOLD}14)${NC} Open shell in panel directory"
    echo -e " ${BOLD}15)${NC} Connect Cloudflare Tunnel"
    echo -e "  ${BOLD}0)${NC} Exit"
    echo ""
    if ! read -rp "  Choose [0-15]: " choice; then
      echo ""
      exit 0
    fi
    echo ""
    case "$choice" in
      1) install_all ;;
      2) reinstall_all ;;
      3) update_panel ;;
      4) start_panel ;;
      5) stop_panel ;;
      6) restart_panel ;;
      7) show_status ;;
      8) show_logs ;;
      9) reset_admin_password ;;
      10) change_port ;;
      11) backup_now ;;
      12) restore_backup ;;
      13) uninstall_panel ;;
      14) open_shell ;;
      15) setup_cloudflare ;;
      0) echo "  Bye."; exit 0 ;;
      *) err "Invalid choice" ;;
    esac
    echo ""
    read -rp "  Press Enter to return to the menu..." _ || exit 0
  done
}

usage() {
  cat <<'EOF'
DeupGaming Free Panel — Management Suite

  bash install.sh                  open the management menu
  bash install.sh --install        full automatic install
  bash install.sh --reinstall      reinstall (keeps database)
  bash install.sh --update         pull + update dependencies
  bash install.sh --start          start panel
  bash install.sh --stop           stop panel
  bash install.sh --restart        restart panel
  bash install.sh --status         show status
  bash install.sh --logs           show logs
  bash install.sh --backup         create backup
  bash install.sh --restore [f]    restore backup
  bash install.sh --reset-admin    reset admin password
  bash install.sh --port N         change panel port
  bash install.sh --uninstall [--purge]
  bash install.sh --cloudflare     connect Cloudflare Tunnel
  bash install.sh --help

Environment (for unattended installs):
  PANEL_USER=admin  PANEL_PASS=secret  VPS_CPU=4  VPS_RAM=4  VPS_DISK=80
EOF
}

# ---------------- entrypoint ----------------
ARG="${1:-}"
if [ "$ARG" = "--help" ] || [ "$ARG" = "-h" ]; then
  usage
  exit 0
fi

if [ "$(id -u)" -ne 0 ]; then
  if have sudo; then
    exec sudo -E bash "$REPO_DIR/install.sh" "$@"
  else
    err "run as root"
    exit 1
  fi
fi

case "$ARG" in
  ""|--menu) menu ;;
  --install|--all) install_all ;;
  --reinstall) reinstall_all ;;
  --update) update_panel ;;
  --start) start_panel ;;
  --stop) stop_panel ;;
  --restart) restart_panel ;;
  --status) show_status ;;
  --logs) show_logs ;;
  --backup) backup_now ;;
  --restore) restore_backup "${2:-}" ;;
  --reset-admin) reset_admin_password ;;
  --port) PANEL_PORT="${2:-}"; change_port ;;
  --uninstall) uninstall_panel "${2:-}" ;;
  --cloudflare) setup_cloudflare ;;
  --help|-h) usage ;;
  *) err "Unknown option: $ARG"; echo ""; usage; exit 1 ;;
esac
