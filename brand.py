"""Guest branding + cloud-provider masking for newly created VPS containers."""
import subprocess


def brand_container(inst):
    """Apply custom fetch branding and hide cloud metadata inside the guest."""
    env = {"HOME": "/root", "DEBIAN_FRONTEND": "noninteractive"}

    script = r'''
# --- hostname ---
HN="vps-$(tr -dc 'a-z0-9' </dev/urandom 2>/dev/null | head -c 6)"
[ -z "$HN" ] && HN="vps-node"
echo "$HN" > /etc/hostname
hostname "$HN" 2>/dev/null || true

# --- OS release branding (keeps apt working, changes display name) ---
if [ -f /etc/os-release ]; then
  sed -i 's/^PRETTY_NAME=.*/PRETTY_NAME="Venlix Nodes VPS (Ubuntu-based)"/' /etc/os-release
  sed -i 's/^NAME=.*/NAME="Venlix Nodes VPS"/' /etc/os-release
fi

# --- disable cloud-init / metadata agents ---
touch /etc/cloud/cloud-init.disabled 2>/dev/null || true
systemctl disable cloud-init cloud-init-local cloud-config cloud-final 2>/dev/null || true
systemctl mask cloud-init 2>/dev/null || true
rm -rf /var/lib/cloud/instance /var/lib/cloud/instances/* 2>/dev/null || true

# --- custom fetch wrappers (override neofetch/fastfetch/screenfetch) ---
cat > /usr/local/bin/neofetch <<'FETCH'
#!/bin/bash
echo "        _   _  ____  _   _ _     ___  ____  "
echo "       | | | |/ ___|| | | | |   / _ \\|  _ \\ "
echo "       | | | | |  _ | |_| | |  | | | | |_) |"
echo "       | |_| | |_| ||  _  | |__| |_| |  __/ "
echo "        \\___/ \\____||_| |_|_____\\___/|_|    "
echo ""
echo "OS:       Venlix Nodes VPS"
echo "Host:     Venlix Nodes Cloud"
echo "Kernel:   $(uname -r)"
echo "Uptime:   $(uptime -p 2>/dev/null || uptime)"
echo "Packages: $(dpkg -l 2>/dev/null | grep -c '^i' || echo 0) (dpkg)"
echo "Shell:    $(basename "${SHELL:-/bin/bash}")"
echo "CPU:      Virtual CPU (isolated)"
echo "Memory:   $(free -h 2>/dev/null | awk '/^Mem:/ {print $3" / "$2}')"
echo "Disk:     $(df -h / 2>/dev/null | awk 'NR==2 {print $3" / "$2}')"
FETCH
chmod +x /usr/local/bin/neofetch
cp -f /usr/local/bin/neofetch /usr/local/bin/fastfetch
cp -f /usr/local/bin/neofetch /usr/local/bin/screenfetch

# --- motd / issue ---
cat > /etc/motd <<'MOTD'
  Welcome to Venlix Nodes VPS
  Type 'neofetch' to see system info.
MOTD
echo 'Venlix Nodes VPS' > /etc/issue 2>/dev/null || true

true
'''
    try:
        inst.execute(["bash", "-c", script], environment=env)
    except Exception as e:
        print(f"[BRAND] guest branding failed: {e}")

    # --- host-side: block cloud metadata endpoints from this container ---
    try:
        import nat
        cip = nat._get_container_ip(inst.name)
        if cip:
            for meta_ip in ("169.254.169.254", "169.254.170.2"):
                subprocess.run(
                    ["iptables", "-A", "FORWARD", "-s", cip, "-d", meta_ip, "-j", "DROP"],
                    capture_output=True, timeout=10,
                )
    except Exception as e:
        print(f"[BRAND] metadata block failed: {e}")
EOF