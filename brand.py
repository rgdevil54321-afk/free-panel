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

# --- restore natural Ubuntu identity (remove old Venlix branding) ---
if [ -f /etc/os-release ]; then
  sed -i 's/^PRETTY_NAME=.*/PRETTY_NAME="Ubuntu 24.04 LTS"/' /etc/os-release
  sed -i 's/^NAME=.*/NAME="Ubuntu"/' /etc/os-release
fi

# --- disable cloud-init / metadata agents ---
touch /etc/cloud/cloud-init.disabled 2>/dev/null || true
systemctl disable cloud-init cloud-init-local cloud-config cloud-final 2>/dev/null || true
systemctl mask cloud-init 2>/dev/null || true
rm -rf /var/lib/cloud/instance /var/lib/cloud/instances/* 2>/dev/null || true

# --- remove stale fake fetch wrappers so real neofetch/fastfetch can work ---
rm -f /usr/local/bin/neofetch /usr/local/bin/fastfetch /usr/local/bin/screenfetch

# --- restore default login banner ---
rm -f /etc/motd
printf 'Ubuntu 24.04 LTS \\l\n' > /etc/issue 2>/dev/null || true

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