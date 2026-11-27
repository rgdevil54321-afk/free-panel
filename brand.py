"""Guest identity cleanup and cloud-provider masking for VPS containers.

The original implementation wrote a fake ``neofetch`` wrapper into every guest
and renamed the OS to "Venlix Nodes VPS".  That script is gone.  This module
now also cleans guests that were created *before* the fix, so ``panel --repair``
can restore a natural Ubuntu identity without recreating anyone's VPS.
"""
import os
import shutil
import subprocess

FETCH_WRAPPERS = (
    "/usr/local/bin/neofetch",
    "/usr/local/bin/fastfetch",
    "/usr/local/bin/screenfetch",
)

IDENTITY = 'Ubuntu 24.04 LTS'


def clean_guest_root(root: str) -> bool:
    """Remove legacy fake fetch wrappers from one guest root filesystem.

    Works directly on the chroot directory, so it also repairs existing VPSes.
    Returns True when something was changed.
    """
    changed = False
    for rel in FETCH_WRAPPERS:
        path = os.path.join(root, rel.lstrip("/"))
        if os.path.lexists(path):
            try:
                os.unlink(path)
                changed = True
            except OSError:
                pass

    os_release = os.path.join(root, "etc", "os-release")
    if os.path.isfile(os_release):
        identity_changed = False
        try:
            with open(os_release, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
            out = []
            for line in lines:
                if line.startswith("PRETTY_NAME=") and "Venlix" in line:
                    out.append(f'PRETTY_NAME="{IDENTITY}"\n')
                    identity_changed = True
                elif line.startswith("NAME=") and "Venlix" in line:
                    out.append('NAME="Ubuntu"\n')
                    identity_changed = True
                else:
                    out.append(line)
            if identity_changed:
                with open(os_release, "w", encoding="utf-8") as f:
                    f.writelines(out)
                changed = True
        except OSError:
            pass

    issue = os.path.join(root, "etc", "issue")
    try:
        if not os.path.isfile(issue):
            with open(issue, "w", encoding="utf-8") as f:
                f.write(f"{IDENTITY} \\l\n")
            changed = True
        else:
            with open(issue, "r", encoding="utf-8", errors="replace") as f:
                data = f.read()
            if "Venlix" in data:
                with open(issue, "w", encoding="utf-8") as f:
                    f.write(f"{IDENTITY} \\l\n")
                changed = True
    except OSError:
        pass

    motd = os.path.join(root, "etc", "motd")
    try:
        if os.path.isfile(motd):
            with open(motd, "r", encoding="utf-8", errors="replace") as f:
                data = f.read()
            if "Venlix" in data:
                os.unlink(motd)
                changed = True
    except OSError:
        pass

    return changed


def _has_real_fetch(root: str) -> bool:
    """True when a real neofetch/fastfetch binary exists inside a guest."""
    for rel in ("usr/bin/neofetch", "usr/bin/fastfetch",
                "usr/local/bin/neofetch", "usr/local/bin/fastfetch"):
        if os.path.isfile(os.path.join(root, rel)):
            return True
    return False


def ensure_real_fetch(root: str) -> bool:
    """Best-effort install of a real neofetch (or fastfetch) inside a guest."""
    if _has_real_fetch(root) or shutil.which("chroot") is None:
        return _has_real_fetch(root)
    if not os.path.isfile(os.path.join(root, "usr", "bin", "apt-get")):
        return False

    try:                                  # reuse the base-rootfs chroot setup
        import vps
        vps._mkdir_devices(root)
        vps._write_chroot_resolv(root)
    except Exception:
        pass

    env = {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "DEBIAN_FRONTEND": "noninteractive",
        "HOME": "/root",
        "LC_ALL": "C.UTF-8",
    }

    def _apt(*args: str) -> bool:
        try:
            r = subprocess.run(
                ["chroot", root, "/usr/bin/apt-get", *args],
                capture_output=True, text=True, timeout=300, env=env,
            )
            return r.returncode == 0
        except Exception:
            return False

    for package in ("neofetch", "fastfetch"):
        if _apt("install", "-y", "-qq", package):
            return True
        _apt("update", "-qq")
        if _apt("install", "-y", "-qq", package):
            return True
    return False


FETCH_FILES = (
    ("usr/bin/neofetch", "usr/bin/neofetch"),
    ("usr/bin/fastfetch", "usr/bin/fastfetch"),
    ("usr/share/neofetch", "usr/share/neofetch"),
    ("usr/share/fastfetch", "usr/share/fastfetch"),
)


def copy_fetch_from_base(base_root: str, guest_root: str) -> bool:
    """Copy a real fetch tool from one guest root to another (no apt needed)."""
    copied = False
    for rel, target_rel in FETCH_FILES:
        src = os.path.join(base_root, rel)
        if not os.path.exists(src):
            continue
        target = os.path.join(guest_root, target_rel)
        try:
            os.makedirs(os.path.dirname(target), exist_ok=True)
            if os.path.isdir(src):
                shutil.rmtree(target, ignore_errors=True)
                shutil.copytree(src, target, symlinks=True)
            else:
                shutil.copy2(src, target)
                os.chmod(target, 0o755)
            copied = True
        except OSError:
            pass
    return copied


def clean_existing_guests(chroot_root: str = None,
                          install_fetch: bool = True) -> tuple[int, int, int]:
    """Clean every existing VPS and the shared base image.

    A real fetch tool is installed into the base image once and copied into the
    other guests, so repairing dozens of VPSes does not run apt in each one.
    Returns ``(cleaned, total, fetch_installed)``.
    """
    root_dir = chroot_root or os.environ.get("VPS_CHROOT_ROOT", "/var/lib/deup-vps")
    base = os.path.join(root_dir, "base")
    paths = [base]
    try:
        names = sorted(os.listdir(root_dir))
    except OSError:
        names = []
    paths += [
        os.path.join(root_dir, name) for name in names
        if name.startswith("vps-") and os.path.isdir(os.path.join(root_dir, name))
    ]
    paths = [p for p in paths if os.path.isdir(p)]

    donor = base if os.path.isdir(base) else next(
        (p for p in paths if _has_real_fetch(p)), None
    )
    if donor and install_fetch and not _has_real_fetch(donor):
        ensure_real_fetch(donor)

    cleaned = installed = 0
    for path in paths:
        if clean_guest_root(path):
            cleaned += 1
        if (install_fetch and donor and path != donor
                and not _has_real_fetch(path)
                and copy_fetch_from_base(donor, path)):
            installed += 1
    return cleaned, len(paths), installed


def brand_container(inst):
    """Apply natural guest identity and hide cloud metadata inside the guest."""
    env = {"HOME": "/root", "DEBIAN_FRONTEND": "noninteractive"}

    script = r'''
# --- hostname ---
HN="vps-$(tr -dc 'a-z0-9' </dev/urandom 2>/dev/null | head -c 6)"
[ -z "$HN" ] && HN="vps-node"
echo "$HN" > /etc/hostname
hostname "$HN" 2>/dev/null || true

# --- natural Ubuntu identity (legacy Venlix branding removed) ---
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
        print(f"[BRAND] guest setup failed: {e}")

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
