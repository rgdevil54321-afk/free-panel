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

# A chroot shares the host kernel, so tools like df/nproc report the host's
# disk and CPU count.  These small shims read the per-VPS plan written to
# /etc/vps-limits by vps.py and rewrite only the values the customer sees.
DF_SHIM = r'''#!/bin/sh
# Plan-aware df: rewrite the root filesystem row using the VPS disk allowance.
REAL_DF=""
for candidate in /usr/bin/df.real /bin/df.real /usr/bin/df /bin/df; do
    [ -x "$candidate" ] || continue
    grep -q '^# Plan-aware df' "$candidate" 2>/dev/null && continue
    REAL_DF="$candidate" && break
done
if [ -z "$REAL_DF" ]; then
    echo "df: real df binary not found" >&2
    exit 127
fi

output=$("$REAL_DF" "$@" 2>&1)
status=$?
if [ "$status" -ne 0 ]; then
    printf '%s\n' "$output" >&2
    exit "$status"
fi

disk_gb=""
if [ -r /etc/vps-limits ]; then
    disk_gb=$(sed -n 's/^DISK_GB=//p' /etc/vps-limits 2>/dev/null | head -n 1 | tr -dc '0-9')
fi
case "$disk_gb" in
    ''|*[!0-9]*) printf '%s\n' "$output"; exit "$status" ;;
esac
[ "$disk_gb" -gt 0 ] || { printf '%s\n' "$output"; exit "$status"; }

# The /proc/cpuinfo and /proc/meminfo bind mounts make df label the root row
# with a /proc path instead of "/".  Track whether the caller asked about a
# specific path so we can rewrite that row regardless of its label.
asked_path=0
exact_root=0
for arg in "$@"; do
    case "$arg" in
        -*) ;;
        /)  asked_path=1; exact_root=1 ;;
        /*) asked_path=1 ;;
    esac
done
root_source=$("$REAL_DF" -P / 2>/dev/null | awk 'NR == 2 {print $1}')

printf '%s\n' "$output" | awk -v gb="$disk_gb" \
        -v asked_path="$asked_path" -v exact_root="$exact_root" \
        -v root_source="$root_source" '
function toblocks(s,   u, v) {
    u = substr(s, length(s), 1)
    if (u ~ /[A-Za-z]/) {
        v = substr(s, 1, length(s) - 1) + 0
        if (u == "K" || u == "k") return v
        if (u == "M") return v * 1024
        if (u == "G") return v * 1048576
        if (u == "T") return v * 1073741824
        if (u == "P") return v * 1099511627776
    }
    return s + 0
}
function fmtg(blocks,   v) {
    v = blocks / 1048576
    if (v >= 10) return sprintf("%.0fG", v)
    return sprintf("%.1fG", v)
}
NR == 1 { print; next }
{
    # Which row is the root filesystem?
    if (asked_path) {
        is_root = (NR == 2)
    } else {
        is_root = ($NF == "/" ||
                   (root_source != "" && $1 == root_source &&
                    $NF ~ /^\/(proc\/(cpuinfo|meminfo)|etc\/(hosts|resolv\.conf))$/))
    }
    if (!is_root || $5 !~ /^[0-9]+%$/) { print; next }
    human = (substr($2, length($2), 1) ~ /[A-Za-z]/)
    total_real = toblocks($2)
    used_real = toblocks($3)
    total = gb * 1048576
    used = (total_real > 0) ? int(total * used_real / total_real) : 0
    if (used > total) used = total
    avail = total - used
    pct = (total > 0) ? int(used * 100 / total + 0.5) : 0
    if (human) {
        $2 = gb "G"; $3 = fmtg(used); $4 = fmtg(avail)
    } else {
        $2 = total; $3 = used; $4 = avail
    }
    $5 = pct "%"
    if (exact_root) $NF = "/"
    print
}'
exit "$status"
'''

NPROC_SHIM = r'''#!/bin/sh
# Plan-aware nproc: report the VPS CPU allowance instead of the host's count.
cores=""
if [ -r /etc/vps-limits ]; then
    cores=$(sed -n 's/^CPU_CORES=//p' /etc/vps-limits 2>/dev/null | head -n 1 | tr -dc '0-9')
fi
case "$cores" in
    ''|*[!0-9]*) cores=0 ;;
esac
if [ "$cores" -gt 0 ]; then
    printf '%s\n' "$cores"
    exit 0
fi
for candidate in /usr/bin/nproc.real /bin/nproc.real /usr/bin/nproc /bin/nproc; do
    [ -x "$candidate" ] || continue
    grep -q '^# Plan-aware nproc' "$candidate" 2>/dev/null && continue
    exec "$candidate" "$@"
done
echo "nproc: real nproc binary not found" >&2
exit 127
'''

PROFILE_SHIM = r'''# Keep plan-aware df/nproc ahead of cached command paths in login shells.
case ":$PATH:" in
    *:/usr/local/bin:*) ;;
    *) PATH="/usr/local/bin:$PATH" ;;
esac
export PATH
hash -r 2>/dev/null || true
'''

# (shim path, canonical binary path, saved real binary, script)
RESOURCE_SHIMS = (
    ("usr/local/bin/df", "usr/bin/df", "usr/bin/df.real", DF_SHIM),
    ("usr/local/bin/nproc", "usr/bin/nproc", "usr/bin/nproc.real", NPROC_SHIM),
)


def _write_script(root: str, rel: str, script: str) -> bool:
    path = os.path.join(root, rel)
    try:
        if os.path.isfile(path):
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                if f.read() == script:
                    return False
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(script)
        os.chmod(path, 0o755)
        return True
    except OSError:
        return False


def install_resource_shims(root: str) -> bool:
    """Install df/nproc plan shims into a guest root. Returns True if changed.

    The shim is written to /usr/local/bin *and* over the canonical /usr/bin
    path.  Some guests resolve df from /usr/bin first (explicit paths, cached
    hashes, or scripts that reset PATH), so only covering /usr/local/bin is not
    enough.  The original binary is saved as <name>.real before replacement.
    """
    changed = False
    for shim_rel, bin_rel, backup_rel, script in RESOURCE_SHIMS:
        binary = os.path.join(root, bin_rel)
        backup = os.path.join(root, backup_rel)
        # Save a genuine coreutils binary once; never back up our own shim.
        if os.path.isfile(binary) and not os.path.isfile(backup):
            try:
                with open(binary, "r", encoding="utf-8", errors="replace") as f:
                    is_shim = f.read(64).startswith("#!/bin/sh\n# Plan-aware")
                if not is_shim:
                    os.makedirs(os.path.dirname(backup), exist_ok=True)
                    shutil.copy2(binary, backup)
                    changed = True
            except OSError:
                pass
        if os.path.isfile(backup):
            changed |= _write_script(root, bin_rel, script)
        changed |= _write_script(root, shim_rel, script)

    profile = os.path.join(root, "etc", "profile.d", "vps-plan.sh")
    try:
        current = ""
        if os.path.isfile(profile):
            with open(profile, "r", encoding="utf-8", errors="replace") as f:
                current = f.read()
        if current != PROFILE_SHIM:
            os.makedirs(os.path.dirname(profile), exist_ok=True)
            with open(profile, "w", encoding="utf-8") as f:
                f.write(PROFILE_SHIM)
            os.chmod(profile, 0o644)
            changed = True
    except OSError:
        pass
    return changed


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

    # Plan-aware df/nproc (host disk/CPU must not leak to the customer).
    if install_resource_shims(root):
        changed = True

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

    # --- host-side: plan-aware df/nproc shims (no apt/network needed) ---
    try:
        import vps as _vps
        install_resource_shims(_vps._path(inst.name))
    except Exception as e:
        print(f"[BRAND] resource shims failed: {e}")

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
