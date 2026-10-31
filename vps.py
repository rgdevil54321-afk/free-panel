"""
Chroot + sshd VPS backend.

This module replaces the LXD/pylxd implementation with a backend that only
needs plain Linux privileges (CAP_SYS_CHROOT, CAP_MKNOD, optional CAP_SYS_ADMIN
for /proc + devpts mounts).  It works inside unprivileged-ish Docker/LXC
containers where cgroup delegation is blocked and LXD cannot start.

How a VPS works here
--------------------
  * One shared, pre-built Ubuntu root filesystem lives in
        /var/lib/deup-vps/base
  * Each VPS is a full copy of that rootfs:
        /var/lib/deup-vps/<container_id>
  * A dedicated sshd runs jailed inside the copy with `chroot` and listens
    on the host's public port assigned by nat.py (10000-10999).
  * Metadata (cpu / ram / disk / password / ssh port) is kept outside the
    jail in /var/lib/deup-vps/meta/<container_id>.json.

Trade-offs (accepted for this host)
-----------------------------------
  * No cgroup limits: CPU/RAM quotas are recorded and displayed but not
    hard-enforced.
  * Networking is shared with the host.  Ports are visible to everyone.
  * Root inside the jail is host root from the kernel's point of view.

Everything else (create / start / stop / suspend / reinstall / destroy,
file manager, exec, logs, stats, sshx, mining detection) keeps the exact
public API that app.py imports.
"""

import base64
import json
import os
import re
import secrets
import shlex
import shutil
import signal
import sqlite3
import stat as statmod
import string
import subprocess
import time
import urllib.request

try:
    from brand import brand_container
except Exception:                                     # pragma: no cover
    def brand_container(inst):
        pass

# ── constants ───────────────────────────────────────────────────────────────

BACKEND      = "chroot"
IMAGE_ALIAS  = os.environ.get("VPS_IMAGE_ALIAS", "ubuntu/22.04")
STORAGE_POOL = os.environ.get("VPS_STORAGE_POOL", "zfs-new")
DB           = "panel.db"

VPS_ROOT  = os.environ.get("VPS_CHROOT_ROOT", "/var/lib/deup-vps")
BASE_ROOT = os.path.join(VPS_ROOT, "base")
META_DIR  = os.path.join(VPS_ROOT, "meta")
LOG_DIR   = os.path.join(VPS_ROOT, "logs")

MAX_VPS_PER_NODE     = 150
TOTAL_DISK_BUDGET_GB = 6 * 1024
try:
    MIN_FREE_DISK_GB = int(os.environ.get("MIN_FREE_DISK_GB", "5"))
except Exception:
    MIN_FREE_DISK_GB = 5

SSHX_LINK_RE   = re.compile(r"https://sshx\.io/s/[A-Za-z0-9]+#[A-Za-z0-9_-]+")
ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")

CHROOT_ENV = {
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "HOME": "/root",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "TERM": "dumb",
    "DEBIAN_FRONTEND": "noninteractive",
}

UBUNTU_BASE_INDEX = "https://cdimage.ubuntu.com/ubuntu-base/releases/22.04/release/"
UBUNTU_MIRROR     = "http://archive.ubuntu.com/ubuntu/"


# ── tiny result object (mimics pylxd exec result) ───────────────────────────

class _ExecResult:
    def __init__(self, exit_code: int, stdout: str, stderr: str):
        self.exit_code = exit_code
        self.stdout    = stdout
        self.stderr    = stderr

    @property
    def output(self):
        return (self.stdout or "") + (self.stderr or "")


# ── paths / metadata ────────────────────────────────────────────────────────

def _path(name: str) -> str:
    return os.path.join(VPS_ROOT, name)


def _meta_path(name: str) -> str:
    return os.path.join(META_DIR, name + ".json")


def _ensure_dirs():
    for d in (VPS_ROOT, META_DIR, LOG_DIR):
        os.makedirs(d, exist_ok=True)
    try:
        os.chmod(VPS_ROOT, 0o711)
    except Exception:
        pass


def _load_meta(name: str) -> dict | None:
    try:
        with open(_meta_path(name), "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _save_meta(name: str, data: dict):
    _ensure_dirs()
    tmp = _meta_path(name) + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    try:
        os.chmod(tmp, 0o600)
    except Exception:
        pass
    os.replace(tmp, _meta_path(name))


def _iter_metas():
    try:
        names = sorted(os.listdir(META_DIR))
    except Exception:
        return
    for fn in names:
        if not fn.endswith(".json"):
            continue
        try:
            with open(os.path.join(META_DIR, fn), "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict) and data.get("name"):
                yield data
        except Exception:
            continue


# ── process helpers ─────────────────────────────────────────────────────────

def _pids_in(name: str) -> list[int]:
    """Every PID whose root directory is this VPS' chroot."""
    real = os.path.realpath(_path(name))
    pids = []
    try:
        entries = os.listdir("/proc")
    except Exception:
        return pids
    for entry in entries:
        if not entry.isdigit():
            continue
        try:
            root = os.readlink(f"/proc/{entry}/root")
        except OSError:
            continue
        if os.path.realpath(root) == real:
            pids.append(int(entry))
    return pids


_SIGKILL = getattr(signal, "SIGKILL", signal.SIGTERM)
_SIGSTOP = getattr(signal, "SIGSTOP", signal.SIGTERM)
_SIGCONT = getattr(signal, "SIGCONT", signal.SIGTERM)


def _kill_all(name: str, sig=_SIGKILL):
    for pid in _pids_in(name):
        try:
            os.kill(pid, sig)
        except OSError:
            pass


def _wait_gone(name: str, timeout: float = 8.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not _pids_in(name):
            return True
        time.sleep(0.25)
    return not _pids_in(name)


# ── mount helpers (best effort) ─────────────────────────────────────────────

def _run(cmd: list, timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def _is_mounted(target: str) -> bool:
    target = os.path.realpath(target)
    try:
        with open("/proc/self/mountinfo", "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                parts = line.split()
                if len(parts) > 4 and parts[4] == target:
                    return True
    except Exception:
        pass
    return False


def _mount_bind(src: str, dst: str) -> bool:
    if _is_mounted(dst):
        return True
    try:
        os.makedirs(dst, exist_ok=True)
    except Exception:
        return False
    try:
        return _run(["mount", "--bind", src, dst], timeout=15).returncode == 0
    except Exception:
        return False


def _mount_fs(fstype: str, src: str, dst: str, options: str = "") -> bool:
    if _is_mounted(dst):
        return True
    try:
        os.makedirs(dst, exist_ok=True)
    except Exception:
        return False
    cmd = ["mount", "-t", fstype]
    if options:
        cmd += ["-o", options]
    cmd += [src, dst]
    try:
        return _run(cmd, timeout=15).returncode == 0
    except Exception:
        return False


def _umount(target: str):
    if not _is_mounted(target):
        return
    try:
        _run(["umount", "-l", target], timeout=15)
    except Exception:
        pass


def _mkdir_devices(root: str):
    devs = {
        "null":   (1, 3),
        "zero":   (1, 5),
        "full":   (1, 7),
        "random": (1, 8),
        "urandom": (1, 9),
        "tty":    (5, 0),
    }
    devdir = os.path.join(root, "dev")
    for name, (major, minor) in devs.items():
        p = os.path.join(devdir, name)
        if os.path.exists(p):
            continue
        try:
            os.mknod(p, 0o666 | statmod.S_IFCHR, os.makedev(major, minor))
            os.chmod(p, 0o666)
        except Exception:
            pass
    # /dev/ptmx -- prefer the devpts-provided node, fall back to c 5:2
    ptmx = os.path.join(devdir, "ptmx")
    if not os.path.lexists(ptmx):
        try:
            os.mknod(ptmx, 0o666 | statmod.S_IFCHR, os.makedev(5, 2))
            os.chmod(ptmx, 0o666)
        except Exception:
            pass
    try:
        os.chmod(os.path.join(root, "tmp"), 0o1777)
    except Exception:
        pass

    # /dev/fd, /dev/stdin, /dev/stdout, /dev/stderr -- needed for process
    # substitution (bash <(curl ...)), here-docs and piped installers.
    # These are symlinks into /proc, which must be mounted at runtime.
    fd_links = {
        "fd":     "/proc/self/fd",
        "stdin":  "/proc/self/fd/0",
        "stdout": "/proc/self/fd/1",
        "stderr": "/proc/self/fd/2",
    }
    for name, target in fd_links.items():
        p = os.path.join(devdir, name)
        if os.path.lexists(p):
            continue
        try:
            os.symlink(target, p)
        except Exception:
            pass


def _prepare_runtime(name: str) -> dict:
    """Mount /proc and a PTY-capable /dev/pts inside the jail (best effort)."""
    root = _path(name)
    for sub in ("proc", "dev", "dev/pts", "dev/shm", "sys", "run", "run/sshd", "tmp"):
        try:
            os.makedirs(os.path.join(root, sub), exist_ok=True)
        except Exception:
            pass
    _mkdir_devices(root)
    _mkdir_devices(root)

    pts_ok = _mount_bind("/dev/pts", os.path.join(root, "dev", "pts"))
    if not pts_ok:
        pts_ok = _mount_fs(
            "devpts", "devpts", os.path.join(root, "dev", "pts"),
            "newinstance,ptmxmode=0666,mode=0620",
        )
    if pts_ok:
        # make sure /dev/ptmx resolves to the mounted devpts instance
        ptmx = os.path.join(root, "dev", "ptmx")
        try:
            if os.path.isfile(ptmx) or os.path.exists(ptmx):
                os.remove(ptmx)
            os.symlink("pts/ptmx", ptmx)
        except Exception:
            pass

    _mount_bind("/dev/shm", os.path.join(root, "dev", "shm"))
    proc_ok = _mount_fs("proc", "proc", os.path.join(root, "proc"))

    return {"proc": proc_ok, "devpts": pts_ok}


def _teardown_runtime(name: str):
    root = _path(name)
    for sub in ("proc", "dev/shm", "dev/pts", "sys"):
        _umount(os.path.join(root, sub))


# ── chroot exec ─────────────────────────────────────────────────────────────

def _chroot_run(name: str, cmd: str, timeout: int = 300,
                env: dict = None, stdin_data: str = None) -> _ExecResult:
    root = _path(name)
    if not os.path.isdir(root):
        return _ExecResult(127, "", f"VPS root not found: {name}")
    run_env = dict(CHROOT_ENV)
    if env:
        run_env.update({k: str(v) for k, v in env.items()})
    try:
        p = subprocess.run(
            ["chroot", root, "/bin/bash", "-c", cmd],
            capture_output=True, text=True, timeout=timeout,
            env=run_env, input=stdin_data,
            errors="replace",
        )
        return _ExecResult(p.returncode, p.stdout or "", p.stderr or "")
    except subprocess.TimeoutExpired:
        return _ExecResult(124, "", f"command timed out after {timeout}s")
    except Exception as e:
        return _ExecResult(127, "", str(e))


class _ChrootVPS:
    """Minimal object exposing .name and .execute() for brand.py & legacy code."""

    def __init__(self, name: str):
        self.name = name

    @property
    def config(self) -> dict:
        m = _load_meta(self.name) or {}
        return {
            "limits.cpu": str(m.get("cpu", get_free_vps_cpu())),
            "limits.memory": f"{m.get('ram_mb', get_free_vps_ram())}MB",
        }

    @property
    def devices(self) -> dict:
        m = _load_meta(self.name) or {}
        return {"root": {"path": "/", "size": f"{m.get('disk_gb', get_free_vps_disk())}GB"}}

    @property
    def status(self) -> str:
        return get_vps_status(self.name).get("status", "stopped")

    def sync(self):
        return None

    def state(self) -> dict:
        return {}

    def execute(self, cmd_list, environment=None) -> _ExecResult:
        if isinstance(cmd_list, str):
            cmd = cmd_list
        elif len(cmd_list) >= 3 and cmd_list[1] == "-c":
            cmd = cmd_list[2]
        else:
            cmd = " ".join(shlex.quote(str(c)) for c in cmd_list)
        return _chroot_run(self.name, cmd, env=environment)


# ── config helpers ──────────────────────────────────────────────────────────

def _get_config(key: str, default: str) -> str:
    try:
        db = sqlite3.connect(DB)
        row = db.execute("SELECT value FROM panel_config WHERE key=?", (key,)).fetchone()
        db.close()
        return row[0] if row else default
    except Exception:
        return default


def get_free_vps_cpu()  -> int:  return int(_get_config("vps_cpu_cores", "4"))
def get_free_vps_ram()  -> int:  return int(_get_config("vps_ram_gb", "4")) * 1024
def get_free_vps_disk() -> int:  return int(_get_config("vps_disk_gb", "80"))


# ── KVM ─────────────────────────────────────────────────────────────────────

def _probe_kvm() -> bool:
    # A chroot shares the host kernel; nested /dev/kvm is not exposed on this
    # class of host.  Keep the API so the panel keeps working unchanged.
    return False


def kvm_available() -> bool:
    return False


def set_kvm_enabled(container_id: str, enable: bool) -> bool:
    return False


# ── capacity ────────────────────────────────────────────────────────────────

def get_host_capacity() -> dict:
    cpu_cores = os.cpu_count() or 1
    ram_mb = 0
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    ram_mb = int(line.split()[1]) // 1024
                    break
    except Exception:
        pass

    real_disk_gb = None
    real_free_gb = None
    try:
        usage = shutil.disk_usage(VPS_ROOT if os.path.isdir(VPS_ROOT) else "/")
        real_disk_gb = usage.total // (1024 ** 3)
        real_free_gb = usage.free // (1024 ** 3)
    except Exception:
        pass

    return {
        "cpu_cores":         cpu_cores,
        "ram_mb":            ram_mb,
        "disk_budget_gb":    TOTAL_DISK_BUDGET_GB,
        "disk_allocated_gb": get_allocated_disk_gb(),
        "real_disk_gb":      real_disk_gb,
        "real_free_gb":      real_free_gb,
        "backend":           BACKEND,
    }


def get_allocated_disk_gb() -> int:
    total = 0
    for m in _iter_metas():
        try:
            total += int(m.get("disk_gb", 0))
        except Exception:
            pass
    return total


def can_allocate_disk(additional_gb: int):
    allocated = get_allocated_disk_gb()
    budget_ok = (allocated + additional_gb) <= TOTAL_DISK_BUDGET_GB

    real_free_gb = None
    try:
        usage = shutil.disk_usage(VPS_ROOT if os.path.isdir(VPS_ROOT) else "/")
        real_free_gb = usage.free // (1024 ** 3)
    except Exception:
        pass

    safety_ok = real_free_gb is None or real_free_gb >= MIN_FREE_DISK_GB
    if not safety_ok:
        return False, allocated, TOTAL_DISK_BUDGET_GB, (
            f"Only {real_free_gb}GB free on the host disk "
            f"(keeping {MIN_FREE_DISK_GB}GB reserve). Free up space first."
        )
    if not budget_ok:
        return False, allocated, TOTAL_DISK_BUDGET_GB, None
    return True, allocated, TOTAL_DISK_BUDGET_GB, None


def count_all_vps() -> int:
    try:
        return sum(
            1 for d in os.listdir(VPS_ROOT)
            if d.startswith("vps-") and os.path.isdir(os.path.join(VPS_ROOT, d))
        )
    except Exception:
        return 0


def get_max_vps_per_node():
    try:
        return int(_get_config("vps_max_per_node", str(MAX_VPS_PER_NODE)))
    except Exception:
        return MAX_VPS_PER_NODE


def can_create_vps():
    current = count_all_vps()
    return current < get_max_vps_per_node(), current


# ── base rootfs ─────────────────────────────────────────────────────────────

def base_rootfs_ready() -> bool:
    return (
        os.path.isdir(BASE_ROOT)
        and os.path.isfile(os.path.join(BASE_ROOT, "bin", "bash"))
        and os.path.isfile(os.path.join(BASE_ROOT, "usr", "sbin", "sshd"))
    )


def _download(url: str, dst: str, timeout: int = 60) -> bool:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "deup-panel/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r, open(dst, "wb") as f:
            shutil.copyfileobj(r, f, length=1024 * 256)
        return os.path.getsize(dst) > 1024 * 1024
    except Exception as e:
        print(f"[base] download failed ({url}): {e}")
        return False


def _ubuntu_base_url() -> str | None:
    try:
        html = urllib.request.urlopen(UBUNTU_BASE_INDEX, timeout=20).read().decode("utf-8", "replace")
        names = sorted(set(re.findall(r"ubuntu-base-22\.04\.\d+-base-amd64\.tar\.gz", html)))
        if names:
            return UBUNTU_BASE_INDEX + names[-1]
    except Exception as e:
        print(f"[base] index lookup failed: {e}")
    return UBUNTU_BASE_INDEX + "ubuntu-base-22.04.5-base-amd64.tar.gz"


def _install_openssh_in_chroot(root: str) -> bool:
    if os.path.isfile(os.path.join(root, "usr", "sbin", "sshd")):
        return True
    # network config inside the chroot
    try:
        os.makedirs(os.path.join(root, "etc"), exist_ok=True)
        shutil.copyfile("/etc/resolv.conf", os.path.join(root, "etc", "resolv.conf"))
    except Exception:
        with open(os.path.join(root, "etc", "resolv.conf"), "w") as f:
            f.write("nameserver 1.1.1.1\nnameserver 8.8.8.8\n")

    os.makedirs(os.path.join(root, "usr", "sbin"), exist_ok=True)
    with open(os.path.join(root, "usr", "sbin", "policy-rc.d"), "w") as f:
        f.write("#!/bin/sh\nexit 101\n")
    os.chmod(os.path.join(root, "usr", "sbin", "policy-rc.d"), 0o755)
    _mkdir_devices(root)

    # mount filesystems inside the chroot so apt-get works
    mounts = []
    for fstype, src, dst, opts in [
        ("proc", "proc", os.path.join(root, "proc"), ""),
        ("bind", "/dev", os.path.join(root, "dev"), ""),
        ("devpts", "devpts", os.path.join(root, "dev", "pts"), "newinstance,ptmxmode=0666,mode=0620"),
    ]:
        ok = False
        if fstype == "bind":
            ok = _mount_bind(src, dst)
        else:
            ok = _mount_fs(fstype, src, dst, opts)
        if ok:
            mounts.append(dst)

    try:
        steps = [
            "export DEBIAN_FRONTEND=noninteractive",
            # gpgv is missing in minimal base images; skip repo signature checks
            "apt-get -o Acquire::AllowInsecureRepositories=true "
            "-o Acquire::AllowDowngradeToInsecureRepositories=true update -qq",
            "apt-get -o Acquire::AllowInsecureRepositories=true "
            "-o Acquire::AllowDowngradeToInsecureRepositories=true install -y -qq "
            "--no-install-recommends openssh-server ca-certificates curl iproute2 procps less nano",
        ]
        for step in steps:
            res = subprocess.run(
                ["chroot", root, "/bin/bash", "-c", step],
                capture_output=True, text=True, timeout=900, env=CHROOT_ENV,
            )
            out = (res.stdout or "") + (res.stderr or "")
            if res.returncode != 0:
                print(f"[base] {step} failed (rc={res.returncode}): {out[-600:]}")
                return False
    except Exception as e:
        print(f"[base] apt inside chroot failed: {e}")
        return False
    finally:
        for dst in reversed(mounts):
            _umount(dst)
    return os.path.isfile(os.path.join(root, "usr", "sbin", "sshd"))


def _extract_tarfile_python(tarball: str, root: str) -> bool:
    """Extract tarball using Python's tarfile module (userspace).

    Python's tarfile opens destination files with 'wb' (O_CREAT|O_TRUNC,
    not O_EXCL), so it avoids GNU tar's EEXIST quirk on this container's
    filesystem where re-creating usr/bin/stat fails with 'File exists'.
    """
    import tarfile
    try:
        with tarfile.open(tarball, "r:gz") as tf:
            # Directories first so file parents exist, then everything else.
            members = sorted(tf.getmembers(), key=lambda m: (not m.isdir(), m.name))
            for m in members:
                try:
                    tf.extract(m, root, set_attrs=True)
                except Exception as e:
                    print(f"[base] tarfile: failed to extract {m.name}: {e}")
                    return False
    except Exception as e:
        print(f"[base] python tarfile open failed: {e}")
        return False
    return True


def _build_from_tarball(root: str) -> bool:
    url = _ubuntu_base_url()
    if not url:
        return False
    tarball = os.path.join("/tmp", f"ubuntu-base-{secrets.token_hex(4)}.tar.gz")
    try:
        print(f"[base] downloading {url}")
        if not _download(url, tarball, timeout=180):
            return False
        # force-clean target so a previous failed extract can't conflict
        shutil.rmtree(root, ignore_errors=True)
        os.makedirs(root, exist_ok=True)

        # Try Python tarfile first (avoids GNU tar EEXIST quirk on this host)
        if _extract_tarfile_python(tarball, root):
            print("[base] tarfile extraction succeeded")
        else:
            # Fallback: GNU tar with relaxed ownership/permissions
            print("[base] tarfile failed, trying GNU tar fallback")
            res = _run(
                ["tar", "-xzf", tarball, "-C", root,
                 "--no-same-owner", "--no-same-permissions", "--delay-directory-restore"],
                timeout=600,
            )
            if res.returncode != 0:
                print(f"[base] tar failed: {res.stderr[-400:]}")
                return False
    finally:
        try:
            os.remove(tarball)
        except Exception:
            pass
    return _install_openssh_in_chroot(root)


def _build_from_debootstrap(root: str) -> bool:
    if not shutil.which("debootstrap"):
        return False
    cmd = [
        "debootstrap", "--variant=minbase", "--no-check-gpg",
        "--include=openssh-server,ca-certificates,curl,iproute2,procps,less,nano",
        "jammy", root, UBUNTU_MIRROR,
    ]
    try:
        print("[base] running debootstrap (this takes a few minutes)")
        res = _run(cmd, timeout=1800)
        if res.returncode != 0:
            print(f"[base] debootstrap failed: {res.stderr[-600:]}")
            return False
    except Exception as e:
        print(f"[base] debootstrap error: {e}")
        return False
    return _install_openssh_in_chroot(root)


def _finalize_base(root: str):
    _mkdir_devices(root)
    for sub in ("run/sshd", "root", "home", "var/log", "var/empty",
                "proc", "sys", "dev/pts", "dev/shm"):
        os.makedirs(os.path.join(root, sub), exist_ok=True)
    try:
        os.chmod(os.path.join(root, "tmp"), 0o1777)
    except Exception:
        pass

    # stop services from trying to start at build/creation time
    prc = os.path.join(root, "usr", "sbin", "policy-rc.d")
    os.makedirs(os.path.dirname(prc), exist_ok=True)
    with open(prc, "w") as f:
        f.write("#!/bin/sh\nexit 101\n")
    os.chmod(prc, 0o755)

    # DNS
    try:
        shutil.copyfile("/etc/resolv.conf", os.path.join(root, "etc", "resolv.conf"))
    except Exception:
        with open(os.path.join(root, "etc", "resolv.conf"), "w") as f:
            f.write("nameserver 1.1.1.1\nnameserver 8.8.8.8\n")

    with open(os.path.join(root, "etc", "hostname"), "w") as f:
        f.write("vps-node\n")

    # make sure /etc/mtab is a symlink (some tools insist)
    try:
        mtab = os.path.join(root, "etc", "mtab")
        if os.path.lexists(mtab) and not os.path.islink(mtab):
            os.remove(mtab)
        if not os.path.lexists(mtab):
            os.symlink("/proc/mounts", mtab)
    except Exception:
        pass

    # neutral host keys: regenerated per VPS
    for fn in os.listdir(os.path.join(root, "etc", "ssh")):
        if fn.startswith("ssh_host_") and fn.endswith("_key"):
            try:
                os.remove(os.path.join(root, "etc", "ssh", fn))
            except Exception:
                pass


def _sshd_config(port: int) -> str:
    return f"""# Managed by DeupGaming panel -- do not edit
Port {port}
ListenAddress 0.0.0.0
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
PermitRootLogin yes
PubkeyAuthentication yes
PasswordAuthentication yes
PermitEmptyPasswords no
KbdInteractiveAuthentication no
UsePAM no
PidFile /run/sshd.pid
X11Forwarding yes
PrintMotd no
PrintLastLog yes
TCPKeepAlive yes
ClientAliveInterval 120
ClientAliveCountMax 3
AcceptEnv LANG LC_* TERM
Subsystem sftp /usr/lib/openssh/sftp-server
"""


def ensure_base_rootfs(verbose: bool = True) -> bool:
    """Build the shared base rootfs if it is missing.  Returns True on success."""
    _ensure_dirs()
    if base_rootfs_ready():
        if verbose:
            print(f"[base] ready: {BASE_ROOT}")
        return True

    tmp = BASE_ROOT + ".tmp." + secrets.token_hex(4)
    shutil.rmtree(tmp, ignore_errors=True)
    os.makedirs(tmp, exist_ok=True)

    ok = False
    try:
        ok = _build_from_tarball(tmp)
        if not ok:
            shutil.rmtree(tmp, ignore_errors=True)
            os.makedirs(tmp, exist_ok=True)
            ok = _build_from_debootstrap(tmp)
        if not ok:
            raise RuntimeError(
                "could not build the base rootfs (network problem or missing tools); "
                "run 'apt-get install -y debootstrap' and try again"
            )
        _finalize_base(tmp)
        if base_rootfs_ready_path(tmp):
            # Move any existing BASE_ROOT out of the way (rename works on
            # non-empty dirs even with /proc /dev mount points underneath,
            # which rm -rf / os.replace cannot handle).
            if os.path.isdir(BASE_ROOT):
                old = BASE_ROOT + ".old." + secrets.token_hex(4)
                try:
                    os.rename(BASE_ROOT, old)
                    # best-effort cleanup of the old dir in background
                    for sub in ("proc", "dev/pts", "dev", "sys", "dev/shm"):
                        _umount(os.path.join(old, sub))
                    shutil.rmtree(old, ignore_errors=True)
                except Exception:
                    pass
            os.replace(tmp, BASE_ROOT)
            if verbose:
                print(f"[base] built at {BASE_ROOT}")
            return True
        raise RuntimeError("base rootfs incomplete after build")
    except Exception as e:
        print(f"[base] ERROR: {e}")
        shutil.rmtree(tmp, ignore_errors=True)
        return False


def base_rootfs_ready_path(root: str) -> bool:
    return (
        os.path.isfile(os.path.join(root, "bin", "bash"))
        and os.path.isfile(os.path.join(root, "usr", "sbin", "sshd"))
    )


# ── per-VPS setup ───────────────────────────────────────────────────────────

def _write_sshd_config(name: str, port: int = 22):
    root = _path(name)
    cfgdir = os.path.join(root, "etc", "ssh")
    os.makedirs(cfgdir, exist_ok=True)
    with open(os.path.join(cfgdir, "sshd_config"), "w", encoding="utf-8") as f:
        f.write(_sshd_config(port))
    os.makedirs(os.path.join(root, "run", "sshd"), exist_ok=True)
    os.makedirs(os.path.join(root, "var", "empty"), exist_ok=True)
    try:
        os.chmod(os.path.join(root, "run"), 0o755)
        os.chmod(os.path.join(root, "run", "sshd"), 0o755)
        os.chmod(os.path.join(root, "var", "empty"), 0o755)
    except Exception:
        pass


def _set_password(name: str, password: str) -> bool:
    res = _chroot_run(name, "/usr/sbin/chpasswd", timeout=30,
                      stdin_data=f"root:{password}\n")
    if res.exit_code == 0:
        return True
    # fallback: chpasswd may not be on PATH inside minimal images
    res = _chroot_run(
        name,
        f"echo {shlex.quote('root:' + password)} | /usr/sbin/chpasswd",
        timeout=30,
    )
    if res.exit_code == 0:
        return True
    # last resort: write the shadow entry on the host using openssl
    try:
        out = subprocess.run(["openssl", "passwd", "-6", password],
                             capture_output=True, text=True, timeout=30)
        hashed = (out.stdout or "").strip()
        if not hashed:
            return False
        shadow = os.path.join(_path(name), "etc", "shadow")
        lines = []
        found = False
        with open(shadow, "r", errors="replace") as f:
            for line in f:
                parts = line.rstrip("\n").split(":")
                if parts and parts[0] == "root":
                    parts[1] = hashed
                    if len(parts) > 2:
                        parts[2] = "19000"     # force a password change epoch reset
                    line = ":".join(parts) + "\n"
                    found = True
                lines.append(line)
        if not found:
            lines.insert(0, f"root:{hashed}:19000:0:99999:7:::\n")
        with open(shadow, "w") as f:
            f.writelines(lines)
        os.chmod(shadow, 0o640)
        return True
    except Exception as e:
        print(f"[vps] password fallback failed: {e}")
        return False


def _gen_host_keys(name: str):
    root = _path(name)
    _chroot_run(name, "rm -f /etc/ssh/ssh_host_*; /usr/bin/ssh-keygen -A >/dev/null 2>&1 || true",
                timeout=120)
    # fallback: generate on the host if the guest image has no ssh-keygen
    for keytype in ("rsa", "ed25519"):
        path = os.path.join(root, "etc", "ssh", f"ssh_host_{keytype}_key")
        if os.path.isfile(path):
            continue
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            subprocess.run(
                ["ssh-keygen", "-q", "-t", keytype, "-N", "", "-f", path],
                capture_output=True, timeout=60,
            )
        except Exception:
            pass


def _setup_guest_identity(name: str):
    hostname = "vps-" + "".join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(6))
    root = _path(name)
    try:
        with open(os.path.join(root, "etc", "hostname"), "w") as f:
            f.write(hostname + "\n")
        with open(os.path.join(root, "etc", "hosts"), "w") as f:
            f.write("127.0.0.1\tlocalhost\n")
            f.write(f"127.0.1.1\t{hostname}\n")
            f.write("::1\tlocalhost ip6-localhost ip6-loopback\n")
    except Exception:
        pass
    try:
        with open(os.path.join(root, "etc", "machine-id"), "w") as f:
            f.write(secrets.token_hex(16) + "\n")
    except Exception:
        pass


def _sshd_pid(name: str) -> int | None:
    pidfile = os.path.join(_path(name), "run", "sshd.pid")
    try:
        with open(pidfile) as f:
            return int(f.read().strip())
    except Exception:
        return None


def _sshd_running(name: str) -> bool:
    pid = _sshd_pid(name)
    if pid:
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            pass
    return bool(_pids_in(name))


def _configured_port(name: str) -> int | None:
    try:
        with open(os.path.join(_path(name), "etc", "ssh", "sshd_config"), "r",
                  errors="replace") as f:
            for line in f:
                line = line.strip()
                if line.startswith("Port "):
                    return int(line.split()[1])
    except Exception:
        pass
    return None


def _start_sshd(name: str, port: int) -> tuple[bool, str]:
    root = _path(name)
    meta = _load_meta(name) or {}
    if meta.get("port") != port:
        meta["port"] = int(port)
        _save_meta(name, meta)

    # already healthy on the right port -> nothing to do (keeps live sessions)
    if _sshd_running(name) and _configured_port(name) == int(port):
        meta["state"] = "running"
        _save_meta(name, meta)
        return True, ""

    _write_sshd_config(name, port)
    _prepare_runtime(name)

    sshd = os.path.join(root, "usr", "sbin", "sshd")
    if not os.path.isfile(sshd):
        return False, "sshd is missing from the VPS rootfs (base image incomplete)"

    # stop a stale daemon first
    _kill_all(name)
    _wait_gone(name, 5)

    logpath = os.path.join(LOG_DIR, name + ".log")
    os.makedirs(LOG_DIR, exist_ok=True)
    try:
        with open(logpath, "ab") as log:
            log.write(f"\n--- start {time.strftime('%Y-%m-%d %H:%M:%S')} port {port} ---\n".encode())
            log.flush()
            res = subprocess.run(
                ["chroot", root, "/usr/sbin/sshd", "-p", str(port),
                 "-o", "PidFile=/run/sshd.pid"],
                stdout=log, stderr=log, timeout=60, env=CHROOT_ENV,
            )
    except Exception as e:
        return False, f"sshd launch failed: {e}"

    if res.returncode != 0:
        return False, f"sshd exited with {res.returncode} (see {logpath})"

    # wait for the daemon
    for _ in range(40):
        time.sleep(0.25)
        pid = _sshd_pid(name)
        if pid and _pid_alive(pid):
            meta = _load_meta(name) or {}
            meta["state"] = "running"
            meta["sshd_pid"] = pid
            _save_meta(name, meta)
            return True, ""
        if _pids_in(name):
            meta = _load_meta(name) or {}
            meta["state"] = "running"
            _save_meta(name, meta)
            return True, ""
    tail = ""
    try:
        with open(logpath, "r", errors="replace") as f:
            tail = "".join(f.readlines()[-6:])
    except Exception:
        pass
    return False, f"sshd did not stay up: {tail.strip()}"


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


# ── create / destroy ────────────────────────────────────────────────────────

def generate_password(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def get_root_password(container_id: str) -> str:
    meta = _load_meta(container_id)
    if not meta:
        raise RuntimeError("VPS not found")
    return meta.get("password", "")


def reset_root_password(container_id: str) -> str:
    meta = _load_meta(container_id)
    if not meta:
        raise RuntimeError("VPS not found")
    password = generate_password()
    meta["password"] = password
    _save_meta(container_id, meta)
    _set_password(container_id, password)
    return password


def _create_raw(username: str, cpu: int, ram_mb: int, disk_gb: int,
                image: str = IMAGE_ALIAS) -> dict:
    if not base_rootfs_ready():
        if not ensure_base_rootfs():
            return {"error": "Base rootfs is not ready and could not be built. "
                             "Check internet access, then retry."}

    password = generate_password()
    name = f"vps-{username}-{secrets.token_hex(3)}"
    final = _path(name)
    tmp = final + ".tmp"

    try:
        shutil.rmtree(tmp, ignore_errors=True)
        os.makedirs(tmp, exist_ok=True)
        # copy the base rootfs (reflink where the filesystem supports it)
        res = _run(["cp", "-a", "--reflink=auto", BASE_ROOT + "/.", tmp], timeout=900)
        if res.returncode != 0:
            shutil.copytree(BASE_ROOT, tmp, symlinks=True, dirs_exist_ok=True)

        tmpname = os.path.basename(tmp)
        _setup_guest_identity(tmpname)
        _write_sshd_config(tmpname, 22)
        _mkdir_devices(tmp)

        # password inside the copy (uses the temp path)
        if not _set_password(tmpname, password):
            raise RuntimeError("could not set the root password in the new VPS")

        _gen_host_keys(tmpname)
        _teardown_runtime(tmpname)

        if os.path.isdir(final):
            shutil.rmtree(final, ignore_errors=True)
        os.replace(tmp, final)

        _save_meta(name, {
            "name": name,
            "cpu": int(cpu),
            "ram_mb": int(ram_mb),
            "disk_gb": int(disk_gb),
            "password": password,
            "port": None,
            "state": "stopped",
            "created": int(time.time()),
        })
        return {"container_id": name, "password": password, "status": "stopped"}
    except Exception as e:
        shutil.rmtree(tmp, ignore_errors=True)
        return {"error": str(e)}


def create_vps_container(
    username: str,
    cpu_limit: int = None,
    ram_limit_mb: int = None,
    disk_limit_gb: int = None,
    image: str = IMAGE_ALIAS,
    kvm_enabled: bool = False,
):
    """Creates a chroot VPS and returns (container_id, sshx_url|'__terminal_only__')."""
    cpu  = cpu_limit    if cpu_limit    is not None else get_free_vps_cpu()
    ram  = ram_limit_mb if ram_limit_mb is not None else get_free_vps_ram()
    disk = disk_limit_gb if disk_limit_gb is not None else get_free_vps_disk()

    allowed, current = can_create_vps()
    if not allowed:
        raise RuntimeError(
            f"Node VPS limit reached ({current}/{get_max_vps_per_node()}). "
            "No new VPS can be created until existing ones are deleted."
        )

    ok, allocated, budget, why = can_allocate_disk(disk)
    if not ok:
        raise RuntimeError(why or f"Not enough disk budget ({allocated}/{budget} GB used).")

    result = _create_raw(username, cpu, ram, disk, image)
    if "error" in result:
        raise RuntimeError(result["error"])

    cid = result["container_id"]
    inst = _ChrootVPS(cid)

    try:
        brand_container(inst)
    except Exception as e:
        print(f"[BRAND] {e}")

    # Give sshx a PTY inside the jail before it starts: sshx allocates
    # /dev/pts for the shell it spawns.  Best-effort — if mount is blocked
    # on the host, sshx still runs but with no interactive terminal.
    try:
        _prepare_runtime(cid)
    except Exception as e:
        print(f"[vps] runtime mount for sshx failed on {cid}: {e}")

    # sshx browser terminal (optional; panel terminal is the fallback)
    sshx_ready = False
    for attempt in range(3):
        if _install_sshx(inst):
            sshx_ready = True
            break
        print(f"[sshx] install attempt {attempt+1}/3 failed, retrying in 5s...")
        time.sleep(5)

    session_url = None
    if sshx_ready:
        for attempt in range(5):
            session_url = _start_sshx_session(inst)
            if session_url:
                break
            print(f"[sshx] session attempt {attempt+1}/5 failed, retrying in 5s...")
            time.sleep(5)

    if not session_url:
        print(f"[sshx] WARNING: sshx not established for {cid} — "
              "browser terminal will be used as fallback.")
        return cid, "__terminal_only__"

    return cid, session_url


def attach_ssh_port(container_id: str, port: int) -> dict:
    """Called by nat.py once a public SSH port has been allocated."""
    meta = _load_meta(container_id)
    if not meta:
        return {"ok": False, "error": "VPS not found"}
    if not os.path.isdir(_path(container_id)):
        return {"ok": False, "error": "VPS rootfs not found"}
    ok, err = _start_sshd(container_id, int(port))
    if not ok:
        print(f"[sshd] {container_id}: {err}")
    return {"ok": ok, "error": err, "port": int(port)}


def get_vps_specs(container_id: str) -> dict | None:
    meta = _load_meta(container_id)
    if not meta:
        return None
    return {
        "cpu_cores": int(meta.get("cpu", get_free_vps_cpu())),
        "ram_mb":    int(meta.get("ram_mb", get_free_vps_ram())),
        "disk_gb":   int(meta.get("disk_gb", get_free_vps_disk())),
    }


def reinstall_vps(container_id: str, username: str, kvm_enabled: bool = False):
    specs = get_vps_specs(container_id) or {
        "cpu_cores": get_free_vps_cpu(),
        "ram_mb":    get_free_vps_ram(),
        "disk_gb":   get_free_vps_disk(),
    }
    try:
        destroy_vps(container_id)
    except Exception:
        pass
    return create_vps_container(
        username,
        cpu_limit=specs["cpu_cores"],
        ram_limit_mb=specs["ram_mb"],
        disk_limit_gb=specs["disk_gb"],
        kvm_enabled=kvm_enabled,
    )


def destroy_vps(container_id: str) -> dict:
    if not _load_meta(container_id) and not os.path.isdir(_path(container_id)):
        return {"error": "not found"}
    _kill_all(container_id, _SIGKILL)
    _wait_gone(container_id, 8)
    _kill_all(container_id, _SIGKILL)
    _teardown_runtime(container_id)
    shutil.rmtree(_path(container_id), ignore_errors=True)
    try:
        os.remove(_meta_path(container_id))
    except Exception:
        pass
    try:
        os.remove(os.path.join(LOG_DIR, container_id + ".log"))
    except Exception:
        pass
    return {"status": "deleted"}


# ── lifecycle ───────────────────────────────────────────────────────────────

def start_vps(container_id: str) -> dict:
    meta = _load_meta(container_id)
    if not meta:
        return {"error": "not found"}
    port = meta.get("port")
    if not port:
        return {"error": "No SSH port assigned yet — reopen the VPS from the panel "
                         "or restart the panel service."}
    ok, err = _start_sshd(container_id, int(port))
    if not ok:
        return {"error": err}
    meta["state"] = "running"
    _save_meta(container_id, meta)
    return {"status": "started"}


def stop_vps(container_id: str) -> dict:
    meta = _load_meta(container_id)
    if not meta:
        return {"error": "not found"}
    _kill_all(container_id, _SIGKILL)
    _wait_gone(container_id, 8)
    _teardown_runtime(container_id)
    meta["state"] = "stopped"
    _save_meta(container_id, meta)
    return {"status": "stopped"}


def suspend_vps(container_id: str) -> dict:
    meta = _load_meta(container_id)
    if not meta:
        return {"error": "not found"}
    pids = _pids_in(container_id)
    if not pids:
        stop_vps(container_id)
        return {"status": "suspended"}
    for pid in pids:
        try:
            os.kill(pid, _SIGSTOP)
        except OSError:
            pass
    meta["state"] = "suspended"
    _save_meta(container_id, meta)
    return {"status": "suspended"}


def unsuspend_vps(container_id: str) -> dict:
    meta = _load_meta(container_id)
    if not meta:
        return {"error": "not found"}
    pids = _pids_in(container_id)
    if not pids:
        return start_vps(container_id)
    for pid in pids:
        try:
            os.kill(pid, _SIGCONT)
        except OSError:
            pass
    meta["state"] = "running"
    _save_meta(container_id, meta)
    return {"status": "running"}


def get_vps_status(container_id: str) -> dict:
    meta = _load_meta(container_id)
    if not meta and not os.path.isdir(_path(container_id)):
        return {"status": "not_found"}
    pids = _pids_in(container_id)
    if not pids:
        state = "stopped"
    elif meta and meta.get("state") == "suspended":
        state = "frozen"
    else:
        state = "running"
    return {"status": state, "name": container_id}


def sync_status(container_id: str, db_status: str) -> str:
    if db_status not in ("running", "stopped"):
        return db_status
    real = get_vps_status(container_id).get("status", db_status)
    return real if real in ("running", "stopped") else db_status


# ── sshx ────────────────────────────────────────────────────────────────────

def _install_sshx(inst) -> bool:
    env = {"HOME": "/root", "DEBIAN_FRONTEND": "noninteractive"}
    find_cmd = (
        "command -v sshx || "
        "for p in /root/.local/bin/sshx /usr/local/bin/sshx /usr/bin/sshx; do "
        "  [ -x \"$p\" ] && echo \"$p\" && break; done"
    )
    try:
        check = inst.execute(["bash", "-c", find_cmd], environment=env)
        found = (check.stdout or "").strip()
        if found:
            _ensure_symlinked(inst, found, env)
            return True

        curl_ok = inst.execute(["bash", "-c", "command -v curl"], environment=env)
        if not (curl_ok.stdout or "").strip():
            if not _apt_install_with_retry(inst, "curl", env):
                return False

        install_cmd = (
            "curl --retry 3 --retry-delay 2 --retry-connrefused "
            "--connect-timeout 10 -sSf https://sshx.io/get | sh"
        )
        for _ in range(3):
            result = inst.execute(["bash", "-c", install_cmd], environment=env)
            if result.exit_code == 0:
                break
            time.sleep(2)

        check2 = inst.execute(["bash", "-c", find_cmd], environment=env)
        found = (check2.stdout or "").strip()
        if not found:
            return False
        _ensure_symlinked(inst, found, env)
        return True
    except Exception as e:
        print(f"[sshx install] {e}")
        return False


def _ensure_symlinked(inst, found_path: str, env: dict):
    if found_path == "/usr/local/bin/sshx":
        return
    try:
        inst.execute(["bash", "-c", f"ln -sf '{found_path}' /usr/local/bin/sshx"],
                     environment=env)
    except Exception:
        pass


def _apt_install_with_retry(inst, package: str, env: dict, attempts: int = 5) -> bool:
    wait_lock = (
        "for i in $(seq 1 30); do "
        "  fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || break; sleep 1; done"
    )
    for _ in range(attempts):
        inst.execute(["bash", "-c", wait_lock], environment=env)
        result = inst.execute(
            ["bash", "-c", f"apt-get update -qq && apt-get install -y -qq {package}"],
            environment=env,
        )
        if result.exit_code == 0:
            return True
        time.sleep(4)
    return False


def _start_sshx_session(inst) -> str | None:
    try:
        inst.execute(["bash", "-c", "pkill sshx 2>/dev/null; rm -f /tmp/sshx.log; true"])
        inst.execute(["bash", "-c",
                      "setsid sh -c 'NO_COLOR=1 TERM=dumb nohup sshx > /tmp/sshx.log 2>&1 < /dev/null' >/dev/null 2>&1 &"])
        for tick in range(30):
            time.sleep(1)
            result = inst.execute(["bash", "-c", "cat /tmp/sshx.log 2>/dev/null || true"])
            raw_log = result.stdout or ""
            clean_log = ANSI_ESCAPE_RE.sub("", raw_log)
            match = SSHX_LINK_RE.search(clean_log)
            if match:
                print(f"[sshx] session link found after {tick+1}s")
                return match.group(0)
            if (tick + 1) % 5 == 0:
                print(f"[sshx] waiting for link... {tick+1}s elapsed")
        print("[sshx] timed out after 30s — no link found in log")
        return None
    except Exception as e:
        print(f"[sshx session] {e}")
        return None


def regen_sshx(container_id: str) -> str | None:
    inst = _ChrootVPS(container_id)
    if not os.path.isdir(_path(container_id)):
        raise RuntimeError("VPS not found")
    env = {"HOME": "/root", "DEBIAN_FRONTEND": "noninteractive"}
    find_cmd = "command -v sshx || ls /root/.local/bin/sshx /usr/local/bin/sshx 2>/dev/null | head -1"
    check = inst.execute(["bash", "-c", find_cmd], environment=env)
    if not (check.stdout or "").strip():
        print("[regen_sshx] sshx not found — attempting install first")
        _install_sshx(inst)
    return _start_sshx_session(inst)


# ── stats ───────────────────────────────────────────────────────────────────

_cpu_sample_cache: dict = {}
_HZ = None


def _clock_ticks() -> int:
    global _HZ
    if _HZ is None:
        try:
            _HZ = int(os.sysconf("SC_CLK_TCK"))
        except Exception:
            _HZ = 100
    return _HZ


def _proc_stat(pid: int) -> tuple[int, int, int] | None:
    try:
        with open(f"/proc/{pid}/stat", "rb") as f:
            data = f.read().decode("utf-8", "replace")
        # comm may contain spaces/parens -> split after the last ')'
        rest = data[data.rfind(")") + 2:].split()
        utime = int(rest[11])
        stime = int(rest[12])
        with open(f"/proc/{pid}/statm", "rb") as f:
            statm = f.read().split()
        rss_pages = int(statm[1])
        return utime + stime, rss_pages, 0
    except Exception:
        return None


def get_container_stats(container_id: str, created_at: int = None) -> dict:
    if not _load_meta(container_id) and not os.path.isdir(_path(container_id)):
        raise RuntimeError("VPS not found")

    meta = _load_meta(container_id) or {}
    pids = _pids_in(container_id)

    ticks = 0
    rss_pages = 0
    for pid in pids:
        st = _proc_stat(pid)
        if st:
            ticks += st[0]
            rss_pages += st[1]

    hz = _clock_ticks()
    cpu_sec = ticks / float(hz)
    mem_bytes = rss_pages * (os.sysconf("SC_PAGE_SIZE") if hasattr(os, "sysconf") else 4096)

    num_cpus = int(meta.get("cpu", 1) or 1)
    mem_limit_bytes = int(meta.get("ram_mb", 0) or 0) * 1024 * 1024

    t_now = time.time()
    cpu_pct = 0.0
    prev = _cpu_sample_cache.get(container_id)
    if prev:
        cpu_prev, t_prev = prev
        elapsed = t_now - t_prev
        delta = cpu_sec - cpu_prev
        if elapsed > 0 and delta >= 0:
            cpu_pct = (delta / (elapsed * num_cpus)) * 100.0
    _cpu_sample_cache[container_id] = (cpu_sec, t_now)

    mem_pct = (mem_bytes / mem_limit_bytes * 100.0) if mem_limit_bytes else 0.0
    uptime_sec = int(time.time() - created_at) if created_at else None

    return {
        "cpu_percent": round(cpu_pct, 2),
        "mem_usage_mb": round(mem_bytes / (1024 * 1024), 1),
        "mem_limit_mb": round(mem_limit_bytes / (1024 * 1024), 1),
        "mem_percent": round(mem_pct, 2),
        "uptime_seconds": uptime_sec,
    }


# ── mining detection ────────────────────────────────────────────────────────

_SAFE_PROCS = [
    "sshx", "sshd", "systemd", "systemd-journald", "systemd-logind",
    "apt", "apt-get", "dpkg", "unattended-upgrade", "cron", "bash",
    "python3", "app.py", "monitor.py", "vps.py", "gunicorn", "flask",
    "init", "dbus-daemon", "rsyslogd", "networkd-dispatcher",
]

_MINER_SIGS = [
    "xmrig", "xmr-stak", "cpuminer", "minerd", "cryptonight",
    "nicehash", "ethminer", "t-rex", "lolminer", "phoenixminer",
    "srbminer", "teamredminer", "unmineable", "kdevtmpfsi", "kinsing",
]

_MINER_PORTS = ["3333", "4444", "5555", "7777", "8080", "9999", "14444", "45700"]

_MINER_CMDS = [
    "--donate-level", "--cpu-priority", "-o stratum+tcp", "stratum+tcp://",
    "stratum+ssl://", "--algo=", "-a randomx", "-a rx/0", "--coin=monero",
    "--pool=", "-o pool.", "xmrig -o", "xmrig --url",
]


def _ps_text(container_id: str) -> str:
    lines = []
    for pid in _pids_in(container_id):
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                cmd = f.read().replace(b"\x00", b" ").decode("utf-8", "replace").strip()
        except Exception:
            continue
        lines.append(f"{pid} {cmd}")
    return "\n".join(lines)


def _connections_text(container_id: str) -> str:
    pids = set(_pids_in(container_id))
    if not pids:
        return ""
    try:
        out = _run(["ss", "-tnp"], timeout=10).stdout or ""
    except Exception:
        return ""
    keep = []
    for line in out.splitlines():
        for pid in pids:
            if f"pid={pid}," in line:
                keep.append(line)
                break
    return "\n".join(keep)


def check_for_mining(container_id: str) -> dict:
    if not _load_meta(container_id) and not os.path.isdir(_path(container_id)):
        return {"suspected": False, "confidence": "low", "reasons": ["not found"], "raw": {}}

    weak, raw = [], {}

    try:
        ps = _ps_text(container_id)
        raw["ps"] = ps[:2000]
        for line in ps.lower().splitlines():
            if any(s in line for s in _SAFE_PROCS):
                continue
            for sig in _MINER_SIGS:
                if sig in line:
                    weak.append(f"process: '{sig}'")
    except Exception as e:
        raw["ps_error"] = str(e)

    try:
        conns = _connections_text(container_id)
        raw["conns"] = conns[:2000]
        for port in _MINER_PORTS:
            if f":{port}" in conns:
                weak.append(f"connection on mining port {port}")
    except Exception as e:
        raw["conns_error"] = str(e)

    strong = []
    try:
        hist_path = os.path.join(_path(container_id), "root", ".bash_history")
        try:
            with open(hist_path, "r", errors="replace") as f:
                history = f.read().lower()
        except Exception:
            history = ""
        history += "\n" + _ps_text(container_id).lower()
        for pattern in _MINER_CMDS:
            if pattern.lower() in history:
                strong.append(f"activation command: '{pattern}'")
    except Exception:
        pass

    if strong:
        return {"suspected": True, "confidence": "high", "reasons": strong, "raw": raw}
    if len(weak) >= 2:
        return {"suspected": True, "confidence": "low", "reasons": weak, "raw": raw}
    return {"suspected": False, "confidence": "low", "reasons": weak, "raw": raw}


def handle_high_cpu(container_id: str, threshold: float = 90.0) -> dict:
    try:
        stats = get_container_stats(container_id)
    except Exception:
        return {"action": "none", "cpu_percent": 0.0}

    if stats["cpu_percent"] < threshold:
        return {"action": "none", "cpu_percent": stats["cpu_percent"]}

    mining = check_for_mining(container_id)
    if mining["suspected"] and mining["confidence"] == "high":
        suspend_vps(container_id)
        return {
            "action": "suspended",
            "cpu_percent": stats["cpu_percent"],
            "confidence": "high",
            "reasons": mining["reasons"],
        }
    if mining["suspected"]:
        return {
            "action": "flagged_for_review",
            "cpu_percent": stats["cpu_percent"],
            "confidence": "low",
            "reasons": mining["reasons"],
        }
    return {
        "action": "none",
        "cpu_percent": stats["cpu_percent"],
        "note": "high CPU, no mining evidence",
    }


# ── file manager ────────────────────────────────────────────────────────────

def _safe_path(path: str) -> str:
    if not path:
        return path
    parts = path.replace("\\", "/").split("/")
    if ".." in parts:
        raise ValueError("Path traversal not allowed")
    return path


def _host_path(container_id: str, path: str) -> str:
    _safe_path(path)
    base = os.path.realpath(_path(container_id))
    if not os.path.isdir(base):
        raise RuntimeError("VPS not found")
    return _resolve_in_root(base, str(path))


def _resolve_in_root(base: str, path: str, depth: int = 0) -> str:
    """Resolve a VPS-internal path without ever escaping the jail.

    Absolute symlinks are interpreted as if the jail were `/` (real chroot
    semantics), which the naive os.path.realpath() gets wrong on the host.
    """
    if depth > 32:
        raise ValueError("Too many levels of symbolic links")
    parts = [p for p in path.replace("\\", "/").split("/") if p not in ("", ".")]
    cur = base
    for i, part in enumerate(parts):
        if part == "..":
            cur = os.path.dirname(cur)
            if cur != base and not cur.startswith(base + os.sep):
                raise ValueError("Path escapes the VPS filesystem")
            continue
        nxt = os.path.join(cur, part)
        if os.path.islink(nxt):
            try:
                target = os.readlink(nxt)
            except OSError:
                raise ValueError("Cannot read symbolic link")
            if target.startswith("/"):
                joined = os.path.join(base, target.lstrip("/"))
            else:
                joined = os.path.join(cur, target)
            rest = "/".join(parts[i + 1:])
            rel = os.path.relpath(joined, base)
            if rel == ".":
                rel = ""
            return _resolve_in_root(base, (rel + "/" + rest) if rest else rel, depth + 1)
        cur = nxt
    if cur != base and not cur.startswith(base + os.sep):
        raise ValueError("Path escapes the VPS filesystem")
    return cur


def list_files(container_id: str, path: str = "/root") -> list[dict]:
    target = _host_path(container_id, path)
    if not os.path.isdir(target):
        raise RuntimeError("Not a directory")
    entries = []
    with os.scandir(target) as it:
        for e in it:
            try:
                is_link = e.is_symlink()
                is_dir = e.is_dir(follow_symlinks=False)
                st = e.stat(follow_symlinks=False)
                size = st.st_size
                perms = statmod.filemode(st.st_mode)
            except OSError:
                is_link = False
                is_dir = False
                size = 0
                perms = "??????????"
            entries.append({
                "name":  e.name,
                "type":  "dir" if is_dir else ("link" if is_link else "file"),
                "size":  size,
                "perms": perms,
            })
    entries.sort(key=lambda x: (x["type"] != "dir", x["name"].lower()))
    return entries


def read_file_b64(container_id: str, path: str) -> str:
    target = _host_path(container_id, path)
    with open(target, "rb") as f:
        return base64.b64encode(f.read()).decode("ascii")


def write_file_b64(container_id: str, path: str, b64_content: str):
    _safe_path(path)
    target = _host_path(container_id, path)
    data = base64.b64decode(b64_content or "")
    parent = os.path.dirname(target)
    if not os.path.isdir(parent):
        raise RuntimeError("Parent directory does not exist")
    with open(target, "wb") as f:
        f.write(data)


def delete_file(container_id: str, path: str):
    _safe_path(path)
    dangerous = {"/", "/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64",
                 "/proc", "/sys", "/dev", "/boot", "/run", "/var"}
    if path.rstrip("/") in dangerous:
        raise RuntimeError("Refusing to delete protected path")
    target = _host_path(container_id, path)
    base = os.path.realpath(_path(container_id))
    if target == base:
        raise RuntimeError("Refusing to delete protected path")
    if os.path.isdir(target) and not os.path.islink(target):
        shutil.rmtree(target)
    else:
        os.remove(target)


def create_directory(container_id: str, path: str):
    _safe_path(path)
    target = _host_path(container_id, path)
    os.makedirs(target, exist_ok=True)


def exec_command(container_id: str, cmd: str) -> dict:
    if not _load_meta(container_id) and not os.path.isdir(_path(container_id)):
        return {"error": "not found"}
    result = _chroot_run(container_id, cmd, timeout=600)
    out = (result.stdout or "") + (result.stderr or "")
    if len(out) > 1024 * 1024:
        out = out[: 1024 * 1024] + "\n...[truncated]"
    return {"exit_code": result.exit_code, "output": out}


# ── logs ────────────────────────────────────────────────────────────────────

def build_logs_stream(container_id: str):
    if not _load_meta(container_id):
        yield "VPS not found"
        return
    logpath = os.path.join(LOG_DIR, container_id + ".log")
    if os.path.isfile(logpath):
        try:
            with open(logpath, "r", errors="replace") as f:
                for line in f.readlines()[-120:]:
                    yield line.rstrip("\n")
            return
        except Exception as e:
            yield f"Could not read logs: {e}"
            return
    result = _chroot_run(container_id, "tail -n 100 /var/log/syslog 2>/dev/null || echo 'no logs yet'",
                         timeout=30)
    for line in (result.stdout or "").splitlines():
        yield line


# ── resources ───────────────────────────────────────────────────────────────

def update_vps_resources(container_id, cpu=None, ram_mb=None, disk_gb=None):
    meta = _load_meta(container_id)
    if not meta:
        return False, "vps not found"
    try:
        if cpu is not None:
            meta["cpu"] = max(1, int(cpu))
        if ram_mb is not None:
            meta["ram_mb"] = max(128, int(ram_mb))
        if disk_gb is not None:
            meta["disk_gb"] = max(1, int(disk_gb))
        _save_meta(container_id, meta)
        return True, "updated (quotas are not hard-enforced by the chroot backend)"
    except Exception as e:
        return False, str(e)
