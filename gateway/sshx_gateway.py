#!/usr/bin/python3
"""Unprivileged SSHX session gateway.

Installed as /opt/sshx/bin/sshx_gateway.py, owned by root, executed ONLY as the
system account ``sshx-gw`` by sshx_manager.  It never runs as root, never sees
host environment variables, and has no customer-controlled arguments: the only
argument is a server-generated session id.  The shell that sshx spawns is the
fixed :mod:`sshx-target-shell` wrapper, which connects to the customer's own
VPS over SSH.
"""

import json
import os
import re
import resource
import signal
import subprocess
import sys
import time

SESSION_ID_RE = re.compile(r"^[a-f0-9]{32}$")
CONTAINER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
LINK_RE = re.compile(r"https://sshx\.io/s/[A-Za-z0-9]+#[A-Za-z0-9_-]+")
ANSI_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")

_child = None


def _stop(signum=None, frame=None):
    global _child
    if _child and _child.poll() is None:
        try:
            os.killpg(_child.pid, signal.SIGTERM)
        except OSError:
            try:
                _child.terminate()
            except OSError:
                pass
        try:
            _child.wait(timeout=3)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(_child.pid, signal.SIGKILL)
            except OSError:
                pass
    sys.exit(0)


def main() -> int:
    global _child

    # Hard refusal: this process must never be root.
    if os.geteuid() == 0:
        sys.stderr.write("sshx gateway refuses to run as root\n")
        return 78

    # Defense in depth: refuse new privileges and cap resource usage.
    try:
        import ctypes
        ctypes.CDLL("libc.so.6", use_errno=True).prctl(36, 1, 0, 0, 0)
    except Exception:
        pass
    for res, limit in (
        (resource.RLIMIT_CPU, 3600),
        (resource.RLIMIT_AS, 512 * 1024 * 1024),
        (resource.RLIMIT_FSIZE, 8 * 1024 * 1024),
        (resource.RLIMIT_NOFILE, 128),
        (resource.RLIMIT_CORE, 0),
    ):
        try:
            resource.setrlimit(res, (limit, limit))
        except Exception:
            pass

    if len(sys.argv) != 2 or not SESSION_ID_RE.match(sys.argv[1]):
        return 2
    session_id = sys.argv[1]
    root = os.environ.get("SSHX_SESSION_ROOT", "/var/lib/deup-vps/sshx")
    spec_path = os.path.join(root, session_id, "spec.json")

    # Only a minimal, server-built environment is inherited.
    os.environ.clear()
    os.environ.update({
        "PATH": "/usr/bin:/bin",
        "HOME": os.environ.get("HOME", "/var/lib/sshx-gw"),
        "LANG": "C.UTF-8",
        "TERM": "dumb",
        "NO_COLOR": "1",
        "SSHX_SESSION_ID": session_id,
        "SSHX_SESSION_ROOT": root,
    })

    try:
        with open(spec_path, "r", encoding="utf-8") as f:
            spec = json.load(f)
    except Exception:
        return 3

    if spec.get("session_id") != session_id:
        return 3
    if int(spec.get("expires_at", 0)) <= int(time.time()):
        return 4

    # The destination identity is server-generated.  Reject anything else,
    # even if an attacker managed to alter the session spec.
    cid = spec.get("container_id", "")
    if not CONTAINER_RE.match(cid) or cid in ("pending", "pending-overflow", "overflow-failed"):
        return 3
    if spec.get("ssh_host") != "127.0.0.1" or spec.get("ssh_user") != "root":
        return 3
    port = spec.get("ssh_port")
    if not isinstance(port, int) or not 1 <= port <= 65535:
        return 3

    link_path = spec.get("link_path", "")
    log_path = spec.get("log_path", "")
    session_dir = os.path.realpath(os.path.join(root, session_id))
    for path in (link_path, log_path):
        if not path or os.path.realpath(os.path.dirname(path)) != session_dir:
            return 3

    def _trusted_binary(path: str) -> bool:
        if not os.path.isfile(path) or not os.access(path, os.X_OK):
            return False
        st = os.stat(path)
        # Executables used by the gateway must be root-owned and not writable
        # by the service account or by anyone else.
        return st.st_uid == 0 and not (st.st_mode & 0o022)

    sshx = spec.get("sshx_binary", "/opt/sshx/sshx")
    target = spec.get("target_shell", "/opt/sshx/bin/sshx-target-shell")
    ssh_client = spec.get("ssh_binary", "/usr/bin/ssh")
    if not _trusted_binary(sshx) or not _trusted_binary(target) or not _trusted_binary(ssh_client):
        return 5

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    # Explicit argument vector.  No shell interpretation and no interpolation
    # of any browser-supplied value.  --shell forces the fixed SSH wrapper.
    cmd = [sshx, "--quiet", "--name", spec.get("container_id", "vps"),
           "--shell", target]

    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": os.environ["HOME"],
        "LANG": "C.UTF-8",
        "TERM": "dumb",
        "NO_COLOR": "1",
        "SSHX_SESSION_ID": session_id,
        "SSHX_SESSION_ROOT": root,
    }
    if spec.get("ssh_binary"):
        env["SSHX_SSH_BINARY"] = spec["ssh_binary"]

    logf = open(log_path, "ab", buffering=0)
    try:
        try:
            _child = subprocess.Popen(
                cmd, env=env, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                start_new_session=True, close_fds=True,
            )
        except Exception:
            return 6

        for raw in _child.stdout:
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            clean = ANSI_RE.sub("", line)
            match = LINK_RE.search(clean)
            if match and not os.path.exists(link_path):
                # The link is a bearer credential.  Write it only to the
                # root-readable session file, never to the audit log.
                tmp = link_path + ".tmp"
                fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                try:
                    os.write(fd, (match.group(0) + "\n").encode("ascii"))
                finally:
                    os.close(fd)
                os.replace(tmp, link_path)
                clean = LINK_RE.sub("[sshx-link-redacted]", clean)
            logf.write((clean[:2000] + "\n").encode("utf-8", "replace"))
        return _child.wait()
    finally:
        logf.close()
        # Never leave a reusable link behind when the gateway exits.
        try:
            os.remove(link_path)
        except OSError:
            pass


if __name__ == "__main__":
    sys.exit(main())
