"""
SSHX secure session manager.

SECURITY MODEL
--------------
The legacy implementation started ``sshx`` *as root* inside the customer's
chroot and published a permanent, shareable link.  A chroot is NOT a security
boundary: root inside it is root on the host kernel, the session shared the
host network namespace and host PTYs, and the link was a long-lived bearer
credential for a root shell.  That is how customers reached the main VPS.

This module replaces that design.  Every SSHX session is:

  * authorized from the database, never from browser supplied host/port/key
    parameters;
  * bound to one authenticated panel user and one VPS they own;
  * short lived, revocable, and audited;
  * backed by a per-session SSH key that only exists on the panel and is
    injected into the *customer's own* VPS sshd as a restricted, time-bounded
    authorized_keys entry;
  * run by an unprivileged service account (``sshx-gw``), never root;
  * proxied through a fixed wrapper whose only action is ``ssh`` to the
    customer's VPS.  The browser never gets a host shell.

The sshx client itself runs on the panel host, but ONLY as the locked-down
``sshx-gw`` user with a fixed forced command.  It has no host shell, no host
environment, no privileged sockets, and no customer-controlled arguments.
"""

from __future__ import annotations

import base64
import ctypes
import datetime as _dt
import hashlib
import json
import os
import pwd
import re
import resource
import secrets
import signal
import sqlite3
import stat
import subprocess
import sys
import threading
import time
from typing import Any

import vps as vps_mod

# ── Configuration (overridable for tests / non-standard installs) ────────────
DB = os.environ.get("SSHX_DB_PATH", "panel.db")
SESSION_ROOT = os.environ.get("SSHX_SESSION_ROOT", os.path.join(vps_mod.VPS_ROOT, "sshx"))
GATEWAY_USER = os.environ.get("SSHX_GATEWAY_USER", "sshx-gw")
GATEWAY_HOME = os.environ.get("SSHX_GATEWAY_HOME", "/var/lib/sshx-gw")
GATEWAY_SCRIPT = os.environ.get(
    "SSHX_GATEWAY_SCRIPT", "/opt/sshx/bin/sshx_gateway.py"
)
TARGET_SHELL = os.environ.get(
    "SSHX_TARGET_SHELL", "/opt/sshx/bin/sshx-target-shell"
)
SSHX_BINARY = os.environ.get("SSHX_BINARY", "/opt/sshx/sshx")
SSH_BINARY = os.environ.get("SSHX_SSH_BINARY", "/usr/bin/ssh")
KEYGEN_BINARY = os.environ.get("SSHX_KEYGEN_BINARY", "/usr/bin/ssh-keygen")
# The gateway uses only the standard library.  It must not inherit the panel's
# venv interpreter: the sshx-gw account may not be able to traverse the repo
# directory (e.g. /root/free-panel or /home/<user>/free-panel).
GATEWAY_PYTHON = os.environ.get("SSHX_GATEWAY_PYTHON", "/usr/bin/python3")

SESSION_TTL_SECONDS = int(os.environ.get("SSHX_SESSION_TTL", "900"))       # 15 min
LINK_WAIT_SECONDS = float(os.environ.get("SSHX_LINK_WAIT", "12"))
MAX_ACTIVE_PER_USER = int(os.environ.get("SSHX_MAX_PER_USER", "2"))
MAX_ACTIVE_PER_VPS = int(os.environ.get("SSHX_MAX_PER_VPS", "1"))
IDLE_TIMEOUT_SECONDS = int(os.environ.get("SSHX_IDLE_TIMEOUT", "600"))     # 10 min
CREATE_RATE_WINDOW = 60
CREATE_RATE_MAX = 3
CONTAINED_POLICY = "sshx_contained"
GLOBAL_POLICY = "global_enabled"

SSHD_HOST = "127.0.0.1"          # fixed: never taken from the request
SSHD_USER = "root"               # root *inside the customer's own VPS*
CONTAINER_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
SESSION_ID_RE = re.compile(r"^[a-f0-9]{32}$")
SSHX_URL_RE = re.compile(r"https://sshx\.io/s/[A-Za-z0-9]+#[A-Za-z0-9_-]+")
ANSI_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")

_lock = threading.RLock()
_sweeper_started = False


# ── Database / schema ────────────────────────────────────────────────────────

def _connect() -> sqlite3.Connection:
    db = sqlite3.connect(DB, timeout=15)
    db.row_factory = sqlite3.Row
    return db


def init_sshx_tables(db: sqlite3.Connection | None = None) -> None:
    """Create SSHX tables and migrate legacy rows.  Safe to call repeatedly.

    Migrations are additive only: no customer/VPS row is ever dropped.  The
    containment flag defaults to ``1`` so an upgraded installation cannot serve
    sessions until an administrator explicitly validates isolation.
    """
    own = db is None
    db = db or _connect()
    try:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS sshx_sessions (
                id            TEXT PRIMARY KEY,
                user_id       INTEGER NOT NULL,
                vps_id        INTEGER NOT NULL,
                container_id  TEXT NOT NULL,
                status        TEXT NOT NULL DEFAULT 'starting',
                created_at    INTEGER NOT NULL,
                expires_at    INTEGER NOT NULL,
                last_seen     INTEGER,
                pid           INTEGER,
                remote_ip     TEXT,
                closed_at     INTEGER
            );
            CREATE INDEX IF NOT EXISTS idx_sshx_sessions_user
                ON sshx_sessions(user_id, status);
            CREATE INDEX IF NOT EXISTS idx_sshx_sessions_vps
                ON sshx_sessions(vps_id, status);
            CREATE INDEX IF NOT EXISTS idx_sshx_sessions_state
                ON sshx_sessions(status, expires_at, last_seen);
            CREATE TABLE IF NOT EXISTS sshx_events (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                user_id    INTEGER,
                vps_id     INTEGER,
                actor_id   INTEGER,
                action     TEXT NOT NULL,
                reason     TEXT,
                ip         TEXT,
                created_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_sshx_events_created
                ON sshx_events(created_at DESC);
            CREATE TABLE IF NOT EXISTS sshx_policy (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sshx_disabled (
                scope      TEXT NOT NULL,
                target_id  INTEGER NOT NULL,
                reason     TEXT,
                created_by INTEGER,
                created_at INTEGER NOT NULL,
                PRIMARY KEY (scope, target_id)
            );
            """
        )
        # Fail closed.  INSERT OR IGNORE preserves an administrator's explicit
        # choice on subsequent runs; new/upgraded installs start contained.
        for key, value in ((CONTAINED_POLICY, "1"), (GLOBAL_POLICY, "0"),
                           ("default_ttl", str(SESSION_TTL_SECONDS))):
            db.execute("INSERT OR IGNORE INTO sshx_policy(key,value) VALUES(?,?)", (key, value))
        # Legacy rows stored a permanent sshx URL inside ssh_command.  Remove it
        # so it can never be rendered, copied, or reused.
        for row in db.execute("SELECT id, ssh_command FROM vps WHERE ssh_command LIKE '%||%'"):
            raw = row["ssh_command"] or ""
            if "|||" in raw:
                cleaned = raw.split("|||", 1)[0]
                db.execute("UPDATE vps SET ssh_command=? WHERE id=?", (cleaned, row["id"]))
            elif SSHX_URL_RE.search(raw):
                db.execute("UPDATE vps SET ssh_command=NULL WHERE id=?", (row["id"],))
        # Resolve historical duplicates before adding the partial unique index.
        # Keep the newest session per VPS; mark older ones failed (no data loss
        # to customers or VPS records).
        seen: set[int] = set()
        for row in db.execute(
            "SELECT id, vps_id FROM sshx_sessions"
            " WHERE status IN ('starting','active') ORDER BY created_at DESC, id DESC"
        ).fetchall():
            if row["vps_id"] in seen:
                db.execute(
                    "UPDATE sshx_sessions SET status='failed', closed_at=? WHERE id=?",
                    (int(time.time()), row["id"]),
                )
            else:
                seen.add(row["vps_id"])
        db.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_sshx_active_vps"
            " ON sshx_sessions(vps_id) WHERE status IN ('starting','active')"
        )
        db.commit()
    finally:
        if own:
            db.close()


def log_event(action: str, *, session_id: str | None = None,
              user_id: int | None = None, vps_id: int | None = None,
              actor_id: int | None = None, reason: str = "",
              ip: str = "", db: sqlite3.Connection | None = None) -> None:
    """Audit event.  Never pass credentials or links here."""
    own = db is None
    db = db or _connect()
    try:
        db.execute(
            "INSERT INTO sshx_events(session_id,user_id,vps_id,actor_id,action,reason,ip,created_at)"
            " VALUES(?,?,?,?,?,?,?,?)",
            (session_id, user_id, vps_id, actor_id, action, (reason or "")[:200],
             (ip or "")[:80], int(time.time())),
        )
        db.commit()
    except Exception:
        pass
    finally:
        if own:
            db.close()


# ── Policy helpers ───────────────────────────────────────────────────────────

def _policy(key: str, default: str, db: sqlite3.Connection | None = None) -> str:
    own = db is None
    db = db or _connect()
    try:
        row = db.execute("SELECT value FROM sshx_policy WHERE key=?", (key,)).fetchone()
        return row["value"] if row else default
    except Exception:
        return default
    finally:
        if own:
            db.close()


def set_policy(key: str, value: str) -> None:
    allowed = {GLOBAL_POLICY, CONTAINED_POLICY, "default_ttl"}
    if key not in allowed:
        raise ValueError("unknown policy")
    if key in (GLOBAL_POLICY, CONTAINED_POLICY) and value not in ("0", "1"):
        raise ValueError("invalid value")
    if key == "default_ttl" and (not value.isdigit() or not 60 <= int(value) <= 86400):
        raise ValueError("invalid value")
    db = _connect()
    try:
        db.execute("INSERT INTO sshx_policy(key,value) VALUES(?,?) "
                   "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))
        db.commit()
    finally:
        db.close()
    if key == GLOBAL_POLICY and value == "0":
        revoke_all_sessions(actor_id=None, reason="disabled globally")


def is_globally_enabled() -> bool:
    return _policy(GLOBAL_POLICY, "0") == "1"


def is_contained() -> bool:
    """True while public SSHX access is blocked for containment/maintenance."""
    return _policy(CONTAINED_POLICY, "1") == "1"


def set_contained(contained: bool, actor_id: int | None = None,
                  reason: str = "") -> None:
    """Enable/disable the fail-closed containment gate (admin action only)."""
    set_policy(CONTAINED_POLICY, "1" if contained else "0")
    log_event("containment_enabled" if contained else "containment_lifted",
              actor_id=actor_id, reason=reason)
    if contained:
        revoke_all_sessions(actor_id=actor_id, reason="containment enabled")


def verify_environment() -> tuple[bool, list[str]]:
    """Server-side prerequisites an admin must confirm before lifting containment."""
    failures: list[str] = []
    if os.geteuid() == 0:
        try:
            pwd.getpwnam(GATEWAY_USER)
        except KeyError:
            failures.append("sshx-gw service account missing")
    for label, path in (("gateway", GATEWAY_SCRIPT), ("target shell", TARGET_SHELL),
                        ("sshx client", SSHX_BINARY), ("ssh client", SSH_BINARY),
                        ("gateway python", GATEWAY_PYTHON)):
        if not os.path.isfile(path) or not os.access(path, os.X_OK):
            failures.append(f"{label} missing or not executable: {path}")
        else:
            st = os.stat(path)
            if st.st_uid != 0:
                failures.append(f"{label} is not root-owned: {path}")
            if st.st_mode & 0o022:
                failures.append(f"{label} is group/world writable: {path}")
    return not failures, failures


def set_disabled(scope: str, target_id: int, disabled: bool,
                 actor_id: int, reason: str = "") -> None:
    if scope not in ("user", "vps") or not isinstance(target_id, int) or target_id <= 0:
        raise ValueError("invalid target")
    db = _connect()
    try:
        if disabled:
            db.execute(
                "INSERT INTO sshx_disabled(scope,target_id,reason,created_by,created_at)"
                " VALUES(?,?,?,?,?) ON CONFLICT(scope,target_id) DO UPDATE SET"
                " reason=excluded.reason,created_by=excluded.created_by,created_at=excluded.created_at",
                (scope, target_id, reason[:200], actor_id, int(time.time())),
            )
        else:
            db.execute("DELETE FROM sshx_disabled WHERE scope=? AND target_id=?", (scope, target_id))
        db.commit()
    finally:
        db.close()
    log_event("admin_disable" if disabled else "admin_enable",
              user_id=target_id if scope == "user" else None,
              vps_id=target_id if scope == "vps" else None,
              actor_id=actor_id, reason=reason)
    if disabled:
        # Kill live sessions covered by the new restriction immediately.
        col = "user_id" if scope == "user" else "vps_id"
        db = _connect()
        try:
            ids = [r["id"] for r in db.execute(
                f"SELECT id FROM sshx_sessions WHERE status IN ('active','starting')"
                f" AND {col}=?", (target_id,),
            ).fetchall()]
        finally:
            db.close()
        for sid in ids:
            revoke_session(sid, actor_id=actor_id, trusted=True, reason=f"{scope} disabled")


def is_disabled(scope: str, target_id: int,
                db: sqlite3.Connection | None = None) -> bool:
    own = db is None
    db = db or _connect()
    try:
        row = db.execute("SELECT 1 FROM sshx_disabled WHERE scope=? AND target_id=?",
                         (scope, target_id)).fetchone()
        return bool(row)
    except Exception:
        return False
    finally:
        if own:
            db.close()


def list_disabled() -> list[dict]:
    db = _connect()
    rows = [dict(r) for r in db.execute(
        "SELECT scope,target_id,reason,created_at FROM sshx_disabled ORDER BY created_at DESC"
    )]
    db.close()
    return rows


# ── Authorization ────────────────────────────────────────────────────────────

def authorize_session(user_id: int, vps_id: int, db: sqlite3.Connection | None = None,
                      ip: str = "", audit: bool = True) -> tuple[bool, str, sqlite3.Row | None]:
    """The single gate for every SSHX session operation.

    Checks, in order: containment, global toggle, user suspension / per-user
    toggle, VPS existence, ownership, status, suspension, per-VPS toggle, NAT
    configuration and container-id validity.  No browser supplied connection
    parameter is ever read here.  ``audit=False`` is used when revalidating
    live sessions so periodic sweeps do not flood the audit log.
    """
    own = db is None
    db = db or _connect()
    def deny(reason: str):
        if audit:
            log_event("auth_deny", user_id=user_id, vps_id=vps_id,
                      reason=reason, ip=ip, db=db)
        return False, reason, None

    try:
        if not isinstance(user_id, int) or user_id <= 0 or not isinstance(vps_id, int) or vps_id <= 0:
            return deny("invalid identifiers")
        if _policy(CONTAINED_POLICY, "1", db) == "1":
            return deny("SSHX is disabled for maintenance; ask an administrator")
        if _policy(GLOBAL_POLICY, "0", db) != "1":
            return deny("sshx disabled globally")
        if is_disabled("user", user_id, db=db):
            return deny("sshx disabled for user")
        user = db.execute("SELECT is_suspended FROM users WHERE id=?", (user_id,)).fetchone()
        if not user:
            return deny("user not found")
        if user["is_suspended"]:
            return deny("user suspended")
        vps = db.execute("SELECT * FROM vps WHERE id=?", (vps_id,)).fetchone()
        if not vps:
            return deny("vps not found")
        if vps["user_id"] != user_id:
            return deny("vps not owned by user")
        if vps["status"] != "running":
            return deny(f"vps not running ({vps['status']})")
        if is_disabled("vps", vps_id, db=db):
            return deny("sshx disabled for vps")
        cid = vps["container_id"] or ""
        if not CONTAINER_ID_RE.match(cid) or cid in ("pending", "pending-overflow", "overflow-failed"):
            return deny("invalid container id")
        if not vps_mod.meta_exists(cid):
            return deny("vps metadata missing")
        meta = vps_mod.load_meta(cid) or {}
        if meta.get("state") == "suspended":
            return deny("vps suspended")
        nat_row = db.execute("SELECT * FROM nat_rules WHERE vps_id=?", (vps_id,)).fetchone()
        if not nat_row or not nat_row["ssh_port"]:
            return deny("no SSH connection configured")
        port = int(nat_row["ssh_port"])
        if not 1 <= port <= 65535:
            return deny("invalid SSH port")
        host_pubkey = vps_mod.get_host_public_key(cid, "ed25519")
        if not host_pubkey:
            return deny("vps host key unavailable")
        return True, "", vps
    finally:
        if own:
            db.close()


# ── Session files / credentials ──────────────────────────────────────────────

def _session_dir(session_id: str) -> str:
    if not SESSION_ID_RE.match(session_id or ""):
        raise ValueError("invalid session id")
    return os.path.join(SESSION_ROOT, session_id)


def _gateway_ids() -> tuple[int, int]:
    try:
        u = pwd.getpwnam(GATEWAY_USER)
        return u.pw_uid, u.pw_gid
    except KeyError:
        # Test / development fallback: never silently run as root in production.
        if os.geteuid() == 0:
            raise RuntimeError(f"service account {GATEWAY_USER} does not exist")
        return os.geteuid(), os.getegid()


def _write_session_spec(session_id: str, spec: dict) -> str:
    directory = _session_dir(session_id)
    os.makedirs(directory, mode=0o700, exist_ok=True)
    os.chmod(directory, 0o700)
    uid, gid = _gateway_ids()
    try:
        os.chown(directory, uid, gid)
    except (PermissionError, OSError):
        pass
    path = os.path.join(directory, "spec.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(spec, f)
    os.chmod(path, 0o600)
    try:
        os.chown(path, uid, gid)
    except (PermissionError, OSError):
        pass
    return path


def _generate_keypair(session_id: str) -> tuple[str, str]:
    """Create an ephemeral ED25519 keypair.  Returns (private_path, public_key)."""
    directory = _session_dir(session_id)
    key = os.path.join(directory, "id_ed25519")
    subprocess.run(
        [KEYGEN_BINARY, "-q", "-t", "ed25519", "-N", "", "-C", f"sshx-{session_id}", "-f", key],
        check=True, capture_output=True, timeout=30,
    )
    os.chmod(key, 0o600)
    with open(key + ".pub", "r", encoding="utf-8") as f:
        pub = f.read().strip()
    os.chmod(key + ".pub", 0o600)
    uid, gid = _gateway_ids()
    for p in (key, key + ".pub"):
        try:
            os.chown(p, uid, gid)
        except (PermissionError, OSError):
            pass
    return key, pub


def _write_known_hosts(session_id: str, cid: str, port: int, host_pubkey: str) -> str:
    directory = _session_dir(session_id)
    path = os.path.join(directory, "known_hosts")
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"[{SSHD_HOST}]:{port} {host_pubkey.strip()}\n")
    os.chmod(path, 0o600)
    uid, gid = _gateway_ids()
    try:
        os.chown(path, uid, gid)
    except (PermissionError, OSError):
        pass
    return path


def _add_authorized_key(cid: str, session_id: str, pubkey: str) -> None:
    """Inject a restricted, per-session key into the customer's own VPS."""
    marker = f"# sshx-session:{session_id}"
    entry = (
        f'from="{SSHD_HOST}",no-port-forwarding,no-agent-forwarding,'
        f'no-X11-forwarding {pubkey} {marker}'
    )
    vps_mod.add_authorized_key(cid, entry, marker)


def _remove_authorized_key(cid: str, session_id: str) -> None:
    vps_mod.remove_authorized_key_marker(cid, f"# sshx-session:{session_id}")


# ── Process launch ───────────────────────────────────────────────────────────

def _spawn_gateway(session_id: str, link_path: str, log_path: str) -> int:
    """Start the unprivileged gateway.  Returns its host PID."""
    uid, gid = _gateway_ids()
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": GATEWAY_HOME,
        "LANG": "C.UTF-8",
        "PYTHONIOENCODING": "utf-8",
        "SSHX_SESSION_ID": session_id,
        "SSHX_SESSION_ROOT": SESSION_ROOT,
        "SSHX_BINARY": SSHX_BINARY,
        "SSHX_TARGET_SHELL": TARGET_SHELL,
        "SSHX_SSH_BINARY": SSH_BINARY,
    }
    logf = open(log_path, "ab", buffering=0)
    # The gateway reopens this path itself after dropping privileges.  Make it
    # writable by sshx-gw; otherwise it dies before creating the link file.
    try:
        os.fchmod(logf.fileno(), 0o600)
        os.fchown(logf.fileno(), uid, gid)
    except OSError:
        pass

    def _demote():
        os.umask(0o077)
        try:
            libc = ctypes.CDLL("libc.so.6", use_errno=True)
            libc.prctl(36, 1, 0, 0, 0)          # PR_SET_NO_NEW_PRIVS
        except Exception:
            pass
        # Hard resource ceilings for each gateway process.
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
        os.setgroups([])
        os.setgid(gid)
        os.setuid(uid)

    kwargs: dict[str, Any] = dict(
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=logf,
        env=env,
        start_new_session=True,
        close_fds=True,
    )
    if sys.version_info >= (3, 9):
        kwargs.update(user=uid, group=gid, extra_groups=[])
    else:  # pragma: no cover - Python 3.8 fallback
        kwargs["preexec_fn"] = _demote
    try:
        proc = subprocess.Popen(
            [GATEWAY_PYTHON, GATEWAY_SCRIPT, session_id], **kwargs
        )
    finally:
        logf.close()
    return proc.pid


def _terminate_pid(pid: int | None) -> None:
    if not pid or pid <= 1:
        return
    try:
        os.killpg(os.getpgid(pid), signal.SIGTERM)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass
    deadline = time.time() + 3
    while time.time() < deadline:
        try:
            os.killpg(os.getpgid(pid), 0)
        except OSError:
            return
        time.sleep(0.1)
    try:
        os.killpg(os.getpgid(pid), signal.SIGKILL)
    except OSError:
        pass


def _session_files(session_id: str) -> tuple[str, str]:
    directory = _session_dir(session_id)
    return os.path.join(directory, "link.txt"), os.path.join(directory, "gateway.log")


def _read_link(session_id: str, timeout: float = LINK_WAIT_SECONDS) -> str | None:
    link_path, _ = _session_files(session_id)
    deadline = time.monotonic() + max(1.0, timeout)
    while time.monotonic() < deadline:
        try:
            with open(link_path, "r", encoding="utf-8") as f:
                value = f.read().strip()
            match = SSHX_URL_RE.search(ANSI_RE.sub("", value))
            if match:
                return match.group(0)
        except (FileNotFoundError, OSError):
            pass
        time.sleep(0.25)
    return None


# ── Session lifecycle ────────────────────────────────────────────────────────

def _active_count(db: sqlite3.Connection, column: str, target: int) -> int:
    row = db.execute(
        f"SELECT COUNT(*) FROM sshx_sessions WHERE {column}=?"
        " AND status IN ('starting','active') AND expires_at>?",
        (target, int(time.time())),
    ).fetchone()
    return int(row[0]) if row else 0


def create_session(user_id: int, vps_id: int, ip: str = "") -> tuple[dict | None, str]:
    """Create a new authorized SSHX session.

    Returns ``(public_session_info, error)``.  The SSHX URL is returned exactly
    once, in ``public_session_info['url']``; it is never written to logs, the
    database, a URL, or browser storage.
    """
    db = _connect()
    try:
        ok, reason, vps = authorize_session(user_id, vps_id, db=db, ip=ip)
        if not ok:
            return None, reason

        with _lock:
            recent = db.execute(
                "SELECT COUNT(*) FROM sshx_sessions WHERE user_id=? AND created_at>?",
                (user_id, int(time.time()) - CREATE_RATE_WINDOW),
            ).fetchone()[0]
            if recent >= CREATE_RATE_MAX:
                log_event("rate_limit", user_id=user_id, vps_id=vps_id, ip=ip, db=db)
                return None, "too many session requests"
            if _active_count(db, "user_id", user_id) >= MAX_ACTIVE_PER_USER:
                return None, "concurrent session limit reached"
            if _active_count(db, "vps_id", vps_id) >= MAX_ACTIVE_PER_VPS:
                return None, "VPS already has an active session"

            session_id = secrets.token_hex(16)
            now = int(time.time())
            ttl = int(_policy("default_ttl", str(SESSION_TTL_SECONDS)))
            ttl = max(60, min(ttl, 86400))
            cid = vps["container_id"]
            port = int(db.execute("SELECT ssh_port FROM nat_rules WHERE vps_id=?",
                                  (vps_id,)).fetchone()[0])

            try:
                db.execute(
                    "INSERT INTO sshx_sessions(id,user_id,vps_id,container_id,status,"
                    "created_at,expires_at,last_seen,remote_ip)"
                    " VALUES(?,?,?,?,'starting',?,?,?,?)",
                    (session_id, user_id, vps_id, cid, now, now + ttl, now, ip),
                )
                # Partial unique index is the cross-process backstop; the lock
                # above covers requests handled by this panel process.
                db.commit()
            except sqlite3.IntegrityError:
                db.rollback()
                return None, "VPS already has an active session"

        try:
            directory = _session_dir(session_id)
            os.makedirs(directory, mode=0o700, exist_ok=True)
            os.chmod(directory, 0o700)
            key_path, pubkey = _generate_keypair(session_id)
            host_pubkey = vps_mod.get_host_public_key(cid, "ed25519")
            if not host_pubkey:
                raise RuntimeError("VPS host key unavailable")
            known_hosts = _write_known_hosts(session_id, cid, port, host_pubkey)
            _add_authorized_key(cid, session_id, pubkey)
            link_path, log_path = _session_files(session_id)
            spec = {
                "session_id": session_id,
                "container_id": cid,
                "ssh_port": port,
                "ssh_host": SSHD_HOST,
                "ssh_user": SSHD_USER,
                "key_path": key_path,
                "known_hosts": known_hosts,
                "link_path": link_path,
                "log_path": log_path,
                "sshx_binary": SSHX_BINARY,
                "target_shell": TARGET_SHELL,
                "ssh_binary": SSH_BINARY,
                "expires_at": now + ttl,
            }
            _write_session_spec(session_id, spec)
            pid = _spawn_gateway(session_id, link_path, log_path)
            db.execute("UPDATE sshx_sessions SET pid=?,status='starting' WHERE id=?",
                       (pid, session_id))
            db.commit()
            log_event("session_created", session_id=session_id, user_id=user_id,
                      vps_id=vps_id, ip=ip, db=db)
        except Exception as exc:
            # Never include exception text with paths/keys in the log event.
            try:
                _remove_authorized_key(cid, session_id)
            except Exception:
                pass
            db.execute("UPDATE sshx_sessions SET status='failed',closed_at=? WHERE id=?",
                       (int(time.time()), session_id))
            db.commit()
            log_event("session_failed", session_id=session_id, user_id=user_id,
                      vps_id=vps_id, reason=type(exc).__name__, ip=ip, db=db)
            return None, "could not start session"

        url = _read_link(session_id)
        if not url:
            revoke_session(session_id, actor_id=user_id, trusted=True, reason="gateway timeout")
            return None, "session gateway did not start"

        if not session_still_active(session_id):
            # Authorization changed while the gateway was starting.
            revoke_session(session_id, actor_id=user_id, trusted=True,
                           reason="authorization changed during startup")
            return None, "session authorization was revoked"

        db.execute(
            "UPDATE sshx_sessions SET status='active',last_seen=? WHERE id=?",
            (int(time.time()), session_id),
        )
        db.commit()

        # Only the owner can learn the URL.  It is deliberately not persisted.
        return {
            "id": session_id,
            "vps_id": vps_id,
            "url": url,
            "expires_at": now + ttl,
            "ttl": ttl,
        }, ""
    finally:
        db.close()


def get_session(session_id: str, user_id: int | None = None,
                is_admin: bool = False) -> dict | None:
    """Return a session only when the caller is its owner (or an admin)."""
    if not SESSION_ID_RE.match(session_id or ""):
        return None
    db = _connect()
    try:
        row = db.execute("SELECT * FROM sshx_sessions WHERE id=?", (session_id,)).fetchone()
        if not row:
            return None
        if not is_admin and (user_id is None or row["user_id"] != user_id):
            return None
        return dict(row)
    finally:
        db.close()


def touch_session(session_id: str, user_id: int | None = None,
                  is_admin: bool = False) -> bool:
    """Record that an authorized caller is still using this session.

    This is what makes idle cleanup meaningful: the customer's dashboard polls
    status only while the terminal page is open.  A closed browser stops the
    heartbeat and the sweeper revokes the session after IDLE_TIMEOUT_SECONDS.
    """
    row = get_session(session_id, user_id, is_admin)
    if not row or row["status"] not in ("starting", "active"):
        return False
    db = _connect()
    try:
        db.execute(
            "UPDATE sshx_sessions SET last_seen=? WHERE id=? AND status IN ('starting','active')",
            (int(time.time()), session_id),
        )
        db.commit()
        return True
    finally:
        db.close()


def session_still_active(session_id: str) -> bool:
    """Re-run the authorization gate against a live session (no audit spam)."""
    db = _connect()
    try:
        row = db.execute("SELECT user_id,vps_id,status,expires_at FROM sshx_sessions"
                         " WHERE id=?", (session_id,)).fetchone()
        if not row or row["status"] not in ("starting", "active") or row["expires_at"] <= int(time.time()):
            return False
        ok, _, _ = authorize_session(row["user_id"], row["vps_id"], db=db, audit=False)
        return ok
    finally:
        db.close()


def enforce_live_authorizations() -> int:
    """Revoke sessions whose customer/VPS authorization was lost mid-session."""
    db = _connect()
    try:
        rows = db.execute(
            "SELECT id,user_id,vps_id,container_id,pid,status FROM sshx_sessions"
            " WHERE status IN ('starting','active')"
        ).fetchall()
        revoked = []
        for row in rows:
            ok, reason, _ = authorize_session(row["user_id"], row["vps_id"],
                                              db=db, audit=False)
            if not ok:
                revoked.append((row["id"], row["user_id"], row["vps_id"],
                                row["container_id"], row["pid"], reason))
    finally:
        db.close()
    for sid, uid, vid, cid, pid, reason in revoked:
        log_event("authz_revoked", session_id=sid, user_id=uid, vps_id=vid,
                  reason=reason[:200])
        revoke_session(sid, trusted=True, reason=reason)
    return len(revoked)


def revoke_all_sessions(actor_id: int | None = None, reason: str = "",
                        *, user_id: int | None = None,
                        vps_id: int | None = None) -> int:
    """Revoke every active session, optionally scoped to one user or VPS."""
    clauses, args = ["status IN ('starting','active')"], []
    if user_id is not None:
        clauses.append("user_id=?"); args.append(user_id)
    if vps_id is not None:
        clauses.append("vps_id=?"); args.append(vps_id)
    sql = "SELECT id FROM sshx_sessions WHERE " + " AND ".join(clauses)
    db = _connect()
    try:
        ids = [r["id"] for r in db.execute(sql, tuple(args)).fetchall()]
    finally:
        db.close()
    for sid in ids:
        revoke_session(sid, actor_id=actor_id, trusted=True, reason=reason)
    return len(ids)


def list_sessions(user_id: int | None = None, limit: int = 200) -> list[dict]:
    db = _connect()
    try:
        if user_id is None:
            rows = db.execute(
                "SELECT s.*,u.username,v.container_id AS vps_container FROM sshx_sessions s"
                " LEFT JOIN users u ON u.id=s.user_id"
                " LEFT JOIN vps v ON v.id=s.vps_id"
                " ORDER BY s.created_at DESC LIMIT ?", (limit,),
            ).fetchall()
        else:
            rows = db.execute(
                "SELECT s.*,u.username,v.container_id AS vps_container FROM sshx_sessions s"
                " LEFT JOIN users u ON u.id=s.user_id"
                " LEFT JOIN vps v ON v.id=s.vps_id"
                " WHERE s.user_id=? ORDER BY s.created_at DESC LIMIT ?", (user_id, limit),
            ).fetchall()
        return [dict(r) for r in rows]
    finally:
        db.close()


def list_events(limit: int = 300, session_id: str | None = None) -> list[dict]:
    db = _connect()
    try:
        if session_id:
            rows = db.execute(
                "SELECT e.*,u.username FROM sshx_events e"
                " LEFT JOIN users u ON u.id=e.user_id"
                " WHERE e.session_id=? ORDER BY e.created_at DESC LIMIT ?",
                (session_id, limit),
            ).fetchall()
        else:
            rows = db.execute(
                "SELECT e.*,u.username FROM sshx_events e"
                " LEFT JOIN users u ON u.id=e.user_id"
                " ORDER BY e.created_at DESC LIMIT ?", (limit,),
            ).fetchall()
        return [dict(r) for r in rows]
    finally:
        db.close()


def revoke_session(session_id: str, actor_id: int | None = None,
                   reason: str = "", *, trusted: bool = False,
                   user_id: int | None = None, is_admin: bool = False) -> bool:
    """Terminate a session and scrub all of its credentials.

    ``trusted`` is only set by internal callers (expiry sweeper, policy
    changes).  Browser callers must provide a matching ``user_id`` unless they
    are administrators.
    """
    if not SESSION_ID_RE.match(session_id or ""):
        return False
    db = _connect()
    try:
        row = db.execute("SELECT * FROM sshx_sessions WHERE id=?", (session_id,)).fetchone()
        if not row:
            return False
        if not trusted and not is_admin and row["user_id"] != user_id:
            log_event("revoke_denied", session_id=session_id, user_id=user_id,
                      actor_id=actor_id, ip="", db=db)
            return False
        if row["status"] in ("revoked", "expired", "failed"):
            # Still make sure cleanup happened (e.g. after a panel restart).
            _cleanup_session(session_id, row["container_id"], row["pid"])
            return True

        status = "expired" if reason == "expired" else "revoked"
        db.execute("UPDATE sshx_sessions SET status=?,closed_at=? WHERE id=?",
                   (status, int(time.time()), session_id))
        db.commit()
        log_event("session_revoked" if status == "revoked" else "session_expired",
                  session_id=session_id, user_id=row["user_id"], vps_id=row["vps_id"],
                  actor_id=actor_id, reason=reason, db=db)
        _cleanup_session(session_id, row["container_id"], row["pid"])
        return True
    finally:
        db.close()


def _cleanup_session(session_id: str, cid: str | None, pid: int | None) -> None:
    _terminate_pid(pid)
    if cid and CONTAINER_ID_RE.match(cid):
        try:
            _remove_authorized_key(cid, session_id)
        except Exception:
            pass
    try:
        import shutil
        shutil.rmtree(_session_dir(session_id), ignore_errors=True)
    except Exception:
        pass


def expire_stale_sessions() -> int:
    """Expire TTL/idle sessions, reap dead processes, recheck authorization."""
    now = int(time.time())
    idle_cutoff = now - max(60, IDLE_TIMEOUT_SECONDS)
    db = _connect()
    expired: list[tuple[str, str, int | None, str]] = []
    dead: list[str] = []
    try:
        for row in db.execute(
            "SELECT id,container_id,pid FROM sshx_sessions"
            " WHERE status IN ('starting','active') AND expires_at<=?", (now,)
        ):
            expired.append((row["id"], row["container_id"], row["pid"], "ttl"))
        for row in db.execute(
            "SELECT id,container_id,pid FROM sshx_sessions"
            " WHERE status IN ('starting','active') AND expires_at>?"
            " AND COALESCE(last_seen,created_at)<?", (now, idle_cutoff)
        ):
            expired.append((row["id"], row["container_id"], row["pid"], "idle timeout"))
        already_closed = {item[0] for item in expired}
        for row in db.execute(
            "SELECT id,pid FROM sshx_sessions WHERE status IN ('starting','active')"
            " AND pid IS NOT NULL AND expires_at>?", (now,)
        ):
            # A session already scheduled for TTL/idle expiry must not be
            # overwritten as 'failed' just because its gateway also exited.
            if row["id"] in already_closed:
                continue
            try:
                os.kill(row["pid"], 0)
            except OSError:
                dead.append(row["id"])
        for sid, _, _, reason in expired:
            db.execute(
                "UPDATE sshx_sessions SET status='expired',closed_at=? WHERE id=?",
                (now, sid),
            )
            log_event("session_expired", session_id=sid, reason=reason, db=db)
        for sid in dead:
            db.execute(
                "UPDATE sshx_sessions SET status='failed',closed_at=? WHERE id=?",
                (now, sid),
            )
            log_event("session_gone", session_id=sid, reason="process exited", db=db)
        db.commit()
    finally:
        db.close()
    for sid, cid, pid, reason in expired:
        _cleanup_session(sid, cid, pid)
    for sid in dead:
        _cleanup_session(sid, "", None)
    return len(expired)


def _sweeper_loop() -> None:
    while True:
        try:
            expire_stale_sessions()
            enforce_live_authorizations()
            shutdown_orphaned_processes()
        except Exception as exc:
            print(f"[sshx] sweeper error: {type(exc).__name__}")
        time.sleep(20)


def shutdown_orphaned_processes() -> None:
    """Defense in depth: no gateway may run without an authorized DB session."""
    db = _connect()
    try:
        live = {r["id"] for r in db.execute(
            "SELECT id FROM sshx_sessions WHERE status IN ('starting','active')"
        ).fetchall()}
    finally:
        db.close()
    try:
        names = os.listdir(SESSION_ROOT)
    except OSError:
        return
    for name in names:
        if not SESSION_ID_RE.match(name) or name in live:
            continue
        # A directory without an active session is leftover state: scrub it.
        _cleanup_session(name, "", None)


def start_sweeper() -> None:
    global _sweeper_started
    with _lock:
        if _sweeper_started:
            return
        _sweeper_started = True
    t = threading.Thread(target=_sweeper_loop, name="sshx-sweeper", daemon=True)
    t.start()


def shutdown_all_sessions(reason: str = "panel restart") -> None:
    """Called at boot/shutdown: no session may survive a panel restart."""
    db = _connect()
    try:
        rows = db.execute(
            "SELECT id,container_id,pid FROM sshx_sessions WHERE status IN ('starting','active')"
        ).fetchall()
        db.execute("UPDATE sshx_sessions SET status='expired',closed_at=? "
                   "WHERE status IN ('starting','active')", (int(time.time()),))
        db.commit()
    finally:
        db.close()
    for row in rows:
        log_event("session_expired", session_id=row["id"], reason=reason)
        _cleanup_session(row["id"], row["container_id"], row["pid"])


def security_stats() -> dict:
    db = _connect()
    try:
        def count(sql: str, args: tuple = ()) -> int:
            return int(db.execute(sql, args).fetchone()[0])
        now = int(time.time())
        return {
            "active": count("SELECT COUNT(*) FROM sshx_sessions WHERE status IN ('starting','active') AND expires_at>?", (now,)),
            "expired": count("SELECT COUNT(*) FROM sshx_sessions WHERE status='expired'"),
            "revoked": count("SELECT COUNT(*) FROM sshx_sessions WHERE status='revoked'"),
            "failed": count("SELECT COUNT(*) FROM sshx_sessions WHERE status='failed'"),
            "denied": count("SELECT COUNT(*) FROM sshx_events WHERE action IN ('auth_deny','revoke_denied')"),
            "global_enabled": is_globally_enabled(),
            "contained": is_contained(),
            "idle_timeout": IDLE_TIMEOUT_SECONDS,
        }
    finally:
        db.close()
