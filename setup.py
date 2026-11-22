"""
DeupGaming Free Panel — first-run setup.

Creates the database schema, the admin account and the per-VPS limits.

Modes:
  python3 setup.py                       interactive first-run wizard
  python3 setup.py --auto                fully automatic (env vars / defaults)
  python3 setup.py --ensure              create only what is missing (no prompts)
  python3 setup.py --reset-pass U P      set a new password for user U

Environment:
  PANEL_USER, PANEL_PASS, VPS_CPU, VPS_RAM, VPS_DISK
"""
import os
import sqlite3
import sys
import time
import getpass
import secrets

from werkzeug.security import generate_password_hash

DB = os.environ.get("PANEL_DB", "panel.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    signup_ip TEXT NOT NULL,
    is_admin INTEGER DEFAULT 0,
    created_at INTEGER NOT NULL,
    recovery_code_hash TEXT,
    recovery_code_shown INTEGER DEFAULT 0,
    youtube_verified INTEGER DEFAULT 0,
    is_vpn_signup INTEGER DEFAULT 0,
    vpn_provider TEXT
);
CREATE TABLE IF NOT EXISTS vps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    container_id TEXT NOT NULL,
    ssh_command TEXT,
    status TEXT DEFAULT 'creating',
    creator_ip TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_regen INTEGER DEFAULT 0,
    kvm_enabled INTEGER DEFAULT 0,
    node_id INTEGER DEFAULT 0,
    FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS nat_rules (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    vps_id       INTEGER NOT NULL UNIQUE,
    container_id TEXT NOT NULL,
    container_ip TEXT NOT NULL,
    ssh_port     INTEGER NOT NULL UNIQUE,
    extra_ports  TEXT NOT NULL DEFAULT '',
    created_at   INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    stars INTEGER NOT NULL,
    comment TEXT,
    created_at INTEGER NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS broadcast (
    id INTEGER PRIMARY KEY CHECK (id=1),
    message TEXT, active INTEGER DEFAULT 0, updated_at INTEGER
);
CREATE TABLE IF NOT EXISTS panel_config (
    key TEXT PRIMARY KEY, value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS discord_config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS discord_links (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL UNIQUE,
    discord_id TEXT NOT NULL UNIQUE,
    discord_username TEXT,
    discord_discriminator TEXT,
    discord_avatar TEXT,
    oauth_token_encrypted TEXT,
    oauth_refresh_token_encrypted TEXT,
    oauth_expires_at INTEGER DEFAULT 0,
    linked_at INTEGER NOT NULL,
    last_verified_at INTEGER DEFAULT 0,
    status TEXT DEFAULT 'linked',
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS discord_membership (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    server_type TEXT NOT NULL,
    server_id TEXT NOT NULL,
    slot_number INTEGER DEFAULT 0,
    is_member INTEGER DEFAULT 0,
    last_checked_at INTEGER DEFAULT 0,
    check_count INTEGER DEFAULT 0,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(user_id, server_type, server_id)
);
CREATE TABLE IF NOT EXISTS discord_promotion_slots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    slot_number INTEGER NOT NULL UNIQUE,
    enabled INTEGER DEFAULT 0,
    server_name TEXT DEFAULT '',
    server_id TEXT DEFAULT '',
    invite_url TEXT DEFAULT '',
    last_check_at INTEGER DEFAULT 0,
    last_check_status TEXT DEFAULT 'unknown',
    verified_user_count INTEGER DEFAULT 0,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS discord_verification_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    server_type TEXT,
    server_id TEXT,
    status TEXT NOT NULL,
    details TEXT,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS discord_membership_suspensions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    vps_id INTEGER NOT NULL,
    server_type TEXT NOT NULL,
    server_id TEXT NOT NULL,
    server_name TEXT,
    reason TEXT NOT NULL,
    suspended_at INTEGER NOT NULL,
    restored_at INTEGER DEFAULT 0,
    is_active INTEGER DEFAULT 1,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(vps_id) REFERENCES vps(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS discord_audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    admin_id INTEGER,
    action TEXT NOT NULL,
    target_user_id INTEGER,
    target_server_id TEXT,
    details TEXT,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS youtube_config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS youtube_links (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL UNIQUE,
    google_id TEXT NOT NULL,
    google_email TEXT,
    google_name TEXT,
    google_avatar TEXT,
    channel_id TEXT,
    channel_title TEXT,
    oauth_token_encrypted TEXT,
    oauth_refresh_token_encrypted TEXT,
    oauth_expires_at INTEGER DEFAULT 0,
    linked_at INTEGER NOT NULL,
    last_verified_at INTEGER DEFAULT 0,
    status TEXT DEFAULT 'linked',
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS youtube_subscription_status (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    channel_id TEXT NOT NULL,
    channel_title TEXT,
    is_subscribed INTEGER DEFAULT 0,
    last_checked_at INTEGER DEFAULT 0,
    check_count INTEGER DEFAULT 0,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(user_id, channel_id)
);
CREATE TABLE IF NOT EXISTS youtube_verification_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    status TEXT NOT NULL,
    details TEXT,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS youtube_subscription_suspensions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    vps_id INTEGER NOT NULL,
    channel_id TEXT NOT NULL,
    channel_title TEXT,
    reason TEXT NOT NULL,
    suspended_at INTEGER NOT NULL,
    restored_at INTEGER DEFAULT 0,
    is_active INTEGER DEFAULT 1,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(vps_id) REFERENCES vps(id) ON DELETE CASCADE
);
"""


def gen_password(length: int = 16) -> str:
    alphabet = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def parse(argv):
    """Tiny flag parser: --auto --ensure --user X --pass Y --cpu N ..."""
    opts = {
        "mode": "interactive",
        "user": os.environ.get("PANEL_USER", ""),
        "pass": os.environ.get("PANEL_PASS", ""),
        "cpu": os.environ.get("VPS_CPU", ""),
        "ram": os.environ.get("VPS_RAM", ""),
        "disk": os.environ.get("VPS_DISK", ""),
        "reset_user": "",
        "reset_pass": "",
        "no_admin": False,
    }
    i = 0
    while i < len(argv):
        a = argv[i]
        nxt = argv[i + 1] if i + 1 < len(argv) else ""
        if a == "--auto":
            opts["mode"] = "auto"
        elif a == "--ensure":
            opts["mode"] = "ensure"
        elif a == "--interactive":
            opts["mode"] = "interactive"
        elif a == "--no-admin":
            opts["no_admin"] = True
        elif a in ("--user", "--username"):
            opts["user"] = nxt
            i += 1
        elif a in ("--pass", "--password"):
            opts["pass"] = nxt
            i += 1
        elif a == "--cpu":
            opts["cpu"] = nxt
            i += 1
        elif a == "--ram":
            opts["ram"] = nxt
            i += 1
        elif a == "--disk":
            opts["disk"] = nxt
            i += 1
        elif a == "--reset-pass":
            opts["mode"] = "reset"
            opts["reset_user"] = nxt
            opts["reset_pass"] = argv[i + 2] if i + 2 < len(argv) else ""
            i += 2
        i += 1
    return opts


def init_schema(con):
    con.executescript(SCHEMA)
    con.execute("INSERT OR IGNORE INTO broadcast(id,message,active,updated_at) VALUES(1,'',0,0)")
    con.commit()


def ask_int(prompt, default, lo, hi):
    while True:
        raw = input(f"  {prompt} [{default}]: ").strip()
        if not raw:
            return default
        try:
            v = int(raw)
            if lo <= v <= hi:
                return v
            print(f"    Must be {lo}-{hi}")
        except ValueError:
            print("    Enter a number")


def clamp(raw, default, lo, hi):
    try:
        v = int(raw)
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, v))


def create_admin(con, opts):
    cur = con.execute("SELECT COUNT(*) FROM users WHERE is_admin=1")
    if cur.fetchone()[0] > 0:
        if opts["mode"] == "interactive":
            print("\n  Admin already exists — skipping.")
        return False

    mode = opts["mode"]

    if mode == "interactive":
        print("\n+--------------------------------------+")
        print("|   DeupGaming Free Panel - First Run  |")
        print("+--------------------------------------+\n")
        username = opts["user"].strip()
        while not username:
            username = input("  Admin username: ").strip()
        password = opts["pass"]
        if not password:
            password = getpass.getpass("  Admin password: ")
            while len(password) < 6:
                password = getpass.getpass("  Min 6 chars: ")
    else:
        username = (opts["user"] or "admin").strip()
        password = opts["pass"]
        if not password:
            password = gen_password()
            print(f"\n  Generated admin password: {password}")

    con.execute(
        "INSERT INTO users(username,password,signup_ip,is_admin,created_at,recovery_code_shown)"
        " VALUES(?,?,?,1,?,1)",
        (username, generate_password_hash(password), "127.0.0.1", int(time.time())),
    )
    con.commit()
    print(f"\n  OK Admin '{username}' created.")
    return True


def set_limits(con, opts):
    existing = {r[0]: r[1] for r in con.execute("SELECT key,value FROM panel_config").fetchall()}
    keys = ["vps_cpu_cores", "vps_ram_gb", "vps_disk_gb"]
    if all(k in existing for k in keys):
        print(
            "  Limits: {} vCPU / {}GB RAM / {}GB disk".format(
                existing["vps_cpu_cores"], existing["vps_ram_gb"], existing["vps_disk_gb"]
            )
        )
        return

    if opts["mode"] == "interactive":
        print("\n[ Per-VPS Resource Limits ]")
        cpu = ask_int("CPU cores (1-32)", 4, 1, 32)
        ram = ask_int("RAM GB (1-256)", 4, 1, 256)
        disk = ask_int("Disk GB (5-2000)", 80, 5, 2000)
    else:
        cpu = clamp(opts["cpu"], 4, 1, 32)
        ram = clamp(opts["ram"], 4, 1, 256)
        disk = clamp(opts["disk"], 80, 5, 2000)

    for k, v in [("vps_cpu_cores", str(cpu)), ("vps_ram_gb", str(ram)), ("vps_disk_gb", str(disk))]:
        con.execute(
            "INSERT INTO panel_config(key,value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (k, v),
        )
    con.commit()
    print(f"  OK Each VPS: {cpu} vCPU / {ram}GB RAM / {disk}GB disk")


def reset_password(con, user, password):
    row = con.execute("SELECT id FROM users WHERE username=?", (user,)).fetchone()
    if not row:
        print(f"  ERROR User '{user}' not found")
        return 1
    if not password:
        password = gen_password()
    con.execute(
        "UPDATE users SET password=? WHERE id=?",
        (generate_password_hash(password), row[0]),
    )
    con.commit()
    print(f"  OK Password updated for '{user}': {password}")
    return 0


def init():
    opts = parse(sys.argv[1:])
    con = sqlite3.connect(DB)
    try:
        init_schema(con)

        if opts["mode"] == "reset":
            return reset_password(
                con, opts["reset_user"] or "admin", opts["reset_pass"]
            )

        if not opts["no_admin"]:
            create_admin(con, opts)
        set_limits(con, opts)

        if opts["mode"] != "interactive":
            print("\n  Setup complete.")
        else:
            print("\n  Setup complete. Start the panel with: bash install.sh --start")
        return 0
    finally:
        con.close()


if __name__ == "__main__":
    sys.exit(init())
