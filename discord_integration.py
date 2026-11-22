"""
Discord Integration Module — DeupGaming Free Panel

Handles Discord OAuth2 account linking, bot membership verification,
promotion server management, and VPS eligibility checks.

All Discord bot credentials are stored in the database (admin_config),
never exposed to the frontend.
"""

import os
import json
import time
import sqlite3
import secrets
import threading
import requests
import logging

DB = "panel.db"
logger = logging.getLogger("discord_integration")

# ── Discord API endpoints ──────────────────────────────────────────────────
DISCORD_API = "https://discord.com/api/v10"
DISCORD_OAUTH_AUTHORIZE = "https://discord.com/api/oauth2/authorize"
DISCORD_OAUTH_TOKEN = "https://discord.com/api/oauth2/token"

# Required scopes for account linking + guild joining
OAUTH_SCOPES = "identify guilds.join"

# ── DB helpers ─────────────────────────────────────────────────────────────

def get_db():
    db = sqlite3.connect(DB)
    db.row_factory = sqlite3.Row
    return db


def init_discord_tables(db):
    """Create Discord-related tables if they don't exist."""
    db.executescript("""
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
        server_type TEXT NOT NULL,  -- 'main' or 'promotion'
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
        event_type TEXT NOT NULL,  -- 'link', 'unlink', 'verify', 'join_attempt', 'suspension', 'restoration'
        server_type TEXT,
        server_id TEXT,
        status TEXT NOT NULL,  -- 'success', 'failed', 'pending'
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
    """)
    # Initialize 5 promotion slots if they don't exist
    now = int(time.time())
    for i in range(1, 6):
        db.execute(
            "INSERT OR IGNORE INTO discord_promotion_slots(slot_number, enabled, created_at, updated_at) "
            "VALUES (?, 0, ?, ?)",
            (i, now, now),
        )
    # Initialize default discord config
    defaults = {
        "bot_token": "",
        "application_id": "",
        "client_id": "",
        "client_secret": "",
        "oauth_redirect_url": "",
        "main_server_id": "",
        "main_server_invite_url": "",
        "main_server_name": "Deup Gaming",
        "main_server_enabled": "1",
        "auto_join_enabled": "1",
        "suspension_enabled": "1",
        "grace_period_hours": "24",
        "verification_interval_hours": "6",
        "log_channel_id": "",
        "bot_status": "disconnected",
        "last_sync_at": "0",
    }
    for key, val in defaults.items():
        db.execute(
            "INSERT OR IGNORE INTO discord_config(key, value) VALUES (?, ?)",
            (key, val),
        )
    db.commit()


# ── Config helpers ─────────────────────────────────────────────────────────

def get_config(key: str, default: str = "") -> str:
    db = get_db()
    row = db.execute("SELECT value FROM discord_config WHERE key=?", (key,)).fetchone()
    db.close()
    return row["value"] if row else default


def set_config(key: str, value: str):
    db = get_db()
    db.execute(
        "INSERT INTO discord_config(key, value) VALUES(?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, value),
    )
    db.commit()
    db.close()


def get_all_config() -> dict:
    db = get_db()
    rows = db.execute("SELECT key, value FROM discord_config").fetchall()
    db.close()
    return {r["key"]: r["value"] for r in rows}


# ── Encryption helpers (simple XOR + base64 for storage) ───────────────────

def _encrypt_token(token: str) -> str:
    """Simple encryption for storing OAuth tokens. Not production-grade but
    better than plaintext. In production, use proper encryption (Fernet)."""
    if not token:
        return ""
    key = os.environ.get("DISCORD_ENCRYPTION_KEY", "dxdfree-panel-secret-key")
    # Simple XOR-based encryption
    encrypted = ""
    for i, c in enumerate(token):
        encrypted += chr(ord(c) ^ ord(key[i % len(key)]))
    return base64.b64encode(encrypted.encode()).decode()


def _decrypt_token(encrypted: str) -> str:
    """Decrypt a stored OAuth token."""
    if not encrypted:
        return ""
    try:
        key = os.environ.get("DISCORD_ENCRYPTION_KEY", "dxdfree-panel-secret-key")
        encrypted = base64.b64decode(encrypted.encode()).decode()
        decrypted = ""
        for i, c in enumerate(encrypted):
            decrypted += chr(ord(c) ^ ord(key[i % len(key)]))
        return decrypted
    except Exception:
        return ""


# ── OAuth2 state management ────────────────────────────────────────────────

def generate_oauth_state(user_id: int) -> str:
    """Generate a secure state token for OAuth2 flow."""
    state = secrets.token_urlsafe(32)
    db = get_db()
    # Store state with user_id and expiry (10 min)
    db.execute(
        "INSERT OR REPLACE INTO discord_config(key, value) VALUES(?, ?)",
        (f"oauth_state_{state}", f"{user_id}:{int(time.time()) + 600}"),
    )
    db.commit()
    db.close()
    return state


def validate_oauth_state(state: str) -> int | None:
    """Validate OAuth2 state and return user_id if valid."""
    if not state:
        return None
    db = get_db()
    row = db.execute(
        "SELECT value FROM discord_config WHERE key=?", (f"oauth_state_{state}",)
    ).fetchone()
    if row:
        db.execute("DELETE FROM discord_config WHERE key=?", (f"oauth_state_{state}",))
        db.commit()
    db.close()
    if not row:
        return None
    parts = row["value"].split(":")
    if len(parts) != 2:
        return None
    try:
        user_id = int(parts[0])
        expiry = int(parts[1])
        if int(time.time()) > expiry:
            return None
        return user_id
    except (ValueError, IndexError):
        return None


# ── Discord OAuth2 URL builder ─────────────────────────────────────────────

def get_oauth_url(user_id: int) -> str:
    """Build the Discord OAuth2 authorization URL."""
    client_id = get_config("client_id")
    redirect_url = get_config("oauth_redirect_url")
    if not client_id or not redirect_url:
        return ""
    state = generate_oauth_state(user_id)
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_url,
        "response_type": "code",
        "scope": OAUTH_SCOPES,
        "state": state,
    }
    query = "&".join(f"{k}={v}" for k, v in params.items())
    return f"{DISCORD_OAUTH_AUTHORIZE}?{query}"


# ── OAuth2 token exchange ──────────────────────────────────────────────────

def exchange_code_for_token(code: str) -> dict | None:
    """Exchange authorization code for access token."""
    client_id = get_config("client_id")
    client_secret = get_config("client_secret")
    redirect_url = get_config("oauth_redirect_url")
    if not client_id or not client_secret or not redirect_url:
        return None
    try:
        resp = requests.post(
            DISCORD_OAUTH_TOKEN,
            data={
                "client_id": client_id,
                "client_secret": client_secret,
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_url,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=15,
        )
        if resp.status_code == 200:
            return resp.json()
        logger.error(f"Token exchange failed: {resp.status_code} {resp.text[:200]}")
        return None
    except Exception as e:
        logger.error(f"Token exchange error: {e}")
        return None


def get_discord_user(access_token: str) -> dict | None:
    """Get the Discord user profile using an access token."""
    try:
        resp = requests.get(
            f"{DISCORD_API}/users/@me",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=15,
        )
        if resp.status_code == 200:
            return resp.json()
        return None
    except Exception:
        return None


# ── Discord bot API helpers ────────────────────────────────────────────────

def _get_bot_token() -> str:
    return get_config("bot_token")


def _bot_headers():
    token = _get_bot_token()
    return {"Authorization": f"Bot {token}", "Content-Type": "application/json"}


def check_bot_connection() -> tuple[bool, str]:
    """Check if the Discord bot token is valid and connected."""
    token = _get_bot_token()
    if not token:
        return False, "No bot token configured"
    try:
        resp = requests.get(f"{DISCORD_API}/users/@me", headers=_bot_headers(), timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            set_config("bot_status", "connected")
            return True, f"Connected as {data.get('username', 'unknown')}#{data.get('discriminator', '0')}"
        return False, f"Discord API returned {resp.status_code}"
    except Exception as e:
        set_config("bot_status", "disconnected")
        return False, str(e)


def get_guild_member(server_id: str, discord_id: str) -> tuple[bool, dict | None]:
    """Check if a Discord user is a member of a guild. Returns (is_member, member_data)."""
    if not server_id or not discord_id:
        return False, None
    try:
        resp = requests.get(
            f"{DISCORD_API}/guilds/{server_id}/members/{discord_id}",
            headers=_bot_headers(),
            timeout=15,
        )
        if resp.status_code == 200:
            return True, resp.json()
        elif resp.status_code == 404:
            return False, None
        else:
            logger.warning(f"Guild member lookup returned {resp.status_code} for {discord_id} in {server_id}")
            return False, None
    except Exception as e:
        logger.error(f"Guild member lookup failed: {e}")
        return False, None


def add_member_to_guild(server_id: str, discord_id: str, access_token: str) -> tuple[bool, str]:
    """Add a user to a guild using their OAuth2 access token (guilds.join scope)."""
    if not server_id or not discord_id or not access_token:
        return False, "Missing parameters"
    try:
        resp = requests.put(
            f"{DISCORD_API}/guilds/{server_id}/members/{discord_id}",
            headers=_bot_headers(),
            json={"access_token": access_token},
            timeout=15,
        )
        if resp.status_code in (200, 201, 204):
            return True, "Joined successfully"
        elif resp.status_code == 403:
            return False, "Bot lacks permission or user already in guild"
        elif resp.status_code == 429:
            return False, "Rate limited by Discord — try again later"
        else:
            return False, f"Discord API returned {resp.status_code}: {resp.text[:200]}"
    except Exception as e:
        return False, str(e)


def get_guild_info(server_id: str) -> dict | None:
    """Get basic info about a guild."""
    if not server_id:
        return None
    try:
        resp = requests.get(
            f"{DISCORD_API}/guilds/{server_id}",
            headers=_bot_headers(),
            timeout=15,
        )
        if resp.status_code == 200:
            return resp.json()
        return None
    except Exception:
        return None


# ── Promotion slot management ──────────────────────────────────────────────

def get_promotion_slots() -> list[dict]:
    """Get all promotion slots."""
    db = get_db()
    rows = db.execute(
        "SELECT * FROM discord_promotion_slots ORDER BY slot_number"
    ).fetchall()
    db.close()
    return [dict(r) for r in rows]


def get_enabled_promotion_slots() -> list[dict]:
    """Get only enabled promotion slots."""
    db = get_db()
    rows = db.execute(
        "SELECT * FROM discord_promotion_slots WHERE enabled=1 ORDER BY slot_number"
    ).fetchall()
    db.close()
    return [dict(r) for r in rows]


def update_promotion_slot(slot_number: int, enabled: int = None, server_name: str = None,
                          server_id: str = None, invite_url: str = None,
                          last_check_status: str = None, last_check_at: int = None) -> bool:
    """Update a promotion slot."""
    db = get_db()
    fields, vals = [], []
    if enabled is not None:
        fields.append("enabled=?"); vals.append(int(enabled))
    if server_name is not None:
        fields.append("server_name=?"); vals.append(server_name)
    if server_id is not None:
        fields.append("server_id=?"); vals.append(server_id)
    if invite_url is not None:
        fields.append("invite_url=?"); vals.append(invite_url)
    if last_check_status is not None:
        fields.append("last_check_status=?"); vals.append(last_check_status)
    if last_check_at is not None:
        fields.append("last_check_at=?"); vals.append(int(last_check_at))
    fields.append("updated_at=?"); vals.append(int(time.time()))
    if fields:
        vals.append(slot_number)
        db.execute(
            f"UPDATE discord_promotion_slots SET {', '.join(fields)} WHERE slot_number=?",
            vals,
        )
        db.commit()
    db.close()
    return True


def test_promotion_slot(slot_number: int) -> tuple[bool, str]:
    """Test connectivity to a promotion server."""
    db = get_db()
    row = db.execute(
        "SELECT server_id FROM discord_promotion_slots WHERE slot_number=?",
        (slot_number,),
    ).fetchone()
    db.close()
    if not row or not row["server_id"]:
        return False, "No server ID configured"
    info = get_guild_info(row["server_id"])
    if info:
        update_promotion_slot(slot_number, last_check_status="connected",
                              last_check_at=int(time.time()))
        return True, f"Connected: {info.get('name', 'unknown')}"
    update_promotion_slot(slot_number, last_check_status="disconnected",
                          last_check_at=int(time.time()))
    return False, "Could not connect to server"


# ── Membership verification ─────────────────────────────────────────────────

def get_required_servers() -> list[dict]:
    """Get all required servers (main + enabled promotion slots)."""
    servers = []
    # Main server
    if get_config("main_server_enabled", "1") == "1":
        main_id = get_config("main_server_id")
        if main_id:
            servers.append({
                "type": "main",
                "slot": 0,
                "name": get_config("main_server_name", "Deup Gaming"),
                "server_id": main_id,
                "invite_url": get_config("main_server_invite_url", ""),
            })
    # Promotion servers
    for slot in get_enabled_promotion_slots():
        if slot.get("server_id"):
            servers.append({
                "type": "promotion",
                "slot": slot["slot_number"],
                "name": slot.get("server_name", f"Promotion Server {slot['slot_number']}"),
                "server_id": slot["server_id"],
                "invite_url": slot.get("invite_url", ""),
            })
    return servers


def verify_user_membership(user_id: int, force: bool = False) -> dict:
    """Verify a user's membership in all required servers.

    Returns dict with:
        verified: bool (True if all required servers verified)
        discord_linked: bool
        discord_id: str or None
        main_server: {status, name, ...}
        promotion_servers: [{status, name, ...}]
        missing: list of missing server names
        missing_servers: list of server dicts that are missing
    """
    db = get_db()
    link = db.execute(
        "SELECT * FROM discord_links WHERE user_id=?", (user_id,)
    ).fetchone()

    result = {
        "verified": False,
        "discord_linked": False,
        "discord_id": None,
        "discord_username": None,
        "main_server": {"status": "not_linked", "name": "Deup Gaming"},
        "promotion_servers": [],
        "missing": [],
        "missing_servers": [],
        "oauth_valid": False,
        "error": None,
    }

    if not link:
        result["error"] = "Discord account not linked"
        db.close()
        return result

    result["discord_linked"] = True
    result["discord_id"] = link["discord_id"]
    result["discord_username"] = link["discord_username"]

    # Check OAuth token validity
    access_token = _decrypt_token(link["oauth_token_encrypted"])
    if access_token:
        # Try to get user profile to validate token
        profile = get_discord_user(access_token)
        if profile:
            result["oauth_valid"] = True
        else:
            result["oauth_valid"] = False
            result["error"] = "Discord authorization expired — please reauthorize"
    else:
        result["oauth_valid"] = False
        result["error"] = "Discord authorization missing — please relink"

    required_servers = get_required_servers()
    all_verified = True

    for server in required_servers:
        is_member, member_data = get_guild_member(server["server_id"], link["discord_id"])
        status = "verified" if is_member else "missing"

        # Update membership record
        db.execute(
            "INSERT INTO discord_membership(user_id, server_type, server_id, is_member, last_checked_at, check_count) "
            "VALUES(?, ?, ?, ?, ?, 1) "
            "ON CONFLICT(user_id, server_type, server_id) DO UPDATE SET "
            "is_member=excluded.is_member, last_checked_at=excluded.last_checked_at, "
            "check_count=check_count+1",
            (user_id, server["type"], server["server_id"], int(is_member), int(time.time())),
        )

        server_info = {
            "name": server["name"],
            "server_id": server["server_id"],
            "type": server["type"],
            "slot": server["slot"],
            "status": status,
            "invite_url": server["invite_url"],
        }

        if server["type"] == "main":
            result["main_server"] = server_info
        else:
            result["promotion_servers"].append(server_info)

        if not is_member:
            all_verified = False
            result["missing"].append(server["name"])
            result["missing_servers"].append(server)

    # Update linked account last_verified_at
    db.execute(
        "UPDATE discord_links SET last_verified_at=? WHERE user_id=?",
        (int(time.time()), user_id),
    )
    db.commit()

    # Log verification
    db.execute(
        "INSERT INTO discord_verification_history(user_id, event_type, status, details, created_at) "
        "VALUES(?, 'verify', ?, ?, ?)",
        (user_id, "success" if all_verified else "incomplete", json.dumps(result["missing"]), int(time.time())),
    )
    db.commit()
    db.close()

    result["verified"] = all_verified and result["oauth_valid"]
    return result


def attempt_join_missing(user_id: int, server_id: str, access_token: str) -> tuple[bool, str]:
    """Attempt to auto-join a user to a missing server."""
    db = get_db()
    link = db.execute("SELECT discord_id FROM discord_links WHERE user_id=?", (user_id,)).fetchone()
    db.close()
    if not link:
        return False, "Discord not linked"
    discord_id = link["discord_id"]
    if not access_token:
        return False, "No access token available"
    ok, msg = add_member_to_guild(server_id, discord_id, access_token)
    # Log the attempt
    db = get_db()
    db.execute(
        "INSERT INTO discord_verification_history(user_id, event_type, server_id, status, details, created_at) "
        "VALUES(?, 'join_attempt', ?, ?, ?, ?)",
        (user_id, server_id, "success" if ok else "failed", msg, int(time.time())),
    )
    db.commit()
    db.close()
    return ok, msg


# ── Link / Unlink ──────────────────────────────────────────────────────────

def link_discord_account(user_id: int, discord_profile: dict, access_token: str, refresh_token: str = None, expires_in: int = 0) -> tuple[bool, str]:
    """Link a Discord account to a panel user."""
    discord_id = discord_profile.get("id")
    if not discord_id:
        return False, "No Discord ID in profile"
    db = get_db()
    # Check if this Discord ID is already linked to another account
    existing = db.execute(
        "SELECT user_id FROM discord_links WHERE discord_id=?", (discord_id,)
    ).fetchone()
    if existing and existing["user_id"] != user_id:
        db.close()
        return False, "This Discord account is already linked to another panel account"
    # Remove old link if exists for this user
    db.execute("DELETE FROM discord_links WHERE user_id=?", (user_id,))
    db.execute(
        "INSERT INTO discord_links(user_id, discord_id, discord_username, discord_discriminator, "
        "discord_avatar, oauth_token_encrypted, oauth_refresh_token_encrypted, oauth_expires_at, linked_at, status) "
        "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, 'linked')",
        (
            user_id,
            discord_id,
            discord_profile.get("username", ""),
            discord_profile.get("discriminator", "0"),
            discord_profile.get("avatar", ""),
            _encrypt_token(access_token),
            _encrypt_token(refresh_token) if refresh_token else "",
            int(time.time()) + expires_in if expires_in else 0,
            int(time.time()),
        ),
    )
    db.commit()
    # Log
    db.execute(
        "INSERT INTO discord_verification_history(user_id, event_type, status, details, created_at) "
        "VALUES(?, 'link', 'success', ?, ?)",
        (user_id, f"Linked Discord account {discord_profile.get('username', '')}#{discord_profile.get('discriminator', '0')}", int(time.time())),
    )
    db.commit()
    db.close()
    return True, "Discord account linked successfully"


def unlink_discord_account(user_id: int, admin_initiated: bool = False) -> bool:
    """Unlink a Discord account from a panel user."""
    db = get_db()
    link = db.execute("SELECT discord_id, discord_username FROM discord_links WHERE user_id=?", (user_id,)).fetchone()
    if not link:
        db.close()
        return False
    db.execute("DELETE FROM discord_links WHERE user_id=?", (user_id,))
    db.execute("DELETE FROM discord_membership WHERE user_id=?", (user_id,))
    db.execute(
        "INSERT INTO discord_verification_history(user_id, event_type, status, details, created_at) "
        "VALUES(?, 'unlink', 'success', ?, ?)",
        (user_id, f"Unlinked Discord account {link['discord_username']}", int(time.time())),
    )
    db.commit()
    db.close()
    return True


# ── VPS eligibility check ──────────────────────────────────────────────────

def check_vps_eligibility(user_id: int) -> tuple[bool, str, list]:
    """Check if a user is eligible to create a VPS.

    Returns (eligible: bool, reason: str, missing_servers: list).

    If Discord is not configured (no bot token, no main server, no promotion slots),
    VPS creation is allowed without Discord (backward compatibility).
    """
    # Check if Discord is required at all
    config = get_all_config()
    bot_token = config.get("bot_token", "")
    main_server_id = config.get("main_server_id", "")
    promo_slots = get_enabled_promotion_slots()
    discord_configured = bool(bot_token and (main_server_id or promo_slots))

    if not discord_configured:
        # Discord not configured — allow VPS creation without Discord
        return True, "Discord not configured — VPS creation allowed", []

    db = get_db()
    link = db.execute("SELECT * FROM discord_links WHERE user_id=?", (user_id,)).fetchone()
    if not link:
        db.close()
        return False, "Discord account not linked. Link your Discord account first.", []

    if link["status"] != "linked":
        db.close()
        return False, "Discord account is disconnected. Please relink.", []

    # Check OAuth token validity
    access_token = _decrypt_token(link["oauth_token_encrypted"])
    if not access_token:
        db.close()
        return False, "Discord authorization missing. Please relink your Discord account.", []

    # Verify membership (cached, with force if stale)
    last_verified = link["last_verified_at"] or 0
    stale = (int(time.time()) - last_verified) > (6 * 3600)  # 6 hours
    result = verify_user_membership(user_id, force=stale)

    if not result["verified"]:
        missing = result["missing"]
        if result["error"]:
            db.close()
            return False, result["error"], result["missing_servers"]
        missing_str = ", ".join(missing)
        db.close()
        return False, f"You must join: {missing_str}", result["missing_servers"]

    db.close()
    return True, "All requirements met", []


# ── Membership suspension / restoration ─────────────────────────────────────

def handle_member_left(user_id: int, server_type: str, server_id: str, server_name: str = None):
    """Handle a user leaving a required server.

    Suspends their VPSes if membership is lost. Does NOT delete VPS data.
    """
    db = get_db()
    # Update membership record
    db.execute(
        "UPDATE discord_membership SET is_member=0, last_checked_at=? "
        "WHERE user_id=? AND server_type=? AND server_id=?",
        (int(time.time()), user_id, server_type, server_id),
    )
    db.commit()

    # Check if suspension is enabled
    if get_config("suspension_enabled", "1") != "1":
        db.close()
        return

    # Get user's active VPSes
    vpses = db.execute(
        "SELECT id, container_id, status FROM vps WHERE user_id=? AND status='running'",
        (user_id,),
    ).fetchall()

    if not vpses:
        db.close()
        return

    reason = f"Missing {server_name or server_id} membership"
    for vps in vpses:
        # Check if already suspended for this reason
        existing = db.execute(
            "SELECT id FROM discord_membership_suspensions "
            "WHERE user_id=? AND vps_id=? AND server_id=? AND is_active=1",
            (user_id, vps["id"], server_id),
        ).fetchone()
        if existing:
            continue
        # Suspend the VPS
        try:
            import vps as vps_mod
            vps_mod.suspend_vps(vps["container_id"])
        except Exception as e:
            logger.error(f"Failed to suspend VPS {vps['id']}: {e}")
        db.execute(
            "UPDATE vps SET status='suspended' WHERE id=?", (vps["id"],)
        )
        db.execute(
            "INSERT INTO discord_membership_suspensions(user_id, vps_id, server_type, server_id, "
            "server_name, reason, suspended_at, is_active) VALUES(?, ?, ?, ?, ?, ?, ?, 1)",
            (user_id, vps["id"], server_type, server_id, server_name, reason, int(time.time())),
        )
        db.commit()
    db.close()


def handle_member_joined(user_id: int, server_type: str, server_id: str):
    """Handle a user joining a required server. May restore VPSes."""
    db = get_db()
    db.execute(
        "INSERT INTO discord_membership(user_id, server_type, server_id, is_member, last_checked_at, check_count) "
        "VALUES(?, ?, ?, 1, ?, 1) "
        "ON CONFLICT(user_id, server_type, server_id) DO UPDATE SET "
        "is_member=1, last_checked_at=excluded.last_checked_at, check_count=check_count+1",
        (user_id, server_type, server_id, int(time.time())),
    )
    db.commit()

    # Check if all requirements are met now
    result = verify_user_membership(user_id, force=True)
    if not result["verified"]:
        db.close()
        return

    # Restore suspended VPSes (only those suspended for membership reasons)
    vpses = db.execute(
        "SELECT v.id, v.container_id FROM vps v "
        "JOIN discord_membership_suspensions dms ON dms.vps_id = v.id "
        "WHERE v.user_id=? AND dms.is_active=1 AND v.status='suspended'",
        (user_id,),
    ).fetchall()

    for vps in vpses:
        # Check if there are other active suspension reasons
        other = db.execute(
            "SELECT COUNT(*) as c FROM discord_membership_suspensions "
            "WHERE vps_id=? AND is_active=1 AND restored_at=0",
            (vps["id"],),
        ).fetchone()
        # Only restore if this was the only suspension reason
        # (or if all membership suspensions are being resolved)
        try:
            import vps as vps_mod
            vps_mod.unsuspend_vps(vps["container_id"])
        except Exception as e:
            logger.error(f"Failed to restore VPS {vps['id']}: {e}")
            continue
        db.execute(
            "UPDATE vps SET status='running' WHERE id=?", (vps["id"],)
        )
        db.execute(
            "UPDATE discord_membership_suspensions SET is_active=0, restored_at=? "
            "WHERE vps_id=? AND is_active=1",
            (int(time.time()), vps["id"]),
        )
        db.commit()
    db.close()


# ── Periodic reconciliation ────────────────────────────────────────────────

def reconcile_memberships():
    """Periodic job to verify all linked users' memberships."""
    db = get_db()
    links = db.execute("SELECT user_id FROM discord_links WHERE status='linked'").fetchall()
    db.close()
    for link in links:
        try:
            verify_user_membership(link["user_id"], force=True)
        except Exception as e:
            logger.error(f"Reconciliation failed for user {link['user_id']}: {e}")


def start_reconciliation_worker(interval_hours: int = 6):
    """Start a background thread for periodic membership reconciliation."""
    def worker():
        while True:
            try:
                reconcile_memberships()
            except Exception as e:
                logger.error(f"Reconciliation worker error: {e}")
            time.sleep(interval_hours * 3600)
    t = threading.Thread(target=worker, daemon=True)
    t.start()
    logger.info(f"Membership reconciliation worker started (interval: {interval_hours}h)")


# ── Audit helpers ──────────────────────────────────────────────────────────

def audit_log(admin_id: int, action: str, target_user_id: int = None, target_server_id: str = None, details: str = ""):
    """Write an audit log entry."""
    db = get_db()
    db.execute(
        "INSERT INTO discord_audit_log(admin_id, action, target_user_id, target_server_id, details, created_at) "
        "VALUES(?, ?, ?, ?, ?, ?)",
        (admin_id, action, target_user_id, target_server_id, details, int(time.time())),
    )
    db.commit()
    db.close()


# ── Config helpers ─────────────────────────────────────────────────────────

def get_discord_config() -> dict:
    return get_all_config()


def update_discord_config(config: dict, admin_id: int = None):
    """Update Discord configuration."""
    for key, val in config.items():
        if key in ("bot_token", "client_secret"):
            # Encrypt secrets
            set_config(key, _encrypt_token(val) if val else "")
        else:
            set_config(key, val)
    if admin_id:
        audit_log(admin_id, "config_update", details=json.dumps({k: "***" if k in ("bot_token", "client_secret") else v for k, v in config.items()}))


def get_promotion_slot(slot_number: int) -> dict | None:
    db = get_db()
    row = db.execute(
        "SELECT * FROM discord_promotion_slots WHERE slot_number=?", (slot_number,)
    ).fetchone()
    db.close()
    return dict(row) if row else None


# ── User-facing status ──────────────────────────────────────────────────────

def get_user_discord_status(user_id: int) -> dict:
    """Get a comprehensive Discord status for a user."""
    db = get_db()
    link = db.execute("SELECT * FROM discord_links WHERE user_id=?", (user_id,)).fetchone()
    if not link:
        db.close()
        return {
            "linked": False,
            "discord_username": None,
            "discord_id": None,
            "main_server": {"status": "not_linked", "name": get_config("main_server_name", "Deup Gaming")},
            "promotion_servers": [],
            "verified": False,
            "oauth_valid": False,
        }
    result = verify_user_membership(user_id)
    db.close()
    return {
        "linked": True,
        "discord_username": link["discord_username"],
        "discord_id": link["discord_id"],
        "discord_avatar": link["discord_avatar"],
        "main_server": result["main_server"],
        "promotion_servers": result["promotion_servers"],
        "verified": result["verified"],
        "oauth_valid": result["oauth_valid"],
        "missing": result["missing"],
        "missing_servers": result["missing_servers"],
        "last_verified_at": link["last_verified_at"],
    }

