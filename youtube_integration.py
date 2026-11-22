"""
YouTube Subscription Verification Module — DeupGaming Free Panel

Handles YouTube OAuth2 account linking, subscription verification,
and VPS eligibility checks based on channel subscription status.

All YouTube/Google credentials are stored in the database (admin_config),
never exposed to the frontend.
"""

import os
import json
import time
import sqlite3
import secrets
import threading
import logging
import base64

import requests

DB = "panel.db"
logger = logging.getLogger("youtube_integration")

# ── Google/YouTube API endpoints ──────────────────────────────────────────
GOOGLE_OAUTH_AUTHORIZE = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_OAUTH_TOKEN = "https://oauth2.googleapis.com/token"
YOUTUBE_API = "https://www.googleapis.com/youtube/v3"

# Required OAuth2 scopes
OAUTH_SCOPES = "https://www.googleapis.com/auth/youtube.readonly"


# ── DB helpers ─────────────────────────────────────────────────────────────

def get_db():
    db = sqlite3.connect(DB)
    db.row_factory = sqlite3.Row
    return db


def init_youtube_tables(db):
    """Create YouTube-related tables if they don't exist."""
    db.executescript("""
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
    """)
    defaults = {
        "client_id": "",
        "client_secret": "",
        "oauth_redirect_url": "",
        "channel_id": "",          # Deup's YouTube channel ID
        "channel_title": "Deup Gaming",
        "channel_url": "",
        "required": "1",            # Whether YouTube sub is required
        "suspension_enabled": "1",
        "grace_period_hours": "24",
        "verification_interval_hours": "12",
        "status": "disconnected",
        "last_sync_at": "0",
    }
    for key, val in defaults.items():
        db.execute(
            "INSERT OR IGNORE INTO youtube_config(key, value) VALUES (?, ?)",
            (key, val),
        )
    db.commit()


# ── Config helpers ─────────────────────────────────────────────────────────

def get_config(key: str, default: str = "") -> str:
    db = get_db()
    row = db.execute("SELECT value FROM youtube_config WHERE key=?", (key,)).fetchone()
    db.close()
    return row["value"] if row else default


def set_config(key: str, value: str):
    db = get_db()
    db.execute(
        "INSERT INTO youtube_config(key, value) VALUES(?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, value),
    )
    db.commit()
    db.close()


def get_all_config() -> dict:
    db = get_db()
    rows = db.execute("SELECT key, value FROM youtube_config").fetchall()
    db.close()
    return {r["key"]: r["value"] for r in rows}


# ── Encryption helpers ──────────────────────────────────────────────────────

def _encrypt_token(token: str) -> str:
    if not token:
        return ""
    key = os.environ.get("YOUTUBE_ENCRYPTION_KEY", "dxdfree-youtube-secret-key")
    encrypted = ""
    for i, c in enumerate(token):
        encrypted += chr(ord(c) ^ ord(key[i % len(key)]))
    return base64.b64encode(encrypted.encode()).decode()


def _decrypt_token(encrypted: str) -> str:
    if not encrypted:
        return ""
    try:
        key = os.environ.get("YOUTUBE_ENCRYPTION_KEY", "dxdfree-youtube-secret-key")
        encrypted = base64.b64decode(encrypted.encode()).decode()
        decrypted = ""
        for i, c in enumerate(encrypted):
            decrypted += chr(ord(c) ^ ord(key[i % len(key)]))
        return decrypted
    except Exception:
        return ""


# ── OAuth2 state management ────────────────────────────────────────────────

def generate_oauth_state(user_id: int) -> str:
    state = secrets.token_urlsafe(32)
    db = get_db()
    db.execute(
        "INSERT OR REPLACE INTO youtube_config(key, value) VALUES(?, ?)",
        (f"oauth_state_{state}", f"{user_id}:{int(time.time()) + 600}"),
    )
    db.commit()
    db.close()
    return state


def validate_oauth_state(state: str) -> int | None:
    if not state:
        return None
    db = get_db()
    row = db.execute(
        "SELECT value FROM youtube_config WHERE key=?", (f"oauth_state_{state}",)
    ).fetchone()
    if row:
        db.execute("DELETE FROM youtube_config WHERE key=?", (f"oauth_state_{state}",))
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


# ── OAuth2 URL builder ──────────────────────────────────────────────────────

def get_oauth_url(user_id: int) -> str:
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
        "access_type": "offline",
        "prompt": "consent",
    }
    query = "&".join(f"{k}={requests.utils.quote(str(v))}" for k, v in params.items())
    return f"{GOOGLE_OAUTH_AUTHORIZE}?{query}"


# ── OAuth2 token exchange ──────────────────────────────────────────────────

def exchange_code_for_token(code: str) -> dict | None:
    client_id = get_config("client_id")
    client_secret = get_config("client_secret")
    redirect_url = get_config("oauth_redirect_url")
    if not client_id or not client_secret or not redirect_url:
        return None
    try:
        resp = requests.post(
            GOOGLE_OAUTH_TOKEN,
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


def get_google_user(access_token: str) -> dict | None:
    try:
        resp = requests.get(
            "https://www.googleapis.com/oauth2/v2/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=15,
        )
        if resp.status_code == 200:
            return resp.json()
        return None
    except Exception:
        return None


def get_youtube_channel(access_token: str) -> dict | None:
    """Get the user's YouTube channel info."""
    try:
        resp = requests.get(
            f"{YOUTUBE_API}/channels",
            params={"part": "snippet,statistics", "mine": "true"},
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=15,
        )
        if resp.status_code == 200:
            data = resp.json()
            items = data.get("items", [])
            if items:
                return items[0]
        return None
    except Exception as e:
        logger.error(f"YouTube channel lookup failed: {e}")
        return None


# ── Subscription check ──────────────────────────────────────────────────────

def check_subscription(access_token: str, channel_id: str) -> tuple[bool, str]:
    """Check if the user is subscribed to a specific channel."""
    if not access_token or not channel_id:
        return False, "Missing parameters"
    try:
        resp = requests.get(
            f"{YOUTUBE_API}/subscriptions",
            params={
                "part": "snippet",
                "mine": "true",
                "forChannelId": channel_id,
            },
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=15,
        )
        if resp.status_code == 200:
            data = resp.json()
            items = data.get("items", [])
            if items:
                return True, "Subscribed"
            return False, "Not subscribed"
        elif resp.status_code == 401:
            return False, "Authorization expired"
        elif resp.status_code == 403:
            return False, "Insufficient permissions — reauthorize with YouTube scope"
        else:
            return False, f"API error {resp.status_code}: {resp.text[:200]}"
    except Exception as e:
        return False, str(e)


# ── Link / Unlink ──────────────────────────────────────────────────────────

def link_youtube_account(user_id: int, google_profile: dict, channel: dict | None, access_token: str, refresh_token: str = None, expires_in: int = 0) -> tuple[bool, str]:
    """Link a YouTube/Google account to a panel user."""
    google_id = google_profile.get("id")
    if not google_id:
        return False, "No Google ID in profile"
    db = get_db()
    existing = db.execute(
        "SELECT user_id FROM youtube_links WHERE google_id=?", (google_id,)
    ).fetchone()
    if existing and existing["user_id"] != user_id:
        db.close()
        return False, "This Google account is already linked to another panel account"
    db.execute("DELETE FROM youtube_links WHERE user_id=?", (user_id,))
    db.execute(
        "INSERT INTO youtube_links(user_id, google_id, google_email, google_name, google_avatar, "
        "channel_id, channel_title, oauth_token_encrypted, oauth_refresh_token_encrypted, "
        "oauth_expires_at, linked_at, status) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'linked')",
        (
            user_id,
            google_id,
            google_profile.get("email", ""),
            google_profile.get("name", ""),
            google_profile.get("picture", ""),
            channel.get("id", "") if channel else "",
            channel.get("snippet", {}).get("title", "") if channel else "",
            _encrypt_token(access_token),
            _encrypt_token(refresh_token) if refresh_token else "",
            int(time.time()) + expires_in if expires_in else 0,
            int(time.time()),
        ),
    )
    db.commit()
    db.execute(
        "INSERT INTO youtube_verification_history(user_id, event_type, status, details, created_at) "
        "VALUES(?, 'link', 'success', ?, ?)",
        (user_id, f"Linked Google account {google_profile.get('email', '')}", int(time.time())),
    )
    db.commit()
    db.close()
    return True, "YouTube account linked successfully"


def unlink_youtube_account(user_id: int) -> bool:
    db = get_db()
    link = db.execute("SELECT google_id, google_name FROM youtube_links WHERE user_id=?", (user_id,)).fetchone()
    if not link:
        db.close()
        return False
    db.execute("DELETE FROM youtube_links WHERE user_id=?", (user_id,))
    db.execute("DELETE FROM youtube_subscription_status WHERE user_id=?", (user_id,))
    db.execute(
        "INSERT INTO youtube_verification_history(user_id, event_type, status, details, created_at) "
        "VALUES(?, 'unlink', 'success', ?, ?)",
        (user_id, f"Unlinked Google account {link['google_name']}", int(time.time())),
    )
    db.commit()
    db.close()
    return True


# ── Config helpers ─────────────────────────────────────────────────────────

def get_config(key: str, default: str = "") -> str:
    db = get_db()
    row = db.execute("SELECT value FROM youtube_config WHERE key=?", (key,)).fetchone()
    db.close()
    return row["value"] if row else default


def set_config(key: str, value: str):
    db = get_db()
    db.execute(
        "INSERT INTO youtube_config(key, value) VALUES(?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, value),
    )
    db.commit()
    db.close()


def get_all_config() -> dict:
    db = get_db()
    rows = db.execute("SELECT key, value FROM youtube_config").fetchall()
    db.close()
    return {r["key"]: r["value"] for r in rows}


# ── Subscription verification ──────────────────────────────────────────────

def get_required_channel() -> dict | None:
    """Get the required YouTube channel config."""
    channel_id = get_config("channel_id")
    if not channel_id:
        return None
    return {
        "channel_id": channel_id,
        "channel_title": get_config("channel_title", "Deup Gaming"),
        "channel_url": get_config("channel_url", f"https://youtube.com/channel/{channel_id}"),
    }


def verify_subscription(user_id: int, force: bool = False) -> dict:
    """Verify a user's YouTube subscription status.

    Returns dict with:
        verified: bool
        youtube_linked: bool
        channel_title: str or None
        is_subscribed: bool
        last_checked_at: int
        error: str or None
    """
    db = get_db()
    link = db.execute("SELECT * FROM youtube_links WHERE user_id=?", (user_id,)).fetchone()
    result = {
        "verified": False,
        "youtube_linked": False,
        "channel_title": None,
        "is_subscribed": False,
        "last_checked_at": 0,
        "error": None,
    }

    if not link:
        result["error"] = "YouTube account not linked"
        db.close()
        return result

    result["youtube_linked"] = True
    result["channel_title"] = link["channel_title"]

    required = get_required_channel()
    if not required:
        # No channel configured — skip verification
        result["verified"] = True
        db.close()
        return result

    channel_id = required["channel_id"]
    channel_title = required["channel_title"]

    # Check cache
    last_checked = link["last_verified_at"] or 0
    stale = (int(time.time()) - last_checked) > (12 * 3600)  # 12 hours
    if not force and not stale:
        # Use cached status
        status_row = db.execute(
            "SELECT is_subscribed FROM youtube_subscription_status WHERE user_id=? AND channel_id=?",
            (user_id, channel_id),
        ).fetchone()
        if status_row:
            result["is_subscribed"] = bool(status_row["is_subscribed"])
            result["verified"] = result["is_subscribed"]
            result["last_checked_at"] = last_checked
            db.close()
            return result

    # Get access token
    access_token = _decrypt_token(link["oauth_token_encrypted"])
    if not access_token:
        result["error"] = "YouTube authorization missing — please relink"
        db.close()
        return result

    # Check subscription
    is_subscribed, msg = check_subscription(access_token, channel_id)

    # Update status
    db.execute(
        "INSERT INTO youtube_subscription_status(user_id, channel_id, channel_title, is_subscribed, last_checked_at, check_count) "
        "VALUES(?, ?, ?, ?, ?, 1) "
        "ON CONFLICT(user_id, channel_id) DO UPDATE SET "
        "is_subscribed=excluded.is_subscribed, last_checked_at=excluded.last_checked_at, "
        "check_count=check_count+1",
        (user_id, channel_id, channel_title, int(is_subscribed), int(time.time())),
    )
    db.execute(
        "UPDATE youtube_links SET last_verified_at=? WHERE user_id=?",
        (int(time.time()), user_id),
    )
    db.commit()

    # Log
    db.execute(
        "INSERT INTO youtube_verification_history(user_id, event_type, status, details, created_at) "
        "VALUES(?, 'verify', ?, ?, ?)",
        (user_id, "success" if is_subscribed else "incomplete", msg, int(time.time())),
    )
    db.commit()
    db.close()

    result["is_subscribed"] = is_subscribed
    result["verified"] = is_subscribed
    result["last_checked_at"] = int(time.time())
    if not is_subscribed:
        result["error"] = f"Not subscribed to {channel_title}"
    return result


# ── VPS eligibility check ──────────────────────────────────────────────────

def check_vps_eligibility(user_id: int) -> tuple[bool, str]:
    """Check if a user is eligible to create a VPS based on YouTube subscription.

    Returns (eligible: bool, reason: str).
    """
    config = get_all_config()
    required = config.get("required", "1") == "1"
    channel_id = config.get("channel_id", "")

    if not required or not channel_id:
        # YouTube verification not required or not configured — allow
        return True, "YouTube verification not required"

    db = get_db()
    link = db.execute("SELECT * FROM youtube_links WHERE user_id=?", (user_id,)).fetchone()
    if not link:
        db.close()
        return False, "YouTube account not linked. Link your YouTube account first."

    if link["status"] != "linked":
        db.close()
        return False, "YouTube account is disconnected. Please relink."

    access_token = _decrypt_token(link["oauth_token_encrypted"])
    if not access_token:
        db.close()
        return False, "YouTube authorization missing. Please relink."

    result = verify_subscription(user_id, force=False)
    db.close()

    if not result["verified"]:
        channel_title = get_config("channel_title", "Deup Gaming")
        channel_url = get_config("channel_url", "")
        msg = f"You must subscribe to {channel_title}"
        if channel_url:
            msg += f" ({channel_url})"
        return False, msg

    return True, "YouTube subscription verified"


# ── Suspension / Restoration ────────────────────────────────────────────────

def handle_unsubscribe(user_id: int):
    """Handle a user unsubscribing from the required channel.

    Suspends their VPSes. Does NOT delete data.
    """
    db = get_db()
    config = get_all_config()
    if config.get("suspension_enabled", "1") != "1":
        db.close()
        return

    vpses = db.execute(
        "SELECT id, container_id, status FROM vps WHERE user_id=? AND status='running'",
        (user_id,),
    ).fetchall()

    channel_id = get_config("channel_id")
    channel_title = get_config("channel_title", "Deup Gaming")

    for vps in vpses:
        try:
            import vps as vps_mod
            vps_mod.suspend_vps(vps["container_id"])
        except Exception as e:
            logger.error(f"Failed to suspend VPS {vps['id']}: {e}")
            continue
        db.execute("UPDATE vps SET status='suspended' WHERE id=?", (vps["id"],))
        db.execute(
            "INSERT INTO youtube_verification_history(user_id, event_type, status, details, created_at) "
            "VALUES(?, 'suspension', 'success', ?, ?)",
            (user_id, f"Suspended: unsubscribed from {channel_title}", int(time.time())),
        )
        db.commit()

    # Update subscription status
    db.execute(
        "UPDATE youtube_subscription_status SET is_subscribed=0 WHERE user_id=? AND channel_id=?",
        (user_id, channel_id),
    )
    db.commit()
    db.close()


def handle_resubscribe(user_id: int):
    """Handle a user resubscribing to the required channel.

    Restores their VPSes if subscription was the only suspension reason.
    """
    db = get_db()
    result = verify_subscription(user_id, force=True)
    if not result["verified"]:
        db.close()
        return

    vpses = db.execute(
        "SELECT id, container_id, status FROM vps WHERE user_id=? AND status='suspended'",
        (user_id,),
    ).fetchall()

    for vps in vpses:
        try:
            import vps as vps_mod
            vps_mod.unsuspend_vps(vps["container_id"])
        except Exception as e:
            logger.error(f"Failed to restore VPS {vps['id']}: {e}")
            continue
        db.execute("UPDATE vps SET status='running' WHERE id=?", (vps["id"],))
        db.execute(
            "INSERT INTO youtube_verification_history(user_id, event_type, status, details, created_at) "
            "VALUES(?, 'restoration', 'success', ?, ?)",
            (user_id, "Restored: resubscribed", int(time.time())),
        )
        db.commit()
    db.close()


# ── User-facing status ──────────────────────────────────────────────────────

def get_user_youtube_status(user_id: int) -> dict:
    """Get a comprehensive YouTube status for a user."""
    db = get_db()
    link = db.execute("SELECT * FROM youtube_links WHERE user_id=?", (user_id,)).fetchone()
    if not link:
        db.close()
        return {
            "linked": False,
            "google_name": None,
            "google_email": None,
            "channel_title": None,
            "channel_url": get_config("channel_url", ""),
            "verified": False,
            "is_subscribed": False,
            "required": get_config("required", "1") == "1",
            "required_channel_title": get_config("channel_title", "Deup Gaming"),
        }
    status = verify_subscription(user_id, force=False)
    db.close()
    return {
        "linked": True,
        "google_name": link["google_name"],
        "google_email": link["google_email"],
        "google_avatar": link["google_avatar"],
        "channel_title": link["channel_title"],
        "channel_url": get_config("channel_url", ""),
        "verified": status["verified"],
        "is_subscribed": status["is_subscribed"],
        "required": get_config("required", "1") == "1",
        "required_channel_title": get_config("channel_title", "Deup Gaming"),
        "last_verified_at": link["last_verified_at"],
        "error": status.get("error"),
    }


# ── Periodic reconciliation ─────────────────────────────────────────────────

def reconcile_subscriptions():
    """Periodic job to verify all linked users' subscriptions."""
    db = get_db()
    links = db.execute("SELECT user_id FROM youtube_links WHERE status='linked'").fetchall()
    db.close()
    for link in links:
        try:
            result = verify_subscription(link["user_id"], force=True)
            if not result["verified"]:
                handle_unsubscribe(link["user_id"])
            else:
                handle_resubscribe(link["user_id"])
        except Exception as e:
            logger.error(f"Reconciliation failed for user {link['user_id']}: {e}")


def start_reconciliation_worker(interval_hours: int = 12):
    """Start a background thread for periodic subscription reconciliation."""
    def worker():
        while True:
            try:
                reconcile_subscriptions()
            except Exception as e:
                logger.error(f"Reconciliation worker error: {e}")
            time.sleep(interval_hours * 3600)
    t = threading.Thread(target=worker, daemon=True)
    t.start()
    logger.info(f"YouTube reconciliation worker started (interval: {interval_hours}h)")


# ── Config helpers ──────────────────────────────────────────────────────────

def get_youtube_config() -> dict:
    return get_all_config()


def update_youtube_config(config: dict, admin_id: int = None):
    """Update YouTube configuration."""
    for key, val in config.items():
        set_config(key, val)
    if admin_id:
        # Audit log
        db = get_db()
        db.execute(
            "INSERT INTO admin_audit(admin_id, action, target, created_at) VALUES(?,?,?,?)",
            (admin_id, "youtube_config_update", "youtube", int(time.time())),
        )
        db.commit()
        db.close()


def test_connection() -> tuple[bool, str]:
    """Test the YouTube API connection with the configured credentials."""
    client_id = get_config("client_id")
    client_secret = get_config("client_secret")
    if not client_id or not client_secret:
        return False, "Client ID and Client Secret are required"
    # Test by getting an access token with client credentials
    try:
        resp = requests.post(
            GOOGLE_OAUTH_TOKEN,
            data={
                "client_id": client_id,
                "client_secret": client_secret,
                "grant_type": "client_credentials",
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=15,
        )
        if resp.status_code == 200:
            return True, "Credentials valid"
        return False, f"API returned {resp.status_code}: {resp.text[:200]}"
    except Exception as e:
        return False, str(e)


def get_channel_info(channel_id: str) -> dict | None:
    """Get channel info (requires API key, not OAuth)."""
    # For now, return basic info from config
    title = get_config("channel_title", "Deup Gaming")
    url = get_config("channel_url", "")
    return {"id": channel_id, "title": title, "url": url}

