"""
SSHX isolation security tests (Tests A-J).

These tests use a temporary database, temporary VPS roots and patched process
launchers.  They never touch real VPS instances or real customer data.

Run with:  python3 -m unittest discover -s tests -v
"""

import json
import os
import re
import shutil
import sqlite3
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

import sshx_manager as sshx
import vps as vps_mod

LINK = "https://sshx.io/s/ABC123def#s3cr3tKey456"


class SSHXIsolationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="sshx-test-")
        self.db_path = os.path.join(self.tmp, "panel.db")
        self.vps_root = os.path.join(self.tmp, "vps")
        self.session_root = os.path.join(self.tmp, "sessions")
        os.makedirs(self.vps_root)
        os.makedirs(self.session_root)

        # Point both modules at the isolated test environment.
        self.patches = [
            mock.patch.object(sshx, "DB", self.db_path),
            mock.patch.object(sshx, "SESSION_ROOT", self.session_root),
            mock.patch.object(sshx, "GATEWAY_USER", "sshx-test"),
            mock.patch.object(sshx, "LINK_WAIT_SECONDS", 2),
            mock.patch.object(sshx, "_gateway_ids",
                              side_effect=lambda: (os.geteuid(), os.getegid())),
            mock.patch.object(sshx, "_generate_keypair",
                              side_effect=self.fake_keypair),
            mock.patch.object(sshx, "_spawn_gateway",
                              side_effect=self.fake_spawn),
            mock.patch.object(vps_mod, "VPS_ROOT", self.vps_root),
            mock.patch.object(vps_mod, "META_DIR", os.path.join(self.vps_root, "meta")),
            mock.patch.object(vps_mod, "LOG_DIR", os.path.join(self.vps_root, "logs")),
            mock.patch.object(vps_mod, "_VPS_NAME_RE",
                              re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")),
        ]
        for p in self.patches:
            p.start()
        os.makedirs(vps_mod.META_DIR, exist_ok=True)

        self._create_db()
        self._create_vps("vps-user1-aaa", 1, 1, 10001, "running")
        self._create_vps("vps-user2-bbb", 2, 2, 10002, "running")
        self.spawn_calls = []

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    # ── helpers ─────────────────────────────────────────────────────────────
    def _create_db(self):
        db = sqlite3.connect(self.db_path)
        db.executescript("""
        CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT, is_admin INTEGER DEFAULT 0,
                           password TEXT, youtube_verified INTEGER DEFAULT 0,
                           is_suspended INTEGER DEFAULT 0);
        CREATE TABLE vps(id INTEGER PRIMARY KEY, user_id INTEGER, container_id TEXT,
                         ssh_command TEXT, status TEXT, created_at INTEGER, last_regen INTEGER);
        CREATE TABLE nat_rules(id INTEGER PRIMARY KEY, vps_id INTEGER, container_id TEXT,
                               container_ip TEXT, ssh_port INTEGER, extra_ports TEXT, created_at INTEGER);
        """)
        db.execute("INSERT INTO users(id,username,is_admin,is_suspended) VALUES(1,'alice',0,0)")
        db.execute("INSERT INTO users(id,username,is_admin,is_suspended) VALUES(2,'bob',0,0)")
        db.execute("INSERT INTO users(id,username,is_admin,is_suspended) VALUES(3,'admin',1,0)")
        db.commit()
        sshx.init_sshx_tables(db)
        db.close()

    def _create_vps(self, cid, vps_id, user_id, port, status="running"):
        db = sqlite3.connect(self.db_path)
        db.execute("INSERT OR REPLACE INTO vps(id,user_id,container_id,ssh_command,status,created_at)"
                   " VALUES(?,?,?,?,?,?)",
                   (vps_id, user_id, cid, f"ssh root@1.2.3.4 -p {port}", status, int(time.time())))
        db.execute("INSERT OR REPLACE INTO nat_rules(id,vps_id,container_id,container_ip,ssh_port,"
                   "extra_ports,created_at) VALUES(?,?,?,?,?,?,?)",
                   (vps_id, vps_id, cid, "127.0.0.1", port, "", int(time.time())))
        db.commit()
        db.close()
        root = os.path.join(self.vps_root, cid)
        os.makedirs(os.path.join(root, "etc", "ssh"), exist_ok=True)
        os.makedirs(os.path.join(root, "root", ".ssh"), exist_ok=True)
        with open(os.path.join(root, "etc", "ssh", "ssh_host_ed25519_key.pub"), "w") as f:
            f.write(f"ssh-ed25519 AAAAHOSTKEY{cid} root@vps\n")
        with open(os.path.join(vps_mod.META_DIR, cid + ".json"), "w") as f:
            json.dump({"name": cid, "state": "running", "password": "x"}, f)

    def _read_spec(self, session_id):
        with open(os.path.join(sshx._session_dir(session_id), "spec.json")) as f:
            return json.load(f)

    def fake_keypair(self, session_id):
        d = sshx._session_dir(session_id)
        key = os.path.join(d, "id_ed25519")
        with open(key, "w") as f:
            f.write("-----BEGIN TEST KEY-----\n")
        os.chmod(key, 0o600)
        with open(key + ".pub", "w") as f:
            f.write(f"ssh-ed25519 AAAAKEY{session_id} sshx-{session_id}\n")
        return key, f"ssh-ed25519 AAAAKEY{session_id} sshx-{session_id}"

    def fake_spawn(self, session_id, link_path, log_path):
        self.spawn_calls.append((session_id, link_path, log_path))
        with open(link_path, "w") as f:
            f.write(LINK + "\n")
        with open(log_path, "w") as f:
            f.write("[sshx gateway test stub]\n")
        return 999999  # non-existent PID: never signalled in tests

    def set_vps_status(self, vps_id, status):
        db = sqlite3.connect(self.db_path)
        db.execute("UPDATE vps SET status=? WHERE id=?", (status, vps_id))
        db.commit()
        db.close()

    def set_user_suspended(self, user_id, value):
        db = sqlite3.connect(self.db_path)
        db.execute("UPDATE users SET is_suspended=? WHERE id=?", (int(value), user_id))
        db.commit()
        db.close()

    # ── Test A: normal access ───────────────────────────────────────────────
    def test_a_normal_access(self):
        info, err = sshx.create_session(1, 1, "203.0.113.5")
        self.assertEqual(err, "", err)
        self.assertEqual(info["url"], LINK)
        row = sshx.get_session(info["id"], 1)
        self.assertIsNotNone(row)
        self.assertEqual(row["vps_id"], 1)
        self.assertEqual(row["container_id"], "vps-user1-aaa")
        spec = self._read_spec(info["id"])
        self.assertEqual(spec["ssh_port"], 10001)
        self.assertEqual(spec["ssh_host"], "127.0.0.1")
        self.assertEqual(spec["container_id"], "vps-user1-aaa")
        # The link must not be persisted in the DB or in the gateway log.
        db = sqlite3.connect(self.db_path)
        blob = "\n".join(str(r) for r in db.execute("SELECT * FROM vps"))
        db.close()
        self.assertNotIn(LINK, blob)
        with open(spec["log_path"]) as log:
            self.assertNotIn(LINK, log.read())

    # ── Test B: cross-user access ───────────────────────────────────────────
    def test_b_cross_user_access_denied(self):
        info, err = sshx.create_session(1, 2, "203.0.113.5")
        self.assertIsNone(info)
        self.assertIn("owned", err)
        self.assertEqual(self.spawn_calls, [])

    # ── Test C: main host protection ────────────────────────────────────────
    def test_c_main_host_protection(self):
        # No host row exists, and host-style identifiers are rejected.
        for cid, vid in (("", 999), ("127.0.0.1", 999), ("localhost", 999)):
            db = sqlite3.connect(self.db_path)
            db.execute("INSERT OR IGNORE INTO vps(id,user_id,container_id,status)"
                       " VALUES(?,?,?, 'running')", (vid, 1, cid))
            db.commit()
            db.close()
        ok, reason, _ = sshx.authorize_session(1, 999)
        self.assertFalse(ok)
        self.assertNotIn("ssh_port", reason)
        self.assertEqual(self.spawn_calls, [])

    # ── Test D: suspended VPS / user ────────────────────────────────────────
    def test_d_suspended_vps_rejected(self):
        self.set_vps_status(1, "suspended")
        info, err = sshx.create_session(1, 1)
        self.assertIsNone(info)
        self.assertIn("not running", err)
        self.set_vps_status(1, "running")
        self.set_user_suspended(1, True)
        info, err = sshx.create_session(1, 1)
        self.assertIsNone(info)
        self.assertIn("suspended", err)

    # ── Test E: session isolation ───────────────────────────────────────────
    def test_e_session_isolation(self):
        a, _ = sshx.create_session(1, 1)
        self.assertIsNone(sshx.get_session(a["id"], 2))          # wrong user
        self.assertFalse(sshx.revoke_session(a["id"], user_id=2))  # wrong user cannot revoke
        self.assertIsNotNone(sshx.get_session(a["id"], 1))        # still active

    # ── Test F: expiration ──────────────────────────────────────────────────
    def test_f_expiration(self):
        info, _ = sshx.create_session(1, 1)
        db = sqlite3.connect(self.db_path)
        db.execute("UPDATE sshx_sessions SET expires_at=? WHERE id=?",
                   (int(time.time()) - 1, info["id"]))
        db.commit()
        db.close()
        with mock.patch.object(sshx, "_terminate_pid") as term:
            count = sshx.expire_stale_sessions()
            self.assertGreaterEqual(count, 1)
            term.assert_called()
        row = sshx.get_session(info["id"], 1)
        self.assertEqual(row["status"], "expired")
        self.assertFalse(os.path.exists(sshx._session_dir(info["id"])))
        ak = os.path.join(self.vps_root, "vps-user1-aaa", "root", ".ssh", "authorized_keys")
        with open(ak) as f:
            self.assertNotIn(info["id"], f.read())

    # ── Test G: revocation ──────────────────────────────────────────────────
    def test_g_revocation(self):
        info, _ = sshx.create_session(1, 1)
        with mock.patch.object(sshx, "_terminate_pid") as term:
            self.assertTrue(sshx.revoke_session(info["id"], actor_id=3,
                                                is_admin=True, reason="admin"))
            term.assert_called_once_with(999999)
        self.assertEqual(sshx.get_session(info["id"], 1)["status"], "revoked")
        self.assertFalse(os.path.exists(sshx._session_dir(info["id"])))

    # ── Test H: invalid identifiers / arbitrary connection params ───────────
    def test_h_invalid_identifiers(self):
        for bad in (0, -1, "1;cat /etc/passwd", "vps-user2-bbb", None):
            ok, _, _ = sshx.authorize_session(1, bad)
            self.assertFalse(ok, f"accepted bad id {bad!r}")
        # Policy toggles and per-target restrictions are enforced.
        sshx.set_disabled("vps", 1, True, 3, "test")
        info, err = sshx.create_session(1, 1)
        self.assertIsNone(info)
        self.assertIn("disabled", err)
        sshx.set_disabled("vps", 1, False, 3)
        sshx.set_disabled("user", 1, True, 3, "test")
        info, err = sshx.create_session(1, 1)
        self.assertIsNone(info)
        sshx.set_disabled("user", 1, False, 3)
        sshx.set_policy("global_enabled", "0")
        info, err = sshx.create_session(1, 1)
        self.assertIsNone(info)
        sshx.set_policy("global_enabled", "1")

    # ── Test I: host privilege checks (static) ──────────────────────────────
    def test_i_host_privilege_checks(self):
        gateway = (REPO / "gateway" / "sshx_gateway.py").read_text()
        target = (REPO / "gateway" / "sshx-target-shell").read_text()
        manager = (REPO / "sshx_manager.py").read_text()
        vps_src = (REPO / "vps.py").read_text()
        self.assertIn("if os.geteuid() == 0", gateway)
        self.assertIn("if os.geteuid() == 0", target)
        self.assertNotIn("shell=True", gateway)
        self.assertNotIn("shell=True", target)
        self.assertNotIn("shell=True", manager)
        self.assertNotIn("chroot(", manager)
        self.assertNotIn("/usr/sbin/chroot", manager)
        self.assertNotIn("_start_sshx_session", vps_src)
        self.assertNotIn("regen_sshx", vps_src)
        self.assertNotIn("SSHX_LINK_RE", vps_src)
        self.assertIn("SSHX_GATEWAY_USER=sshx-gw", (REPO / "installer.py").read_text())

    # ── Test J: multiple users ──────────────────────────────────────────────
    def test_j_multiple_users_isolated(self):
        a, ea = sshx.create_session(1, 1)
        b, eb = sshx.create_session(2, 2)
        self.assertEqual((ea, eb), ("", ""))
        sa = self._read_spec(a["id"])
        sb = self._read_spec(b["id"])
        self.assertNotEqual(sa["ssh_port"], sb["ssh_port"])
        self.assertNotEqual(sa["key_path"], sb["key_path"])
        self.assertEqual(sshx.get_session(a["id"], 2), None)
        self.assertEqual(sshx.get_session(b["id"], 1), None)
        self.assertEqual(sshx.get_session(a["id"], 1)["vps_id"], 1)
        self.assertEqual(sshx.get_session(b["id"], 2)["vps_id"], 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
