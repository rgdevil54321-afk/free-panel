"""HTTP-level SSHX isolation tests.

Exercises the Flask routes with an isolated temporary database.  No real VPS,
host account, or customer data is touched.
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

import app as app_mod
import sshx_manager as sshx
import vps as vps_mod

LINK = "https://sshx.io/s/XYZ789abc#routeTestSecret"


class SSHXRouteTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="sshx-route-test-")
        self.db_path = os.path.join(self.tmp, "panel.db")
        self.vps_root = os.path.join(self.tmp, "vps")
        self.session_root = os.path.join(self.tmp, "sessions")
        os.makedirs(self.vps_root)
        os.makedirs(self.session_root)

        self.patches = [
            mock.patch.object(app_mod, "DB", self.db_path),
            mock.patch.object(sshx, "DB", self.db_path),
            mock.patch.object(sshx, "SESSION_ROOT", self.session_root),
            mock.patch.object(sshx, "GATEWAY_USER", "sshx-test"),
            mock.patch.object(sshx, "LINK_WAIT_SECONDS", 2),
            mock.patch.object(sshx, "_gateway_ids",
                              side_effect=lambda: (os.geteuid(), os.getegid())),
            mock.patch.object(sshx, "_generate_keypair", side_effect=self.fake_keypair),
            mock.patch.object(sshx, "_spawn_gateway", side_effect=self.fake_spawn),
            mock.patch.object(vps_mod, "VPS_ROOT", self.vps_root),
            mock.patch.object(vps_mod, "META_DIR", os.path.join(self.vps_root, "meta")),
            mock.patch.object(vps_mod, "LOG_DIR", os.path.join(self.vps_root, "logs")),
            mock.patch.object(vps_mod, "_VPS_NAME_RE",
                              re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")),
            mock.patch.object(app_mod.nat, "get_public_ip", return_value="198.51.100.1"),
            mock.patch.object(app_mod, "kvm_available", return_value=False),
        ]
        for p in self.patches:
            p.start()
        os.makedirs(vps_mod.META_DIR, exist_ok=True)

        app_mod.get_db = self.get_db
        self._create_db()
        self._create_vps("vps-route-alice", 1, 1, 11001)
        self._create_vps("vps-route-bob", 2, 2, 11002)

        app_mod.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
        self.client = app_mod.app.test_client()

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def get_db(self):
        db = sqlite3.connect(self.db_path, timeout=15)
        db.row_factory = sqlite3.Row
        return db

    def login(self, uid):
        with self.client.session_transaction() as sess:
            sess["_user_id"] = str(uid)
            sess["_fresh"] = True
            sess["_csrf_token"] = "test-csrf-token"

    def _create_db(self):
        db = sqlite3.connect(self.db_path)
        db.executescript("""
        CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT, is_admin INTEGER DEFAULT 0,
                           password TEXT, youtube_verified INTEGER DEFAULT 0,
                           is_suspended INTEGER DEFAULT 0);
        CREATE TABLE broadcast(id INTEGER PRIMARY KEY, message TEXT, active INTEGER);
        CREATE TABLE vps(id INTEGER PRIMARY KEY, user_id INTEGER, container_id TEXT,
                         ssh_command TEXT, status TEXT, created_at INTEGER, last_regen INTEGER,
                         kvm_enabled INTEGER DEFAULT 0);
        CREATE TABLE nat_rules(id INTEGER PRIMARY KEY, vps_id INTEGER, container_id TEXT,
                               container_ip TEXT, ssh_port INTEGER, extra_ports TEXT,
                               created_at INTEGER);
        INSERT INTO broadcast(id,message,active) VALUES(1,NULL,0);
        INSERT INTO users(id,username,is_admin,is_suspended) VALUES(1,'alice',0,0);
        INSERT INTO users(id,username,is_admin,is_suspended) VALUES(2,'bob',0,0);
        INSERT INTO users(id,username,is_admin,is_suspended) VALUES(3,'admin',1,0);
        """)
        db.commit()
        sshx.init_sshx_tables(db)
        # Tests run with containment lifted (post-validation state).
        db.execute("INSERT OR REPLACE INTO sshx_policy(key,value) VALUES(?,?)",
                   (sshx.CONTAINED_POLICY, "0"))
        db.execute("INSERT OR REPLACE INTO sshx_policy(key,value) VALUES(?,?)",
                   (sshx.GLOBAL_POLICY, "1"))
        db.commit()
        db.close()

    def _create_vps(self, cid, vps_id, user_id, port):
        db = sqlite3.connect(self.db_path)
        db.execute("INSERT INTO vps(id,user_id,container_id,ssh_command,status,created_at)"
                   " VALUES(?,?,?,?, 'running',?)",
                   (vps_id, user_id, cid, f"ssh root@198.51.100.1 -p {port}", int(time.time())))
        db.execute("INSERT INTO nat_rules(id,vps_id,container_id,container_ip,ssh_port,"
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
            json.dump({"name": cid, "state": "running"}, f)

    def fake_keypair(self, session_id):
        d = sshx._session_dir(session_id)
        os.makedirs(d, exist_ok=True)
        key = os.path.join(d, "id_ed25519")
        with open(key, "w") as f:
            f.write("dummy")
        with open(key + ".pub", "w") as f:
            f.write(f"ssh-ed25519 AAAAKEY{session_id} sshx-{session_id}\n")
        return key, f"ssh-ed25519 AAAAKEY{session_id} sshx-{session_id}"

    def fake_spawn(self, session_id, link_path, log_path):
        with open(link_path, "w") as f:
            f.write(LINK + "\n")
        with open(log_path, "w") as f:
            f.write("[test gateway]\n")
        return 999999

    def post_create(self, vps_id, extra=None):
        payload = {"vps_id": vps_id}
        payload.update(extra or {})
        return self.client.post(
            "/api/sshx/session", json=payload,
            headers={"X-CSRF-Token": "test-csrf-token"},
        )

    # ── H (HTTP): no browser-supplied host / port / key is honoured ──────────
    def test_route_ignores_client_connection_parameters(self):
        self.login(1)
        r = self.post_create(1, extra={
            "host": "127.0.0.1",
            "port": 22,
            "ssh_port": 22,
            "container_id": "vps-route-bob",
            "username": "root",
            "password": "hunter2",
            "private_key": "PRIVATE KEY MATERIAL",
            "forwarding": "0.0.0.0:22:127.0.0.1:22",
        })
        self.assertEqual(r.status_code, 201, r.get_data(as_text=True))
        data = r.get_json()
        self.assertEqual(data["vps_id"], 1)
        for forbidden in ("password", "private_key", "hunter2", "PRIVATE KEY MATERIAL"):
            self.assertNotIn(forbidden, r.get_data(as_text=True))
        with open(os.path.join(sshx._session_dir(data["id"]), "spec.json")) as f:
            spec = json.load(f)
        self.assertEqual(spec["ssh_port"], 11001)
        self.assertEqual(spec["container_id"], "vps-route-alice")
        self.assertEqual(spec["ssh_host"], "127.0.0.1")
        self.assertNotIn("password", spec)
        self.assertNotIn("private_key", spec)

    # ── B (HTTP): cross-user VPS id ──────────────────────────────────────────
    def test_route_cross_user_vps_forbidden(self):
        self.login(1)
        r = self.post_create(2)
        self.assertEqual(r.status_code, 403)
        self.assertIn("owned", r.get_json()["error"])

    # ── E (HTTP): another user cannot read or revoke the session ─────────────
    def test_route_session_isolation(self):
        self.login(1)
        r = self.post_create(1)
        sid = r.get_json()["id"]

        self.login(2)
        self.assertEqual(self.client.get(f"/api/sshx/session/{sid}").status_code, 404)
        r2 = self.client.post(f"/api/sshx/session/{sid}/revoke",
                              headers={"X-CSRF-Token": "test-csrf-token"})
        self.assertEqual(r2.status_code, 404)

        self.login(1)
        r = self.client.get(f"/api/sshx/session/{sid}")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(sshx.get_session(sid, 1)["status"], "active")
        # Owner polling is a heartbeat that keeps idle cleanup at bay.
        self.assertTrue(r.get_json()["authorized"])
        self.assertIn("last_seen", r.get_json())

    # ── Admin management: no credentials exposed ─────────────────────────────
    def test_admin_page_has_no_credentials(self):
        self.login(1)
        self.post_create(1)
        self.login(3)
        r = self.client.get("/admin/sshx")
        self.assertEqual(r.status_code, 200)
        body = r.get_data(as_text=True)
        self.assertNotIn(LINK, body)
        self.assertNotIn("id_ed25519", body)
        self.assertNotIn("known_hosts", body)
        self.assertIn("SSHX security management", body)

        # Admin can terminate somebody else's session.
        sid = sshx.list_sessions()[0]["id"]
        r = self.client.post("/admin/sshx", data={
            "csrf_token": "test-csrf-token", "action": "terminate", "session_id": sid,
        })
        self.assertEqual(r.status_code, 302)
        self.assertEqual(sshx.get_session(sid, 3, is_admin=True)["status"], "revoked")

    # ── Containment: fail closed over HTTP ────────────────────────────────────
    def test_route_containment_returns_maintenance(self):
        self.login(1)
        sshx.set_contained(True, actor_id=3, reason="test")
        r = self.post_create(1)
        self.assertEqual(r.status_code, 503)
        data = r.get_json()
        self.assertTrue(data["maintenance"])
        self.assertFalse(data["can_retry"])
        self.assertIn("maintenance", data["error"])
        self.assertEqual(sshx.list_sessions(), [])
        # Status endpoint still reports containment to an owner.
        sshx.set_policy(sshx.CONTAINED_POLICY, "0")
        created = self.post_create(1)
        self.assertEqual(created.status_code, 201)
        sid = created.get_json()["id"]

    # ── Admin: validation, containment and scoped revocation ─────────────────
    def test_admin_containment_and_revocation_controls(self):
        self.login(1)
        created = self.post_create(1)
        sid = created.get_json()["id"]

        # fresh installs start contained; set the flag without revoking the
        # session we just created so we can exercise the admin flow.
        sshx.set_policy(sshx.CONTAINED_POLICY, "1")

        self.login(3)
        # 1. Confirmation is mandatory.
        r = self.client.post("/admin/sshx", data={
            "csrf_token": "test-csrf-token", "action": "validate_and_enable",
        })
        self.assertEqual(r.status_code, 302)
        self.assertTrue(sshx.is_contained())

        # 2. Prerequisite failures keep containment enabled.
        with mock.patch.object(sshx, "verify_environment",
                               return_value=(False, ["gateway missing"])):
            r = self.client.post("/admin/sshx", data={
                "csrf_token": "test-csrf-token", "action": "validate_and_enable",
                "confirm": "1",
            })
        self.assertEqual(r.status_code, 302)
        self.assertTrue(sshx.is_contained())

        # 3. Confirmed + validated lifts containment and enables access.
        with mock.patch.object(sshx, "verify_environment", return_value=(True, [])):
            r = self.client.post("/admin/sshx", data={
                "csrf_token": "test-csrf-token", "action": "validate_and_enable",
                "confirm": "1",
            })
        self.assertEqual(r.status_code, 302)
        self.assertFalse(sshx.is_contained())
        self.assertTrue(sshx.is_globally_enabled())
        self.assertEqual(sshx.get_session(sid, 1)["status"], "active")

        # 4. Scoped revocation works without exposing other users' links.
        r = self.client.post("/admin/sshx", data={
            "csrf_token": "test-csrf-token", "action": "revoke_user", "user_id": "1",
        })
        self.assertEqual(r.status_code, 302)
        self.assertEqual(sshx.get_session(sid, 3, is_admin=True)["status"], "revoked")

        # 5. Global containment revokes everything again.
        self.login(1)
        other = self.post_create(1)
        self.login(3)
        self.client.post("/admin/sshx", data={
            "csrf_token": "test-csrf-token", "action": "contain",
        })
        self.assertTrue(sshx.is_contained())
        self.assertEqual(sshx.get_session(other.get_json()["id"], 3, True)["status"], "revoked")

    # ── Dashboard template never renders a one-time link or credentials ─────
    def test_dashboard_template_has_no_link_or_credentials(self):
        body = (REPO / "templates" / "dashboard.html").read_text()
        self.assertIn("sshx_contained", body)
        self.assertIn("Target VPS", body)
        self.assertIn("Assigned SSH port", body)
        self.assertNotIn(LINK, body)
        self.assertNotIn("id_ed25519", body)
        self.assertNotIn("known_hosts", body)
        # The destination comes from the server-rendered VPS record.
        self.assertIn("{{ vps.container_id }}", body)


if __name__ == "__main__":
    unittest.main(verbosity=2)
