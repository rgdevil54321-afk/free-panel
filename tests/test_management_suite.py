"""Tests for the restored Management Suite CLI and safe installer config.

These tests use a temporary directory and never touch a real installation,
systemd unit, /usr/local/bin, or customer data.
"""

import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

import installer
import management_suite


class ManagementSuiteTests(unittest.TestCase):
    def test_menu_restores_all_original_15_actions(self):
        expected = {
            "1": "install", "2": "reinstall", "3": "update", "4": "start",
            "5": "stop", "6": "restart", "7": "status", "8": "logs",
            "9": "reset-admin", "10": "port", "11": "backup", "12": "restore",
            "13": "uninstall", "14": "shell", "15": "cloudflare",
        }
        self.assertEqual(
            {k: mode for k, (mode, _) in management_suite.ACTION_MODES.items()},
            expected,
        )

    def test_every_menu_action_delegates_to_installer(self):
        src = (REPO / "installer.py").read_text()
        for mode, _ in management_suite.ACTION_MODES.values():
            if mode == "shell":
                continue
            self.assertIn(f'"{mode}"', src, f"mode {mode} is not implemented")
        # The menu must not reimplement backend actions itself.
        suite_src = (REPO / "management_suite.py").read_text()
        self.assertIn("Installer(mode=mode", suite_src)
        self.assertNotIn("subprocess.run([\"apt", suite_src)


class InstallerConfigTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="installer-test-")
        self.repo = os.path.join(self.tmp, "repo")
        os.makedirs(self.repo)
        self.log = mock.Mock()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_write_config_preserves_existing_operator_settings(self):
        env_path = os.path.join(self.repo, ".env")
        with open(env_path, "w", encoding="utf-8") as f:
            f.write(
                "# operator config\n"
                "PANEL_PORT=8443\n"
                "TRUST_PROXY=1\n"
                "CLOUDFLARE_TOKEN=eyJcustom\n"
                "MY_CUSTOM_KEY=keep-me\n"
            )
        with mock.patch.object(installer, "REPO_DIR", self.repo):
            mgr = installer.ConfigManager(self.log, {})
            self.assertTrue(mgr.write_config(5000))
        with open(env_path, "r", encoding="utf-8") as f:
            content = f.read()
        for preserved in ("PANEL_PORT=8443", "TRUST_PROXY=1",
                          "CLOUDFLARE_TOKEN=eyJcustom", "MY_CUSTOM_KEY=keep-me"):
            self.assertIn(preserved, content)
        for added in ("SSHX_GATEWAY_USER=sshx-gw", "SSHX_SESSION_TTL=900"):
            self.assertIn(added, content)
        self.assertNotIn("PANEL_PORT=5000", content)

    def test_write_config_fresh_install_adds_secure_defaults(self):
        with mock.patch.object(installer, "REPO_DIR", self.repo):
            mgr = installer.ConfigManager(self.log, {})
            self.assertTrue(mgr.write_config(5000))
        with open(os.path.join(self.repo, ".env"), "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("PANEL_PORT=5000", content)
        self.assertIn("TRUST_PROXY=0", content)
        self.assertIn("SSHX_GATEWAY_USER=sshx-gw", content)
        self.assertIn("SSHX_MAX_PER_VPS=1", content)

    def test_install_cli_creates_root_executable_wrapper(self):
        source = os.path.join(self.repo, "management_suite.py")
        with open(source, "w", encoding="utf-8") as f:
            f.write("# restored menu\n")
        target = os.path.join(self.tmp, "panel")
        with mock.patch.object(installer, "REPO_DIR", self.repo), \
             mock.patch.object(installer, "CLI_PATH", target):
            mgr = installer.ConfigManager(self.log, {})
            self.assertTrue(mgr.install_cli())
        self.assertTrue(os.path.isfile(target))
        with open(target, "r", encoding="utf-8") as f:
            wrapper = f.read()
        self.assertIn(source, wrapper)
        self.assertIn('exec "', wrapper)
        self.assertEqual(os.stat(target).st_mode & 0o777, 0o755)


class InstallerSafetyTests(unittest.TestCase):
    def test_service_check_uses_systemctl_is_active(self):
        src = (REPO / "installer.py").read_text()
        self.assertIn("def is_active(self)", src)
        self.assertIn('"systemctl", "is-active", "--quiet", SERVICE', src)

    def test_all_install_paths_restore_management_cli(self):
        src = (REPO / "installer.py").read_text()
        # install, reinstall, update, repair and repair_panel
        self.assertGreaterEqual(src.count("self.config_mgr.install_cli()"), 5)

    def test_systemd_unit_loads_env_file(self):
        src = (REPO / "installer.py").read_text()
        self.assertIn("EnvironmentFile=-{repo_dir}/.env", src)
        # Explicit settings below EnvironmentFile must not be overridden by it.
        self.assertLess(
            src.index("EnvironmentFile=-{repo_dir}/.env"),
            src.index("Environment=PANEL_PORT={port}"),
        )

    def test_sshx_session_root_is_traversable_by_gateway(self):
        src = (REPO / "installer.py").read_text()
        self.assertIn("self.HOME, self.SESSION_ROOT,", src)

    def test_sshx_migrations_are_additive_only(self):
        src = (REPO / "sshx_manager.py").read_text()
        self.assertNotIn("DROP TABLE", src)
        self.assertNotIn("DELETE FROM users", src)
        self.assertNotIn("DELETE FROM vps", src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
