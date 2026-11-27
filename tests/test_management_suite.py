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


class ServiceRestartTests(unittest.TestCase):
    """Regression tests for the duplicate restart that broke --update."""

    def test_only_start_panel_restarts_the_panel(self):
        src = (REPO / "installer.py").read_text()
        start = src.index("    def start_panel(self, port: int) -> bool:")
        end = src.index("    def start_cloudflare(", start)
        outside = src[:start] + src[end:]
        self.assertNotIn('"systemctl", "restart", SERVICE', outside)

    def test_start_panel_restarts_once_and_accepts_redirect(self):
        mgr = installer.ServiceManager(mock.Mock())
        calls = []
        result = mock.Mock(returncode=0, stdout="active\n", stderr="")

        def fake_run(cmd, **kwargs):
            calls.append(cmd)
            return result

        response = mock.MagicMock()
        response.status = 301
        response.__enter__.return_value = response
        with mock.patch.object(installer.subprocess, "run", side_effect=fake_run), \
             mock.patch.object(installer.urllib.request, "urlopen",
                               return_value=response), \
             mock.patch.object(installer.time, "sleep"):
            self.assertTrue(mgr.start_panel(5000))
        restarts = [c for c in calls if c[:2] == ["systemctl", "restart"]]
        self.assertEqual(len(restarts), 1)
        self.assertTrue(any(c[:2] == ["systemctl", "reset-failed"] for c in calls))

    def test_health_check_failure_reports_service_state(self):
        mgr = installer.ServiceManager(log := mock.Mock())
        result = mock.Mock(returncode=0, stdout="failed\n", stderr="")

        def fake_run(cmd, **kwargs):
            return result

        with mock.patch.object(installer.subprocess, "run", side_effect=fake_run), \
             mock.patch.object(installer.urllib.request, "urlopen",
                               side_effect=OSError("refused")), \
             mock.patch.object(installer.time, "sleep"):
            self.assertFalse(mgr.start_panel(5000))
        logged = " ".join(str(c) for c in log.error.call_args_list)
        self.assertIn("service state: failed", logged)


if __name__ == "__main__":
    unittest.main(verbosity=2)
