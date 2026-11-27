"""Tests that guest branding no longer fakes neofetch / OS identity."""

import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

import brand


class NaturalNeofetchTests(unittest.TestCase):
    def test_brand_script_removes_fake_fetch_wrappers(self):
        src = (REPO / "brand.py").read_text()
        self.assertNotIn("cat > /usr/local/bin/neofetch", src)
        self.assertNotIn("Venlix Nodes Cloud", src)
        self.assertNotIn("Virtual CPU (isolated)", src)
        self.assertIn("rm -f /usr/local/bin/neofetch", src)

    def test_brand_script_restores_ubuntu_identity(self):
        src = (REPO / "brand.py").read_text()
        self.assertNotIn('PRETTY_NAME="Venlix', src)
        self.assertIn('PRETTY_NAME="Ubuntu 24.04 LTS"', src)
        self.assertIn('NAME="Ubuntu"', src)


class ExistingGuestCleanupTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="brand-test-")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    @staticmethod
    def _make_guest(root, fake_fetch=True):
        os.makedirs(os.path.join(root, "etc"), exist_ok=True)
        if fake_fetch:
            os.makedirs(os.path.join(root, "usr", "local", "bin"), exist_ok=True)
            with open(os.path.join(root, "usr", "local", "bin", "neofetch"), "w") as f:
                f.write('echo "OS: Venlix Nodes VPS"\n')
        with open(os.path.join(root, "etc", "os-release"), "w") as f:
            f.write('NAME="Venlix Nodes VPS"\n'
                    'PRETTY_NAME="Venlix Nodes VPS (Ubuntu-based)"\n'
                    'ID=ubuntu\n')
        with open(os.path.join(root, "etc", "issue"), "w") as f:
            f.write("Venlix Nodes VPS\n")
        with open(os.path.join(root, "etc", "motd"), "w") as f:
            f.write("Welcome to Venlix Nodes VPS\n")

    def test_clean_guest_root_removes_fake_wrapper_and_identity(self):
        guest = os.path.join(self.tmp, "vps-test")
        self._make_guest(guest)
        self.assertTrue(brand.clean_guest_root(guest))
        self.assertFalse(os.path.exists(
            os.path.join(guest, "usr", "local", "bin", "neofetch")))
        with open(os.path.join(guest, "etc", "os-release")) as f:
            release = f.read()
        self.assertIn('NAME="Ubuntu"', release)
        self.assertIn('PRETTY_NAME="Ubuntu 24.04 LTS"', release)
        self.assertIn("ID=ubuntu", release)
        with open(os.path.join(guest, "etc", "issue")) as f:
            self.assertIn("Ubuntu", f.read())
        self.assertFalse(os.path.exists(os.path.join(guest, "etc", "motd")))

    def test_clean_existing_guests_covers_base_and_all_vpses(self):
        self._make_guest(os.path.join(self.tmp, "base"))
        self._make_guest(os.path.join(self.tmp, "vps-aaaaaa"))
        self._make_guest(os.path.join(self.tmp, "vps-bbbbbb"))
        os.makedirs(os.path.join(self.tmp, "meta"), exist_ok=True)

        cleaned, total, installed = brand.clean_existing_guests(
            self.tmp, install_fetch=False)
        self.assertEqual(total, 3)
        self.assertEqual(cleaned, 3)
        self.assertEqual(installed, 0)
        for name in ("base", "vps-aaaaaa", "vps-bbbbbb"):
            self.assertFalse(os.path.exists(os.path.join(
                self.tmp, name, "usr", "local", "bin", "neofetch")))

    def test_real_fetch_is_copied_from_base_without_apt(self):
        base = os.path.join(self.tmp, "base")
        guest = os.path.join(self.tmp, "vps-cccccc")
        os.makedirs(os.path.join(base, "usr", "bin"), exist_ok=True)
        os.makedirs(os.path.join(guest, "usr"), exist_ok=True)
        with open(os.path.join(base, "usr", "bin", "neofetch"), "w") as f:
            f.write("#!/bin/bash\necho real neofetch\n")
        self.assertTrue(brand.copy_fetch_from_base(base, guest))
        self.assertTrue(brand._has_real_fetch(guest))

    def test_update_and_repair_both_clean_guest_identity(self):
        src = (REPO / "installer.py").read_text()
        self.assertGreaterEqual(src.count("self._clean_guest_identity("), 2)
        self.assertIn("self._clean_guest_identity(install_fetch=False)", src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
