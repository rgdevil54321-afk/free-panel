"""Tests that guest branding no longer fakes neofetch / OS identity."""

import os
import shutil
import subprocess
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


class ResourceShimTests(unittest.TestCase):
    """Guest df/nproc shims must report the recorded plan, not host totals."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="shim-test-")
        self.limits = os.path.join(self.tmp, "vps-limits")
        with open(self.limits, "w") as f:
            f.write("CPU_CORES=4\nRAM_MB=16384\nDISK_GB=80\n")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run_shim(self, script: str, *args: str):
        path = os.path.join(self.tmp, "shim")
        with open(path, "w") as f:
            f.write(script)
        return subprocess.run(["sh", path, *args],
                              capture_output=True, text=True, timeout=15)

    def test_shims_are_valid_shell(self):
        for script in (brand.DF_SHIM, brand.NPROC_SHIM):
            path = os.path.join(self.tmp, "syntax")
            with open(path, "w") as f:
                f.write(script)
            result = subprocess.run(["sh", "-n", path],
                                    capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_install_resource_shims_is_idempotent(self):
        root = os.path.join(self.tmp, "guest")
        self.assertTrue(brand.install_resource_shims(root))
        for rel in ("usr/local/bin/df", "usr/local/bin/nproc"):
            path = os.path.join(root, rel)
            self.assertTrue(os.path.isfile(path))
            self.assertTrue(os.access(path, os.X_OK))
        self.assertFalse(brand.install_resource_shims(root))

    def test_canonical_df_is_backed_up_then_shimmed(self):
        root = os.path.join(self.tmp, "guest")
        real = os.path.join(root, "usr", "bin", "df")
        os.makedirs(os.path.dirname(real), exist_ok=True)
        with open(real, "w") as f:
            f.write("REAL COREUTILS DF\n")
        self.assertTrue(brand.install_resource_shims(root))
        with open(real) as f:
            self.assertEqual(f.read(), brand.DF_SHIM)
        with open(real + ".real") as f:
            self.assertEqual(f.read(), "REAL COREUTILS DF\n")
        self.assertFalse(brand.install_resource_shims(root))

    def test_df_shim_rewrites_only_root_row(self):
        fake_df = os.path.join(self.tmp, "real-df")
        with open(fake_df, "w") as f:
            f.write("#!/bin/sh\n"
                    "printf '%s\\n' "
                    "'Filesystem Size Used Avail Use% Mounted on' "
                    "'/dev/root 967G 25G 943G 3% /' "
                    "'tmpfs 126G 0 126G 0% /dev'\n")
        os.chmod(fake_df, 0o755)
        script = (brand.DF_SHIM
                  .replace("/usr/bin/df", fake_df)
                  .replace("/etc/vps-limits", self.limits))
        result = self._run_shim(script, "-P", "-h", "/")
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = result.stdout.splitlines()
        self.assertIn("80G", lines[1])
        self.assertNotIn("967G", result.stdout)
        self.assertIn("126G", result.stdout)

    def test_df_shim_handles_cpuinfo_mount_label(self):
        """The CPU bind mount makes df label the root row /proc/cpuinfo."""
        fake_df = os.path.join(self.tmp, "real-df")
        with open(fake_df, "w") as f:
            f.write("#!/bin/sh\n"
                    "printf '%s\\n' "
                    "'Filesystem Size Used Avail Use% Mounted on' "
                    "'/dev/sda1 968G 19G 949G 2% /proc/cpuinfo'\n")
        os.chmod(fake_df, 0o755)
        script = (brand.DF_SHIM
                  .replace("/usr/bin/df", fake_df)
                  .replace("/etc/vps-limits", self.limits))
        result = self._run_shim(script, "-P", "-h", "/")
        self.assertEqual(result.returncode, 0, result.stderr)
        line = result.stdout.splitlines()[1]
        self.assertIn("80G", line)
        self.assertTrue(line.endswith(" /"), line)
        self.assertNotIn("968G", result.stdout)

    def test_nproc_shim_reports_plan_cores(self):
        script = brand.NPROC_SHIM.replace("/etc/vps-limits", self.limits)
        result = self._run_shim(script)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "4")


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
