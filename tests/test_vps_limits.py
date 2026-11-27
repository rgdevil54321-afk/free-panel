"""Tests for projecting recorded VPS plan limits into guest tooling."""

import io
import os
import shutil
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

import vps


class GuestLimitProjectionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="vps-limits-")
        self.root = os.path.join(self.tmp, "vps-test")
        os.makedirs(os.path.join(self.root, "etc"), exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_meminfo_is_scaled_to_recorded_limit(self):
        with mock.patch.object(vps, "_path", return_value=self.root):
            self.assertTrue(vps._write_guest_meminfo("vps-test", 16 * 1024))
        values = {}
        with open(os.path.join(self.root, "etc", "vps-meminfo")) as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2:
                    values[parts[0].rstrip(":")] = int(parts[1])
        expected_kb = 16 * 1024 * 1024
        self.assertGreater(values["MemTotal"], expected_kb * 0.99)
        self.assertLess(values["MemTotal"], expected_kb * 1.01)
        self.assertLessEqual(values["MemAvailable"], values["MemTotal"])

    def test_cpuinfo_is_truncated_to_recorded_cores(self):
        host_cpuinfo = "\n\n".join(
            f"processor\t: {i}\nmodel name\t: Test CPU @ 2.00GHz\n"
            for i in range(8)
        ) + "\n"
        real_open = open

        def fake_open(path, *args, **kwargs):
            if str(path) == "/proc/cpuinfo":
                return io.StringIO(host_cpuinfo)
            return real_open(path, *args, **kwargs)

        with mock.patch("builtins.open", side_effect=fake_open), \
             mock.patch.object(vps, "_path", return_value=self.root):
            self.assertTrue(vps._write_guest_cpuinfo("vps-test", 4))
        with open(os.path.join(self.root, "etc", "vps-cpuinfo")) as f:
            content = f.read()
        self.assertEqual(content.count("processor\t:"), 4)
        self.assertNotIn("processor\t: 7", content)

    def test_apply_guest_limits_writes_plan_and_projects_cpu(self):
        meta = {"cpu": 4, "ram_mb": 16 * 1024, "disk_gb": 80}
        with mock.patch.object(vps, "_path", return_value=self.root), \
             mock.patch.object(vps, "_load_meta", return_value=meta), \
             mock.patch.object(vps, "_is_mounted", return_value=True), \
             mock.patch.object(vps, "_apply_guest_meminfo", return_value=True), \
             mock.patch.object(vps, "_apply_guest_cpuinfo", return_value=True):
            result = vps.apply_guest_limits("vps-test")
        self.assertTrue(result["meminfo"])
        self.assertTrue(result["cpuinfo"])
        with open(os.path.join(self.root, "etc", "vps-limits")) as f:
            limits = f.read()
        self.assertIn("CPU_CORES=4", limits)
        self.assertIn("RAM_MB=16384", limits)
        self.assertIn("DISK_GB=80", limits)

    def test_apply_guest_limits_skips_stopped_vps(self):
        with mock.patch.object(vps, "_path", return_value=self.root), \
             mock.patch.object(vps, "_load_meta",
                               return_value={"ram_mb": 16 * 1024}), \
             mock.patch.object(vps, "_is_mounted", return_value=False):
            result = vps.apply_guest_limits("vps-test")
        self.assertFalse(result["meminfo"])
        self.assertFalse(result["cpuinfo"])
        self.assertFalse(result["proc"])

    def test_bind_mount_targets_existing_file(self):
        """makedirs() must not be called on an existing /proc/meminfo file."""
        source = os.path.join(self.tmp, "vps-meminfo")
        target = os.path.join(self.root, "proc", "meminfo")
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(source, "w") as f:
            f.write("MemTotal: 16384 kB\n")
        with open(target, "w") as f:
            f.write("MemTotal: 262144 kB\n")
        with mock.patch.object(vps, "_is_mounted", return_value=False), \
             mock.patch.object(vps, "_run",
                               return_value=mock.Mock(returncode=0)) as run:
            self.assertTrue(vps._mount_bind(source, target))
        self.assertEqual(run.call_args[0][0], ["mount", "--bind", source, target])

    def test_apply_all_reads_container_ids_from_db(self):
        db_path = os.path.join(self.tmp, "panel.db")
        db = sqlite3.connect(db_path)
        db.execute("CREATE TABLE vps(container_id TEXT)")
        db.execute("INSERT INTO vps VALUES('vps-test')")
        db.commit()
        db.close()
        with mock.patch.object(vps, "DB", db_path), \
             mock.patch.object(vps, "_load_meta",
                               return_value={"cpu": 4, "ram_mb": 16384,
                                             "disk_gb": 80}), \
             mock.patch.object(vps, "apply_guest_limits",
                               return_value={"meminfo": True, "cpuinfo": True}):
            self.assertEqual(vps.apply_guest_limits_to_all(), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
