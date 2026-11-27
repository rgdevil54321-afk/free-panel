"""Tests for projecting recorded VPS RAM limits into guest tooling."""

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


class GuestRamProjectionTests(unittest.TestCase):
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

    def test_apply_guest_limits_skips_stopped_vps(self):
        with mock.patch.object(vps, "_path", return_value=self.root), \
             mock.patch.object(vps, "_load_meta",
                               return_value={"ram_mb": 16 * 1024}), \
             mock.patch.object(vps, "_is_mounted", return_value=False):
            result = vps.apply_guest_limits("vps-test")
        self.assertFalse(result["meminfo"])
        self.assertFalse(result["proc"])

    def test_apply_all_reads_container_ids_from_db(self):
        db_path = os.path.join(self.tmp, "panel.db")
        db = sqlite3.connect(db_path)
        db.execute("CREATE TABLE vps(container_id TEXT)")
        db.execute("INSERT INTO vps VALUES('vps-test')")
        db.commit()
        db.close()
        with mock.patch.object(vps, "DB", db_path), \
             mock.patch.object(vps, "apply_guest_limits",
                               return_value={"meminfo": True}):
            self.assertEqual(vps.apply_guest_limits_to_all(), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
