"""Tests that guest branding no longer fakes neofetch / OS identity."""

import sys
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
