"""Tests for actionable Discord promotion-server diagnostics."""

import sys
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

import discord_integration as discord


class PromotionDiagnosticsTests(unittest.TestCase):
    def test_missing_bot_token_has_actionable_message(self):
        with mock.patch.object(discord, "_get_bot_token", return_value=""):
            ok, msg = discord.check_guild_access("123456789")
        self.assertFalse(ok)
        self.assertIn("No bot token", msg)

    def test_forbidden_guild_explains_bot_membership(self):
        response = mock.Mock(status_code=403)
        with mock.patch.object(discord, "_get_bot_token", return_value="bot-token"), \
             mock.patch.object(discord.requests, "get", return_value=response):
            ok, msg = discord.check_guild_access("123456789")
        self.assertFalse(ok)
        self.assertIn("not in this server", msg)

    def test_connected_guild_returns_name(self):
        response = mock.Mock(status_code=200)
        response.json.return_value = {"name": "Promo Server"}
        with mock.patch.object(discord, "_get_bot_token", return_value="bot-token"), \
             mock.patch.object(discord.requests, "get", return_value=response):
            ok, msg = discord.check_guild_access("123456789")
        self.assertTrue(ok)
        self.assertIn("Promo Server", msg)


if __name__ == "__main__":
    unittest.main(verbosity=2)
