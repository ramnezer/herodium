import unittest

from herodium.core.config_migrations import (
    HARDENED_MEMORY_HUNTER_DEFAULT_WHITELIST,
    migrate_memory_hunter_whitelist,
)


class MemoryHunterConfigMigrationTests(unittest.TestCase):
    def test_current_legacy_default_is_migrated(self):
        config = {
            "memory_scan": {
                "whitelist": [
                    "chrome",
                    "firefox",
                    "code",
                    "gnome-shell",
                    "systemd",
                ]
            }
        }

        self.assertTrue(migrate_memory_hunter_whitelist(config))
        self.assertEqual(
            config["memory_scan"]["whitelist"],
            list(HARDENED_MEMORY_HUNTER_DEFAULT_WHITELIST),
        )

    def test_historical_legacy_default_is_migrated(self):
        config = {
            "memory_scan": {
                "whitelist": [
                    "systemd-journald",
                    "init",
                    "systemd",
                    "clamd",
                    "gnome-shell",
                    "code",
                    "firefox",
                    "chrome",
                ]
            }
        }

        self.assertTrue(migrate_memory_hunter_whitelist(config))
        self.assertEqual(
            config["memory_scan"]["whitelist"],
            list(HARDENED_MEMORY_HUNTER_DEFAULT_WHITELIST),
        )

    def test_custom_absolute_whitelist_is_preserved(self):
        original = ["/usr/local/sbin/operator-tool", "/usr/bin/gnome-shell"]
        config = {"memory_scan": {"whitelist": list(original)}}

        self.assertFalse(migrate_memory_hunter_whitelist(config))
        self.assertEqual(config["memory_scan"]["whitelist"], original)

    def test_mixed_custom_and_legacy_names_are_not_guessed(self):
        original = ["firefox", "/usr/local/sbin/operator-tool"]
        config = {"memory_scan": {"whitelist": list(original)}}

        self.assertFalse(migrate_memory_hunter_whitelist(config))
        self.assertEqual(config["memory_scan"]["whitelist"], original)

    def test_malformed_whitelist_is_preserved_fail_closed(self):
        config = {"memory_scan": {"whitelist": "firefox"}}

        self.assertFalse(migrate_memory_hunter_whitelist(config))
        self.assertEqual(config["memory_scan"]["whitelist"], "firefox")


if __name__ == "__main__":
    unittest.main()
