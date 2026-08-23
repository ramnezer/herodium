import json
import unittest
from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[1]
INSTALLER = PROJECT_ROOT / "installer/install.sh"
LOCK = PROJECT_ROOT / "installer/supply-chain-lock.json"
FALCO_CONFIG = PROJECT_ROOT / "installer/falco/herodium-falco.yaml"
FALCO_RULES = PROJECT_ROOT / "installer/falco/herodium-falco-rules.yaml"
FALCO_LOGROTATE = PROJECT_ROOT / "installer/logrotate/herodium-falco"


class FalcoDeploymentSupplyChainTests(unittest.TestCase):
    def test_falco_supply_chain_is_exact_and_pinned(self):
        lock = json.loads(LOCK.read_text(encoding="utf-8"))

        self.assertEqual(lock["schema_version"], 2)
        self.assertEqual(
            lock["falco"],
            {
                "repository": "https://download.falco.org/packages/deb",
                "suite": "stable",
                "component": "main",
                "key_url": "https://falco.org/repo/falcosecurity-packages.asc",
                "trusted_fingerprint": (
                    "478B2FBBC75F4237B731DA4365106822B35B1B1F"
                ),
                "package_version": "0.44.1",
                "driver": "modern_ebpf",
            },
        )

    def test_installer_parser_rejects_unpinned_falco_supply_chain(self):
        content = INSTALLER.read_text(encoding="utf-8")

        self.assertIn(
            'falco_repository != "https://download.falco.org/packages/deb"',
            content,
        )
        self.assertIn(
            'falco_key_url != "https://falco.org/repo/falcosecurity-packages.asc"',
            content,
        )
        self.assertIn(
            'falco_fingerprint != "478B2FBBC75F4237B731DA4365106822B35B1B1F"',
            content,
        )
        self.assertIn('falco_driver != "modern_ebpf"', content)
        self.assertIn(
            'falco_package_version != "0.44.1"',
            content,
        )

    def test_installer_does_not_contain_remote_script_execution(self):
        content = INSTALLER.read_text(encoding="utf-8")

        self.assertNotIn("curl | bash", content)
        self.assertNotIn("curl | sh", content)
        self.assertNotIn("wget | bash", content)
        self.assertNotIn("wget | sh", content)


class FalcoDeploymentAssetTests(unittest.TestCase):
    def test_falco_output_override_is_jsonl_and_alert_only(self):
        config = yaml.safe_load(FALCO_CONFIG.read_text(encoding="utf-8"))

        self.assertTrue(config["json_output"])
        self.assertTrue(config["json_include_output_property"])
        self.assertTrue(config["json_include_output_fields_property"])
        self.assertTrue(config["json_include_tags_property"])
        self.assertTrue(config["time_format_iso_8601"])
        self.assertEqual(config["priority"], "error")
        self.assertEqual(
            config["file_output"],
            {
                "enabled": True,
                "keep_alive": False,
                "filename": "/var/log/herodium/falco-events.jsonl",
            },
        )
        self.assertNotIn("program_output", config)
        self.assertNotIn("http_output", config)

    def test_herodium_rules_are_high_signal_and_do_not_log_command_line(self):
        entries = yaml.safe_load(FALCO_RULES.read_text(encoding="utf-8"))

        self.assertIsInstance(entries, list)
        rules = [entry for entry in entries if "rule" in entry]
        macros = [entry for entry in entries if "macro" in entry]
        self.assertEqual(len(rules), 1)
        self.assertEqual(macros, [])
        rule = rules[0]
        self.assertEqual(rule["rule"], "Herodium Write To Systemd Unit Directory")
        self.assertEqual(rule["priority"], "ERROR")
        self.assertIn("herodium", rule["tags"])
        self.assertNotIn("proc.cmdline", rule["output"])
        self.assertNotIn("%evt.buffer", rule["output"])
        self.assertNotIn("evt.dir", rule["condition"])

    def test_high_signal_policy_avoids_scenario_specific_low_priority_tuning(self):
        config = yaml.safe_load(FALCO_CONFIG.read_text(encoding="utf-8"))
        entries = yaml.safe_load(FALCO_RULES.read_text(encoding="utf-8"))
        rendered = FALCO_RULES.read_text(encoding="utf-8")

        self.assertEqual(config["priority"], "error")
        self.assertNotIn("user_read_sensitive_file_conditions", rendered)
        self.assertNotIn("clamdscan", rendered)
        self.assertTrue(
            all(
                entry.get("priority") in {"ERROR", "CRITICAL", "ALERT", "EMERGENCY"}
                for entry in entries
                if "rule" in entry
            )
        )

    def test_logrotate_uses_rename_rotation_and_reopens_falco_output(self):
        content = FALCO_LOGROTATE.read_text(encoding="utf-8")

        self.assertIn("/var/log/herodium/falco-events.jsonl", content)
        self.assertIn("create 0600 root root", content)
        self.assertIn("maxsize 25M", content)
        self.assertIn("--signal=SIGUSR1 falco.service", content)
        self.assertNotIn("copytruncate", content)

    def test_deployment_assets_are_staged_through_verified_copy(self):
        content = INSTALLER.read_text(encoding="utf-8")

        for source, destination in (
            (
                '${REPO_DIR}/installer/falco/herodium-falco.yaml',
                "supply-chain/installer/falco/herodium-falco.yaml",
            ),
            (
                '${REPO_DIR}/installer/falco/herodium-falco-rules.yaml',
                "supply-chain/installer/falco/herodium-falco-rules.yaml",
            ),
            (
                '${REPO_DIR}/installer/logrotate/herodium-falco',
                "supply-chain/installer/logrotate/herodium-falco",
            ),
        ):
            self.assertIn(source, content)
            self.assertIn(destination, content)


if __name__ == "__main__":
    unittest.main()
