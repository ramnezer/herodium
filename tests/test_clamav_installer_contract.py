import unittest
from pathlib import Path

import yaml


PROJECT_ROOT = Path(__file__).resolve().parents[1]
INSTALLER = PROJECT_ROOT / "installer/install.sh"
CONFIG = PROJECT_ROOT / "herodium/config/herodium.yaml"


class ClamAVInstallerContractTests(unittest.TestCase):
    def test_private_temp_directory_is_configured_before_daemon_start(self):
        content = INSTALLER.read_text(encoding="utf-8")
        function = content.split(
            "configure_clamav_transactionally() {", 1
        )[1].split(
            "# ==============================================================================\n"
            "# MAIN INSTALLATION LOGIC", 1
        )[0]

        variable = function.index(
            'CLAMAV_TEMP_DIR="/var/lib/clamav/herodium-tmp"'
        )
        configuration = function.index(
            'set_clamd_option "TemporaryDirectory" "${CLAMAV_TEMP_DIR}"'
        )
        directory = function.index(
            'install -d -o clamav -g clamav -m 0700 "${CLAMAV_TEMP_DIR}"'
        )
        daemon_start = function.index("systemctl start clamav-daemon")

        self.assertLess(variable, configuration)
        self.assertLess(configuration, directory)
        self.assertLess(directory, daemon_start)

    def test_runtime_config_matches_installer_temp_directory(self):
        config = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))

        self.assertEqual(
            config["clamav"]["temporary_directory"],
            "/var/lib/clamav/herodium-tmp",
        )
        self.assertIn(
            "/var/lib/clamav",
            config["directories"]["ignore_prefixes"],
        )


if __name__ == "__main__":
    unittest.main()
