import logging
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch


PROJECT_ROOT = Path(__file__).resolve().parents[1]
HERODIUM_ROOT = PROJECT_ROOT / "herodium"
if str(HERODIUM_ROOT) not in sys.path:
    sys.path.insert(0, str(HERODIUM_ROOT))

from modules.sys_hardener import SystemHardener  # noqa: E402


class SystemHardenerTests(unittest.TestCase):
    def _hardener(self):
        logger = Mock(spec=logging.Logger)
        config = {
            "hardening": {
                "enable": True,
                "rules": {"net.ipv4.tcp_syncookies": 1},
            }
        }
        return SystemHardener(config, logger), logger

    def test_invalid_key_is_rejected_without_execution(self):
        hardener, _ = self._hardener()
        with patch("modules.sys_hardener.run_system_tool") as run_mock:
            self.assertFalse(hardener._set_sysctl("net.ipv4.x;id", 1))
        run_mock.assert_not_called()

    def test_successful_rule_application_returns_true(self):
        hardener, _ = self._hardener()
        completed = SimpleNamespace(returncode=0, stdout="ok", stderr="")
        with patch(
            "modules.sys_hardener.run_system_tool", return_value=completed
        ):
            self.assertTrue(hardener.apply_security_rules())

    def test_failed_rule_application_returns_false(self):
        hardener, logger = self._hardener()
        completed = SimpleNamespace(returncode=1, stdout="", stderr="denied")
        with patch(
            "modules.sys_hardener.run_system_tool", return_value=completed
        ):
            self.assertFalse(hardener.apply_security_rules())
        logger.warning.assert_called_once()


if __name__ == "__main__":
    unittest.main()
