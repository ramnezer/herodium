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

from modules.zram_manager import ZramManager  # noqa: E402


class ZramManagerTests(unittest.TestCase):
    def _manager(self, enabled=True):
        logger = Mock(spec=logging.Logger)
        config = {"performance": {"enable_zram": enabled}}
        return ZramManager(config, logger), logger

    def test_string_false_does_not_enable_zram(self):
        manager, _ = self._manager("false")
        self.assertFalse(manager.enabled)

    def test_swapon_output_detects_zram(self):
        manager, _ = self._manager()
        completed = SimpleNamespace(returncode=0, stdout="/dev/zram0\n", stderr="")
        with patch(
            "modules.zram_manager.system_tool_available", return_value=False
        ), patch(
            "modules.zram_manager.run_system_tool", return_value=completed
        ):
            self.assertTrue(manager._is_active())

    def test_unsupported_service_is_rejected(self):
        manager, logger = self._manager()
        manager.service_name = "attacker.service"
        self.assertFalse(manager._configure_zram())
        logger.error.assert_called_once()

    def test_enable_and_restart_must_both_succeed(self):
        manager, _ = self._manager()
        manager.service_name = "zramswap"
        results = [
            SimpleNamespace(returncode=0, stdout="", stderr=""),
            SimpleNamespace(returncode=1, stdout="", stderr="failed"),
        ]
        with patch(
            "modules.zram_manager.run_system_tool", side_effect=results
        ):
            self.assertFalse(manager._configure_zram())


if __name__ == "__main__":
    unittest.main()
