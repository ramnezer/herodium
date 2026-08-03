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

from modules.ips_manager import IPSManager  # noqa: E402


class IPSManagerTests(unittest.TestCase):
    def _manager(self, enabled=True):
        logger = Mock(spec=logging.Logger)
        config = {"ips": {"enable": enabled}}
        return IPSManager(config, logger), logger

    def test_string_false_does_not_enable_ips(self):
        manager, _ = self._manager("false")
        self.assertFalse(manager.enabled)

    def test_start_reports_success_after_verified_ping(self):
        manager, logger = self._manager()
        results = [
            SimpleNamespace(returncode=0, stdout="", stderr=""),
            SimpleNamespace(returncode=0, stdout="", stderr=""),
            SimpleNamespace(returncode=0, stdout="Server replied: pong\n", stderr=""),
        ]
        with patch(
            "modules.ips_manager.system_tool_available", return_value=True
        ), patch.object(
            manager, "_has_existing_herodium_jail", return_value=True
        ), patch(
            "modules.ips_manager.run_system_tool", side_effect=results
        ), patch("modules.ips_manager.time.sleep"):
            self.assertTrue(manager.start())

        logger.info.assert_any_call(
            "IPS Active: SSH Brute-Force Protection Enabled."
        )

    def test_restart_failure_is_not_reported_healthy(self):
        manager, logger = self._manager()
        results = [
            SimpleNamespace(returncode=0, stdout="", stderr=""),
            SimpleNamespace(returncode=1, stdout="", stderr="failed"),
        ]
        with patch(
            "modules.ips_manager.system_tool_available", return_value=True
        ), patch.object(
            manager, "_has_existing_herodium_jail", return_value=True
        ), patch(
            "modules.ips_manager.run_system_tool", side_effect=results
        ):
            self.assertFalse(manager.start())

        logger.error.assert_called_with("Could not restart Fail2Ban service.")


if __name__ == "__main__":
    unittest.main()
