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

from modules.performance_manager import PerformanceManager  # noqa: E402


class PerformanceManagerTests(unittest.TestCase):
    def _manager(self, percent=30):
        logger = Mock(spec=logging.Logger)
        config = {"performance": {"cpu_limit_percent": percent}}
        return PerformanceManager(config, logger, Mock()), logger

    def test_cpu_limit_is_bounded(self):
        manager, _ = self._manager(500)
        self.assertEqual(manager.cap_machine_percent, 100)

    def test_failed_quota_application_is_not_persisted(self):
        manager, logger = self._manager()
        process = Mock()
        process.pid = 123
        process.nice.return_value = 0
        process.ionice.return_value = SimpleNamespace(ioclass=2, value=4)
        failed = SimpleNamespace(returncode=1, stdout="", stderr="failed")

        with patch("modules.performance_manager.psutil.Process", return_value=process), patch(
            "modules.performance_manager.run_system_tool", return_value=failed
        ):
            result = manager._apply_limit(120, 123)

        self.assertFalse(result)
        self.assertIsNone(manager.current_limit_value)
        logger.error.assert_called_with("Unable to apply ClamAV CPUQuota.")

    def test_successful_limit_records_quota(self):
        manager, _ = self._manager()
        process = Mock()
        process.pid = 123
        process.nice.return_value = 0
        process.ionice.return_value = SimpleNamespace(ioclass=2, value=4)
        completed = SimpleNamespace(returncode=0, stdout="", stderr="")

        with patch("modules.performance_manager.psutil.Process", return_value=process), patch(
            "modules.performance_manager.run_system_tool", return_value=completed
        ):
            result = manager._apply_limit(120, 123)

        self.assertTrue(result)
        self.assertEqual(manager.current_limit_value, 120)
        process.nice.assert_any_call(19)

    def test_failed_release_keeps_known_limit(self):
        manager, _ = self._manager()
        manager.current_limit_value = 120
        manager._restore_original_priority = Mock(return_value=True)
        failed = SimpleNamespace(returncode=1, stdout="", stderr="failed")

        with patch(
            "modules.performance_manager.run_system_tool", return_value=failed
        ):
            result = manager._remove_limit()

        self.assertFalse(result)
        self.assertEqual(manager.current_limit_value, 120)


if __name__ == "__main__":
    unittest.main()
