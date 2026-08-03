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

from modules.rkhunter_manager import RkhunterCommandResult  # noqa: E402
from modules.scheduler import TaskScheduler  # noqa: E402


class TaskSchedulerRkhunterTests(unittest.TestCase):
    def _scheduler(self):
        config = {
            "scheduler": {
                "enable": True,
                "rkhunter_interval_hours": 24,
                "home_scan_interval_hours": 0,
                "full_scan_interval_hours": 0,
                "update_interval_hours": 24,
            }
        }
        logger = Mock(spec=logging.Logger)
        with patch("modules.scheduler.Notifier"), patch(
            "modules.scheduler.RkhunterManager"
        ):
            scheduler = TaskScheduler(config, logger)
        scheduler.notifier = Mock()
        scheduler.rkhunter = Mock()
        return scheduler, logger

    def test_scheduled_updates_never_update_properties_baseline(self):
        scheduler, _ = self._scheduler()
        scheduler._run_system_tool = Mock(
            return_value=SimpleNamespace(returncode=0)
        )
        scheduler.rkhunter.available.return_value = True
        scheduler.rkhunter.update_data.return_value = RkhunterCommandResult(
            operation="update",
            returncode=0,
        )

        result = scheduler._run_updates()

        self.assertTrue(result)
        scheduler.rkhunter.update_data.assert_called_once_with()
        scheduler.rkhunter.update_properties.assert_not_called()
        scheduler.rkhunter.review_then_update_properties.assert_not_called()

    def test_rkhunter_warning_is_reported_and_not_trusted(self):
        scheduler, logger = self._scheduler()
        scheduler.rkhunter.check.return_value = RkhunterCommandResult(
            operation="check",
            returncode=1,
            stdout="File properties have changed",
        )

        result = scheduler._run_rkhunter()

        self.assertTrue(result)
        logger.warning.assert_called_once()
        scheduler.notifier.send_notification.assert_called_once()
        scheduler.rkhunter.update_properties.assert_not_called()

    def test_rkhunter_execution_error_is_not_reported_clean(self):
        scheduler, logger = self._scheduler()
        scheduler.rkhunter.check.return_value = RkhunterCommandResult(
            operation="check",
            returncode=127,
            stderr="executable unavailable",
        )

        result = scheduler._run_rkhunter()

        self.assertFalse(result)
        self.assertFalse(
            any("scan clean" in str(call).lower() for call in logger.info.call_args_list)
        )
        logger.error.assert_called_once()

    def test_scheduler_start_is_idempotent(self):
        scheduler, _ = self._scheduler()
        scheduler._loop = lambda: scheduler.stop_event.wait(1)

        first = scheduler.start()
        second = scheduler.start()
        scheduler.stop()

        self.assertTrue(first)
        self.assertTrue(second)


if __name__ == "__main__":
    unittest.main()
