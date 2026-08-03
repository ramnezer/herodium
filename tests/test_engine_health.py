import logging
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock


PROJECT_ROOT = Path(__file__).resolve().parents[1]
HERODIUM_ROOT = PROJECT_ROOT / "herodium"
if str(HERODIUM_ROOT) not in sys.path:
    sys.path.insert(0, str(HERODIUM_ROOT))

from core.health import (  # noqa: E402
    ComponentState,
    StartupHealthManager,
    SystemHealth,
)


class StartupHealthManagerTests(unittest.TestCase):
    def _manager(self, *, clamav=True, apparmor=True):
        logger = Mock(spec=logging.Logger)
        notifier = Mock()
        config = {
            "performance": {"enable_zram": False},
            "ips": {"enable": False},
            "hardening": {"enable": False},
            "scheduler": {"enable": False},
        }

        scanner = Mock()
        scanner.health_check.return_value = clamav
        zram_manager = Mock()
        apparmor_manager = Mock()
        apparmor_manager.apply_policy.return_value = apparmor
        ips_manager = Mock()
        hardener = Mock()
        scheduler = Mock()
        network_monitor = Mock()
        performance_manager = Mock()
        filesystem_monitor = Mock()
        filesystem_monitor.run.return_value = True
        start_memory_hunter = Mock(return_value=True)

        manager = StartupHealthManager(
            config=config,
            logger=logger,
            scanner=scanner,
            zram_manager=zram_manager,
            apparmor_manager=apparmor_manager,
            ips_manager=ips_manager,
            hardener=hardener,
            scheduler=scheduler,
            network_monitor=network_monitor,
            performance_manager=performance_manager,
            filesystem_monitor=filesystem_monitor,
            start_memory_hunter=start_memory_hunter,
        )
        return manager, notifier

    def test_clamav_failure_is_failed_and_short_circuits_startup(self):
        manager, _ = self._manager(clamav=False)

        report = manager.collect(
            live_monitor_enabled=False,
            maltrail_enabled=False,
        )

        self.assertIs(report.state, SystemHealth.FAILED)
        self.assertIs(
            report.component("clamav").state,
            ComponentState.FAILED,
        )
        manager.apparmor_manager.apply_policy.assert_not_called()
        manager.performance_manager.start.assert_not_called()

    def test_disabled_optional_components_allow_protected_state(self):
        manager, _ = self._manager()

        report = manager.collect(
            live_monitor_enabled=False,
            maltrail_enabled=False,
        )

        self.assertIs(report.state, SystemHealth.PROTECTED)
        self.assertIs(
            report.component("filesystem_monitor").state,
            ComponentState.DISABLED_BY_POLICY,
        )
        self.assertIs(
            report.component("memory_hunter").state,
            ComponentState.DISABLED_BY_POLICY,
        )

    def test_apparmor_failure_degrades_but_does_not_fail(self):
        manager, _ = self._manager(apparmor=False)

        report = manager.collect(
            live_monitor_enabled=False,
            maltrail_enabled=False,
        )

        self.assertIs(report.state, SystemHealth.DEGRADED)
        self.assertIs(
            report.component("apparmor").state,
            ComponentState.DEGRADED,
        )

    def test_enabled_maltrail_failure_degrades_system(self):
        manager, _ = self._manager()
        manager.network_monitor.start_monitoring.return_value = False

        report = manager.collect(
            live_monitor_enabled=False,
            maltrail_enabled=True,
        )

        self.assertIs(report.state, SystemHealth.DEGRADED)
        self.assertIs(
            report.component("maltrail").state,
            ComponentState.DEGRADED,
        )

    def test_filesystem_failure_makes_enabled_live_monitor_failed(self):
        manager, _ = self._manager()
        manager.filesystem_monitor.run.return_value = False

        report = manager.collect(
            live_monitor_enabled=True,
            maltrail_enabled=False,
        )

        self.assertIs(report.state, SystemHealth.FAILED)
        self.assertIs(
            report.component("filesystem_monitor").state,
            ComponentState.FAILED,
        )
        self.assertIs(
            report.component("memory_hunter").state,
            ComponentState.FAILED,
        )
        manager.start_memory_hunter.assert_not_called()

    def test_enabled_live_monitor_is_protected_when_threads_start(self):
        manager, _ = self._manager()

        report = manager.collect(
            live_monitor_enabled=True,
            maltrail_enabled=False,
        )

        self.assertIs(report.state, SystemHealth.PROTECTED)
        self.assertIs(
            report.component("filesystem_monitor").state,
            ComponentState.HEALTHY,
        )
        self.assertIs(
            report.component("memory_hunter").state,
            ComponentState.HEALTHY,
        )

    def test_failed_report_never_emits_protected_notification(self):
        manager, notifier = self._manager(clamav=False)
        report = manager.collect(
            live_monitor_enabled=False,
            maltrail_enabled=False,
        )

        manager.emit(report, notifier)

        protected_message = "System is PROTECTED. Monitoring active..."
        logged_messages = [
            call.args[0]
            for call in manager.logger.info.call_args_list
            if call.args
        ]
        self.assertNotIn(protected_message, logged_messages)
        manager.logger.critical.assert_called_once()
        notifier.send_notification.assert_called_once()
        notification = notifier.send_notification.call_args.args[1]
        self.assertIn("FAILED", notification)


if __name__ == "__main__":
    unittest.main()
