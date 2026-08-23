import logging
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import Mock

PROJECT_ROOT = Path(__file__).resolve().parents[1]
HERODIUM_ROOT = PROJECT_ROOT / "herodium"
if str(HERODIUM_ROOT) not in sys.path:
    sys.path.insert(0, str(HERODIUM_ROOT))

_ENGINE_IMPORT_STUBS = {
    "modules.apparmor_manager": "AppArmorManager",
    "modules.av_scanner": "ClamAVScanner",
    "modules.fs_monitor": "Watcher",
    "modules.ips_manager": "IPSManager",
    "modules.memory_hunter": "MemoryHunter",
    "modules.network_monitor": "NetworkMonitor",
    "modules.notifier": "Notifier",
    "modules.performance_manager": "PerformanceManager",
    "modules.scheduler": "TaskScheduler",
    "modules.sys_hardener": "SystemHardener",
    "modules.zram_manager": "ZramManager",
}
_stubbed_modules = []
for module_name, class_name in _ENGINE_IMPORT_STUBS.items():
    if module_name in sys.modules:
        continue
    module = types.ModuleType(module_name)
    setattr(module, class_name, type(class_name, (), {}))
    sys.modules[module_name] = module
    _stubbed_modules.append(module_name)

from core.engine import HerodiumEngine
from core.health import (
    ComponentHealth,
    ComponentState,
    HealthReport,
    StartupHealthManager,
    SystemHealth,
)

for module_name in _stubbed_modules:
    sys.modules.pop(module_name, None)
from modules.falco_monitor import FalcoMonitor


class FalcoConfigContractTests(unittest.TestCase):
    def setUp(self):
        self.logger = logging.getLogger(f"falco-config-test-{id(self)}")

    def test_default_config_is_alert_only_and_bounded(self):
        monitor = FalcoMonitor.from_config(self.logger, {"enable": True})

        self.assertEqual(monitor.queue_max_size, 2048)
        self.assertEqual(monitor.reader.start_position, "end")
        self.assertEqual(
            monitor.reader.event_log_path,
            Path("/var/log/herodium/falco-events.jsonl"),
        )

    def test_unknown_config_key_is_rejected(self):
        with self.assertRaises(ValueError):
            FalcoMonitor.from_config(
                self.logger,
                {"enable": True, "unexpected": "value"},
            )

    def test_non_alert_mode_is_rejected(self):
        with self.assertRaises(ValueError):
            FalcoMonitor.from_config(
                self.logger,
                {"enable": True, "mode": "enforce"},
            )

    def test_relative_event_log_path_is_rejected(self):
        with self.assertRaises(ValueError):
            FalcoMonitor.from_config(
                self.logger,
                {"enable": True, "event_log_path": "falco.jsonl"},
            )

    def test_non_mapping_config_is_rejected(self):
        with self.assertRaises(TypeError):
            FalcoMonitor.from_config(self.logger, ["enable"])


class FalcoHealthIntegrationTests(unittest.TestCase):
    def _manager(self, falco_monitor):
        config = {
            "performance": {"enable_zram": False},
            "ips": {"enable": False},
            "hardening": {"enable": False},
            "scheduler": {"enable": False},
        }
        scanner = Mock()
        scanner.health_check.return_value = True
        apparmor_manager = Mock()
        apparmor_manager.apply_policy.return_value = True
        performance_manager = Mock()
        performance_manager.start.return_value = True

        return StartupHealthManager(
            config=config,
            logger=Mock(spec=logging.Logger),
            scanner=scanner,
            zram_manager=Mock(),
            apparmor_manager=apparmor_manager,
            ips_manager=Mock(),
            hardener=Mock(),
            scheduler=Mock(),
            network_monitor=Mock(),
            performance_manager=performance_manager,
            filesystem_monitor=Mock(),
            start_memory_hunter=Mock(return_value=True),
            falco_monitor=falco_monitor,
        )

    def test_disabled_falco_does_not_degrade_system(self):
        manager = self._manager(None)

        report = manager.collect(
            live_monitor_enabled=False,
            maltrail_enabled=False,
            falco_enabled=False,
        )

        self.assertIs(report.state, SystemHealth.PROTECTED)
        self.assertIs(
            report.component("falco").state,
            ComponentState.DISABLED_BY_POLICY,
        )

    def test_enabled_falco_without_monitor_degrades_system(self):
        manager = self._manager(None)

        report = manager.collect(
            live_monitor_enabled=False,
            maltrail_enabled=False,
            falco_enabled=True,
        )

        self.assertIs(report.state, SystemHealth.DEGRADED)
        self.assertIs(
            report.component("falco").state,
            ComponentState.DEGRADED,
        )

    def test_started_falco_is_healthy_at_startup(self):
        monitor = Mock()
        monitor.start.return_value = True
        manager = self._manager(monitor)

        report = manager.collect(
            live_monitor_enabled=False,
            maltrail_enabled=False,
            falco_enabled=True,
        )

        self.assertIs(report.state, SystemHealth.PROTECTED)
        self.assertIs(
            report.component("falco").state,
            ComponentState.HEALTHY,
        )

    def test_falco_start_failure_is_optional_and_degrades_only(self):
        monitor = Mock()
        monitor.start.return_value = False
        manager = self._manager(monitor)

        report = manager.collect(
            live_monitor_enabled=False,
            maltrail_enabled=False,
            falco_enabled=True,
        )

        self.assertIs(report.state, SystemHealth.DEGRADED)
        self.assertFalse(report.component("falco").required)


class FalcoEngineIntegrationTests(unittest.TestCase):
    def test_invalid_enabled_config_returns_no_monitor_without_crashing(self):
        engine = object.__new__(HerodiumEngine)
        engine.falco_enabled = True
        engine.config = {"falco": {"enable": True, "mode": "enforce"}}
        engine.logger = Mock(spec=logging.Logger)

        monitor = engine._create_falco_monitor()

        self.assertIsNone(monitor)
        engine.logger.error.assert_called_once()

    def test_disabled_falco_does_not_construct_monitor(self):
        engine = object.__new__(HerodiumEngine)
        engine.falco_enabled = False
        engine.config = {"falco": {"enable": False}}
        engine.logger = Mock(spec=logging.Logger)

        self.assertIsNone(engine._create_falco_monitor())
        engine.logger.error.assert_not_called()

    def test_dispatch_batch_larger_than_queue_rejects_enabled_runtime(self):
        engine = object.__new__(HerodiumEngine)
        engine.falco_enabled = True
        engine.config = {
            "falco": {
                "enable": True,
                "queue_max_size": 16,
                "dispatch": {"max_events_per_cycle": 17},
            }
        }
        engine.logger = logging.getLogger(f"falco-engine-config-{id(self)}")
        engine.logger.error = Mock()

        monitor = engine._create_falco_monitor()

        self.assertIsNone(monitor)
        engine.logger.error.assert_called_once()

    def test_valid_runtime_constructs_dispatcher(self):
        engine = object.__new__(HerodiumEngine)
        engine.falco_enabled = True
        engine.config = {
            "falco": {
                "enable": True,
                "dispatch": {"max_events_per_cycle": 8},
            }
        }
        engine.logger = logging.getLogger(f"falco-dispatcher-config-{id(self)}")
        engine.notifier = Mock()
        engine.falco_monitor = engine._create_falco_monitor()

        dispatcher = engine._create_falco_dispatcher()

        self.assertIsNotNone(dispatcher)
        self.assertEqual(dispatcher.max_events_per_cycle, 8)


class FalcoRuntimeHealthTests(unittest.TestCase):
    @staticmethod
    def _snapshot(state_name, *, thread_alive=True, dropped=0, rejected=0):
        state = Mock()
        state.value = state_name
        stats = Mock()
        stats.events_dropped = dropped
        stats.events_rejected = rejected
        stats.reader_errors = 0
        snapshot = Mock()
        snapshot.state = state
        snapshot.thread_alive = thread_alive
        snapshot.queue_size = 2
        snapshot.queue_capacity = 2048
        snapshot.stats = stats
        return snapshot

    def _manager(self, monitor):
        manager = object.__new__(StartupHealthManager)
        manager.falco_monitor = monitor
        manager.logger = Mock(spec=logging.Logger)
        return manager

    def test_starting_runtime_state_is_not_transiently_degraded(self):
        monitor = Mock()
        monitor.health.return_value = self._snapshot("STARTING")
        manager = self._manager(monitor)

        component = manager.falco_runtime_component(True)

        self.assertIs(component.state, ComponentState.HEALTHY)
        self.assertIn("runtime=STARTING", component.detail)

    def test_degraded_monitor_state_degrades_optional_component(self):
        monitor = Mock()
        monitor.health.return_value = self._snapshot(
            "DEGRADED",
            dropped=1,
        )
        manager = self._manager(monitor)

        component = manager.falco_runtime_component(True)

        self.assertIs(component.state, ComponentState.DEGRADED)
        self.assertFalse(component.required)
        self.assertIn("dropped=1", component.detail)

    def test_runtime_health_exception_is_isolated(self):
        monitor = Mock()
        monitor.health.side_effect = RuntimeError("sensitive-message")
        manager = self._manager(monitor)

        component = manager.falco_runtime_component(True)

        self.assertIs(component.state, ComponentState.DEGRADED)
        rendered = repr(manager.logger.error.call_args)
        self.assertIn("RuntimeError", rendered)
        self.assertNotIn("sensitive-message", rendered)

    def test_health_report_replaces_component_immutably(self):
        original = HealthReport.from_components(
            (ComponentHealth("falco", ComponentState.HEALTHY),)
        )
        replacement = ComponentHealth("falco", ComponentState.DEGRADED)

        updated = original.with_component(replacement)

        self.assertIs(original.component("falco").state, ComponentState.HEALTHY)
        self.assertIs(updated.component("falco").state, ComponentState.DEGRADED)


    def test_runtime_transition_emits_once_for_state_change(self):
        manager = self._manager(Mock())
        notifier = Mock()
        previous = ComponentHealth("falco", ComponentState.HEALTHY)
        current = ComponentHealth(
            "falco",
            ComponentState.DEGRADED,
            detail="runtime=DEGRADED",
        )
        report = HealthReport.from_components((current,))

        emitted = manager.emit_component_transition(
            previous,
            current,
            report,
            notifier,
        )

        self.assertTrue(emitted)
        notifier.send_notification.assert_called_once()
        self.assertEqual(
            notifier.send_notification.call_args.kwargs["level"],
            "critical",
        )

    def test_runtime_transition_ignores_same_state(self):
        manager = self._manager(Mock())
        notifier = Mock()
        previous = ComponentHealth("falco", ComponentState.HEALTHY)
        current = ComponentHealth(
            "falco",
            ComponentState.HEALTHY,
            detail="queue changed only",
        )
        report = HealthReport.from_components((current,))

        emitted = manager.emit_component_transition(
            previous,
            current,
            report,
            notifier,
        )

        self.assertFalse(emitted)
        notifier.send_notification.assert_not_called()


    def test_runtime_transition_notification_failure_is_isolated(self):
        manager = self._manager(Mock())
        notifier = Mock()
        notifier.send_notification.side_effect = RuntimeError("private-backend")
        previous = ComponentHealth("falco", ComponentState.HEALTHY)
        current = ComponentHealth("falco", ComponentState.DEGRADED)
        report = HealthReport.from_components((current,))

        emitted = manager.emit_component_transition(
            previous,
            current,
            report,
            notifier,
        )

        self.assertTrue(emitted)
        rendered = repr(manager.logger.error.call_args)
        self.assertIn("RuntimeError", rendered)
        self.assertNotIn("private-backend", rendered)


class FalcoEngineRuntimeServiceTests(unittest.TestCase):
    def _engine(self, current_state=ComponentState.HEALTHY):
        engine = object.__new__(HerodiumEngine)
        engine.falco_enabled = True
        engine.falco_monitor = Mock()
        engine.falco_dispatcher = Mock()
        engine.falco_dispatcher.service_once.return_value = 3
        engine.health_manager = Mock()
        engine.notifier = Mock()
        engine.logger = Mock(spec=logging.Logger)
        engine.health_report = HealthReport.from_components(
            (ComponentHealth("falco", current_state),)
        )
        return engine

    def test_runtime_service_dispatches_bounded_events_and_refreshes_health(self):
        engine = self._engine()
        current = ComponentHealth("falco", ComponentState.HEALTHY)
        engine.health_manager.falco_runtime_component.return_value = current

        dispatched = engine._service_falco_runtime()

        self.assertEqual(dispatched, 3)
        engine.falco_dispatcher.service_once.assert_called_once_with()
        engine.health_manager.falco_runtime_component.assert_called_once_with(True)
        engine.health_manager.emit_component_transition.assert_not_called()

    def test_runtime_degradation_updates_report_and_emits_transition(self):
        engine = self._engine()
        current = ComponentHealth(
            "falco",
            ComponentState.DEGRADED,
            detail="runtime=DEGRADED",
        )
        engine.health_manager.falco_runtime_component.return_value = current

        engine._service_falco_runtime()

        self.assertIs(
            engine.health_report.component("falco").state,
            ComponentState.DEGRADED,
        )
        engine.health_manager.emit_component_transition.assert_called_once()

    def test_dispatch_failure_isolated_and_degrades_falco_only(self):
        engine = self._engine()
        engine.falco_dispatcher.service_once.side_effect = RuntimeError(
            "secret-dispatch-error"
        )

        dispatched = engine._service_falco_runtime()

        self.assertEqual(dispatched, 0)
        self.assertIs(
            engine.health_report.component("falco").state,
            ComponentState.DEGRADED,
        )
        rendered = repr(engine.logger.error.call_args)
        self.assertIn("RuntimeError", rendered)
        self.assertNotIn("secret-dispatch-error", rendered)

    def test_disabled_runtime_service_is_noop(self):
        engine = self._engine()
        engine.falco_enabled = False

        self.assertEqual(engine._service_falco_runtime(), 0)

        engine.falco_dispatcher.service_once.assert_not_called()



if __name__ == "__main__":
    unittest.main()
