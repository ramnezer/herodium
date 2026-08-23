import logging
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock

PROJECT_ROOT = Path(__file__).resolve().parents[1]
HERODIUM_ROOT = PROJECT_ROOT / "herodium"
if str(HERODIUM_ROOT) not in sys.path:
    sys.path.insert(0, str(HERODIUM_ROOT))

from modules.falco_dispatcher import FalcoEventDispatcher
from modules.falco_event import FalcoEvent, FalcoPriority
from modules.falco_monitor import FalcoMonitor
from modules.falco_reader import FalcoReadBatch


class _IdleReader:
    def poll(self):
        raise AssertionError("reader poll should not be used in dispatcher tests")

    def close(self):
        return None


def _event(
    *,
    rule="Execution from temp directory",
    priority=FalcoPriority.ERROR,
    output="raw output that should not be persisted",
    fields=None,
):
    default_fields = {
        "proc.exepath": "/tmp/tool",
        "proc.name": "tool",
        "proc.pname": "bash",
        "proc.cmdline": "tool --token TOP-SECRET-TOKEN",
        "user.name": "test",
        "user.uid": 1000,
        "fd.name": "/etc/shadow",
        "evt.type": "openat",
    }
    if fields is not None:
        default_fields.update(fields)
    return FalcoEvent(
        timestamp=datetime(2026, 8, 12, tzinfo=timezone.utc),
        timestamp_text="2026-08-12T00:00:00Z",
        rule=rule,
        priority=priority,
        output=output,
        hostname="test-host",
        source="syscall",
        tags=("herodium",),
        output_fields=tuple(sorted(default_fields.items())),
        raw_size_bytes=512,
    )


def _monitor(queue_size=2048):
    return FalcoMonitor(
        logging.getLogger(f"dispatcher-monitor-{queue_size}"),
        reader=_IdleReader(),
        queue_max_size=queue_size,
    )


class FalcoDispatcherConfigTests(unittest.TestCase):
    def setUp(self):
        self.logger = logging.getLogger(f"dispatcher-config-{id(self)}")
        self.notifier = Mock()
        self.monitor = _monitor()

    def test_defaults_are_bounded_and_error_only(self):
        dispatcher = FalcoEventDispatcher.from_config(
            self.logger,
            self.notifier,
            self.monitor,
            {},
        )

        self.assertEqual(dispatcher.max_events_per_cycle, 256)
        self.assertEqual(dispatcher.alert_cache_max_entries, 1024)
        self.assertEqual(dispatcher.minimum_priority, FalcoPriority.ERROR)
        self.assertEqual(
            dispatcher.notification_minimum_priority,
            FalcoPriority.ERROR,
        )
        self.assertTrue(dispatcher.desktop_notifications)

    def test_unknown_dispatch_key_is_rejected(self):
        with self.assertRaises(ValueError):
            FalcoEventDispatcher.from_config(
                self.logger,
                self.notifier,
                self.monitor,
                {"dispatch": {"unexpected": True}},
            )

    def test_non_mapping_dispatch_config_is_rejected(self):
        with self.assertRaises(TypeError):
            FalcoEventDispatcher.from_config(
                self.logger,
                self.notifier,
                self.monitor,
                {"dispatch": ["invalid"]},
            )

    def test_dispatch_batch_cannot_exceed_queue_capacity(self):
        with self.assertRaises(ValueError):
            FalcoEventDispatcher.validate_config(
                {"dispatch": {"max_events_per_cycle": 17}},
                queue_capacity=16,
            )

    def test_invalid_minimum_priority_is_rejected(self):
        with self.assertRaises(ValueError):
            FalcoEventDispatcher.from_config(
                self.logger,
                self.notifier,
                self.monitor,
                {"dispatch": {"minimum_priority": "NOPE"}},
            )

    def test_invalid_notification_priority_is_rejected(self):
        with self.assertRaises(ValueError):
            FalcoEventDispatcher.from_config(
                self.logger,
                self.notifier,
                self.monitor,
                {"dispatch": {"notification_minimum_priority": "NOPE"}},
            )

    def test_desktop_notifications_requires_boolean(self):
        with self.assertRaises(TypeError):
            FalcoEventDispatcher.from_config(
                self.logger,
                self.notifier,
                self.monitor,
                {"dispatch": {"desktop_notifications": "yes"}},
            )


class FalcoDispatcherDeliveryTests(unittest.TestCase):
    def setUp(self):
        self.logger = logging.getLogger(f"dispatcher-delivery-{id(self)}")
        self.logger.log = Mock()
        self.logger.error = Mock()
        self.notifier = Mock()
        self.notifier.send_notification.return_value = True
        self.monitor = _monitor()
        self.dispatcher = FalcoEventDispatcher(
            self.logger,
            self.notifier,
            self.monitor,
            alert_cooldown_seconds=60,
        )
        self.now = [100.0]
        self.dispatcher._now = lambda: self.now[0]

    def test_valid_event_is_logged_without_raw_output_or_command_line(self):
        event = _event(output="RAW-SECRET-PAYLOAD")

        self.assertTrue(self.dispatcher.dispatch(event))

        rendered_call = repr(self.logger.log.call_args)
        self.assertNotIn("RAW-SECRET-PAYLOAD", rendered_call)
        self.assertNotIn("TOP-SECRET-TOKEN", rendered_call)
        self.assertIn("Execution from temp directory", rendered_call)
        self.assertIn("/tmp/tool", rendered_call)

    def test_notice_and_warning_are_filtered_by_default(self):
        self.assertFalse(
            self.dispatcher.dispatch(_event(priority=FalcoPriority.NOTICE))
        )
        self.assertFalse(
            self.dispatcher.dispatch(_event(priority=FalcoPriority.WARNING))
        )

        self.logger.log.assert_not_called()
        self.notifier.send_notification.assert_not_called()
        stats = self.dispatcher.stats()
        self.assertEqual(stats.events_seen, 2)
        self.assertEqual(stats.events_filtered, 2)
        self.assertEqual(stats.events_logged, 0)

    def test_error_uses_critical_notification_urgency(self):
        self.dispatcher.dispatch(_event(priority=FalcoPriority.ERROR))

        self.assertEqual(
            self.notifier.send_notification.call_args.kwargs["level"],
            "critical",
        )

    def test_notification_failure_is_counted_without_raising(self):
        self.notifier.send_notification.side_effect = RuntimeError("backend")

        self.assertTrue(self.dispatcher.dispatch(_event()))

        stats = self.dispatcher.stats()
        self.assertEqual(stats.notifications_attempted, 1)
        self.assertEqual(stats.notification_failures, 1)
        rendered = repr(self.logger.error.call_args)
        self.assertIn("RuntimeError", rendered)
        self.assertNotIn("backend", rendered)

    def test_repeated_alert_is_suppressed_inside_cooldown(self):
        event = _event()

        self.assertTrue(self.dispatcher.dispatch(event))
        self.now[0] += 10
        self.assertFalse(self.dispatcher.dispatch(event))

        stats = self.dispatcher.stats()
        self.assertEqual(stats.events_seen, 2)
        self.assertEqual(stats.events_logged, 1)
        self.assertEqual(stats.events_suppressed, 1)
        self.assertEqual(self.notifier.send_notification.call_count, 1)

    def test_next_alert_after_cooldown_reports_suppressed_count(self):
        event = _event()
        self.dispatcher.dispatch(event)
        self.now[0] += 10
        self.dispatcher.dispatch(event)
        self.now[0] += 60

        self.assertTrue(self.dispatcher.dispatch(event))

        rendered_call = repr(self.logger.log.call_args)
        self.assertIn("suppressed_since_last=1", rendered_call)

    def test_distinct_process_identity_is_not_coalesced(self):
        self.dispatcher.dispatch(_event(fields={"proc.exepath": "/tmp/one"}))

        self.assertTrue(
            self.dispatcher.dispatch(
                _event(fields={"proc.exepath": "/tmp/two"})
            )
        )

        self.assertEqual(self.logger.log.call_count, 2)

    def test_alert_cache_is_bounded(self):
        dispatcher = FalcoEventDispatcher(
            self.logger,
            self.notifier,
            self.monitor,
            alert_cache_max_entries=2,
        )
        dispatcher._now = lambda: 100.0

        dispatcher.dispatch(_event(rule="rule-1"))
        dispatcher.dispatch(_event(rule="rule-2"))
        dispatcher.dispatch(_event(rule="rule-3"))

        self.assertEqual(dispatcher.stats().cache_evictions, 1)
        self.assertEqual(len(dispatcher._alerts), 2)

    def test_disabled_desktop_notifications_never_call_notifier(self):
        dispatcher = FalcoEventDispatcher(
            self.logger,
            self.notifier,
            self.monitor,
            desktop_notifications=False,
        )

        dispatcher.dispatch(_event(priority=FalcoPriority.EMERGENCY))

        self.notifier.send_notification.assert_not_called()


class FalcoDispatcherServiceTests(unittest.TestCase):
    def test_real_monitor_queue_is_drained_by_dispatcher(self):
        logger = logging.getLogger(f"dispatcher-real-queue-{id(self)}")
        logger.log = Mock()
        monitor = _monitor(queue_size=16)
        event = _event(priority=FalcoPriority.ERROR)
        monitor._record_successful_batch(
            FalcoReadBatch(
                events=(event,),
                rejected=(),
                records_consumed=1,
                bytes_consumed=512,
                rotation_detected=False,
                truncation_detected=False,
            )
        )
        dispatcher = FalcoEventDispatcher(
            logger,
            Mock(),
            monitor,
            max_events_per_cycle=8,
        )

        self.assertEqual(dispatcher.service_once(), 1)
        self.assertEqual(monitor.health().queue_size, 0)
        self.assertEqual(dispatcher.stats().events_logged, 1)

    def test_service_once_attempts_remaining_batch_after_one_dispatch_failure(self):
        logger = logging.getLogger(f"dispatcher-partial-failure-{id(self)}")
        monitor = _monitor(queue_size=16)
        first = _event(rule="first")
        second = _event(rule="second")
        monitor.drain = Mock(return_value=(first, second))
        dispatcher = FalcoEventDispatcher(
            logger, Mock(), monitor, max_events_per_cycle=8
        )
        dispatcher.dispatch = Mock(
            side_effect=(RuntimeError("sensitive-dispatch-error"), True)
        )

        with self.assertRaises(RuntimeError):
            dispatcher.service_once()

        self.assertEqual(dispatcher.dispatch.call_count, 2)
        self.assertEqual(dispatcher.stats().dispatch_failures, 1)

    def test_service_once_uses_bounded_drain_limit(self):
        logger = logging.getLogger(f"dispatcher-service-{id(self)}")
        logger.log = Mock()
        monitor = _monitor(queue_size=16)
        event = _event(priority=FalcoPriority.NOTICE)
        monitor.drain = Mock(return_value=(event, event))
        notifier = Mock()
        dispatcher = FalcoEventDispatcher(
            logger,
            notifier,
            monitor,
            max_events_per_cycle=8,
            alert_cooldown_seconds=0,
        )

        count = dispatcher.service_once()

        self.assertEqual(count, 2)
        monitor.drain.assert_called_once_with(8)


if __name__ == "__main__":
    unittest.main()
