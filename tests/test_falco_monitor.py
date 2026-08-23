import json
import logging
import os
import sys
import tempfile
import threading
import time
import unittest
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock

PROJECT_ROOT = Path(__file__).resolve().parents[1]
HERODIUM_ROOT = PROJECT_ROOT / "herodium"
if str(HERODIUM_ROOT) not in sys.path:
    sys.path.insert(0, str(HERODIUM_ROOT))

from modules.falco_event import FalcoEvent, FalcoPriority
from modules.falco_monitor import FalcoMonitor, FalcoMonitorState
from modules.falco_reader import FalcoReadBatch, FalcoReaderError


class _FakeReader:
    def __init__(self, results=None):
        self.results = deque(results or [])
        self.poll_calls = 0
        self.close_calls = 0
        self._lock = threading.Lock()

    def poll(self):
        with self._lock:
            self.poll_calls += 1
            if self.results:
                result = self.results.popleft()
            else:
                result = _batch()
        if isinstance(result, BaseException):
            raise result
        return result

    def close(self):
        self.close_calls += 1


class _BlockingReader(_FakeReader):
    def __init__(self):
        super().__init__()
        self.entered = threading.Event()
        self.release = threading.Event()

    def poll(self):
        self.entered.set()
        self.release.wait(2.0)
        return _batch()


class _FatalReader(_FakeReader):
    def poll(self):
        raise RuntimeError("unexpected failure")


class _CloseFailReader(_FakeReader):
    def close(self):
        self.close_calls += 1
        raise FalcoReaderError("cursor_write_failed", "sensitive detail")


def _event(rule="Test rule"):
    return FalcoEvent(
        timestamp=datetime(2026, 8, 12, tzinfo=timezone.utc),
        timestamp_text="2026-08-12T00:00:00Z",
        rule=rule,
        priority=FalcoPriority.NOTICE,
        output="test output",
        hostname="test-host",
        source="syscall",
        tags=("herodium",),
        output_fields=(),
        raw_size_bytes=128,
    )


def _batch(
    *events,
    rejected=(),
    rotation=False,
    truncation=False,
):
    return FalcoReadBatch(
        events=tuple(events),
        rejected=tuple(rejected),
        records_consumed=len(events) + sum(count for _, count in rejected),
        bytes_consumed=128 * (len(events) + sum(count for _, count in rejected)),
        rotation_detected=rotation,
        truncation_detected=truncation,
    )


def _event_json_line(rule="Runtime test"):
    return (
        json.dumps(
            {
                "time": "2026-08-12T00:00:00.000000001Z",
                "rule": rule,
                "priority": "Notice",
                "output": "runtime test",
                "hostname": "test-host",
                "source": "syscall",
                "tags": ["herodium"],
                "output_fields": {"proc.name": "bash"},
            },
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def _wait_until(predicate, timeout=1.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.005)
    return predicate()


class FalcoMonitorValidationTests(unittest.TestCase):
    def setUp(self):
        self.logger = Mock(spec=logging.Logger)

    def test_logger_must_be_logging_logger(self):
        with self.assertRaises(TypeError):
            FalcoMonitor(Mock(), reader=_FakeReader())

    def test_queue_size_rejects_boolean(self):
        with self.assertRaises(TypeError):
            FalcoMonitor(self.logger, reader=_FakeReader(), queue_max_size=True)

    def test_queue_size_is_bounded(self):
        with self.assertRaises(ValueError):
            FalcoMonitor(self.logger, reader=_FakeReader(), queue_max_size=0)

    def test_poll_interval_must_be_numeric(self):
        with self.assertRaises(TypeError):
            FalcoMonitor(
                self.logger,
                reader=_FakeReader(),
                poll_interval_seconds="fast",
            )

    def test_warning_cache_is_bounded(self):
        with self.assertRaises(ValueError):
            FalcoMonitor(
                self.logger,
                reader=_FakeReader(),
                warning_cache_max_entries=0,
            )

    def test_drain_limit_cannot_exceed_queue_capacity(self):
        monitor = FalcoMonitor(
            self.logger,
            reader=_FakeReader(),
            queue_max_size=2,
        )
        with self.assertRaises(ValueError):
            monitor.drain(3)


    def test_timeout_requires_blocking_get(self):
        monitor = FalcoMonitor(self.logger, reader=_FakeReader())

        with self.assertRaises(ValueError):
            monitor.get_event(timeout=0.1)


class FalcoMonitorLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.logger = Mock(spec=logging.Logger)

    def test_initial_health_is_stopped(self):
        monitor = FalcoMonitor(self.logger, reader=_FakeReader())

        health = monitor.health()

        self.assertEqual(health.state, FalcoMonitorState.STOPPED)
        self.assertFalse(health.thread_alive)

    def test_start_is_idempotent_and_uses_one_thread(self):
        reader = _FakeReader()
        monitor = FalcoMonitor(
            self.logger,
            reader=reader,
            poll_interval_seconds=0.01,
        )
        self.addCleanup(monitor.stop)

        self.assertTrue(monitor.start())
        thread = monitor._thread
        self.assertTrue(monitor.start())

        self.assertIs(monitor._thread, thread)
        self.assertTrue(_wait_until(lambda: reader.poll_calls >= 1))

    def test_successful_poll_transitions_to_healthy(self):
        monitor = FalcoMonitor(
            self.logger,
            reader=_FakeReader([_batch()]),
            poll_interval_seconds=0.01,
        )
        self.addCleanup(monitor.stop)

        self.assertTrue(monitor.start())
        self.assertTrue(
            _wait_until(
                lambda: monitor.health().state is FalcoMonitorState.HEALTHY
            )
        )

    def test_stop_closes_reader_after_thread_exits(self):
        reader = _FakeReader()
        monitor = FalcoMonitor(
            self.logger,
            reader=reader,
            poll_interval_seconds=0.01,
        )
        monitor.start()
        self.assertTrue(_wait_until(lambda: reader.poll_calls >= 1))

        self.assertTrue(monitor.stop())

        self.assertEqual(reader.close_calls, 1)
        self.assertEqual(monitor.health().state, FalcoMonitorState.STOPPED)

    def test_stop_before_start_is_safe(self):
        reader = _FakeReader()
        monitor = FalcoMonitor(self.logger, reader=reader)

        self.assertTrue(monitor.stop())
        self.assertEqual(reader.close_calls, 0)

    def test_stop_timeout_does_not_close_reader_while_thread_is_alive(self):
        reader = _BlockingReader()
        monitor = FalcoMonitor(
            self.logger,
            reader=reader,
            poll_interval_seconds=0.01,
        )
        monitor.start()
        self.assertTrue(reader.entered.wait(1.0))

        self.assertFalse(monitor.stop(timeout=0.001))
        self.assertEqual(reader.close_calls, 0)

        reader.release.set()
        self.assertTrue(_wait_until(lambda: not monitor.health().thread_alive))
        self.assertTrue(monitor.stop())
        self.assertEqual(reader.close_calls, 1)

    def test_unexpected_reader_failure_marks_monitor_failed(self):
        monitor = FalcoMonitor(
            self.logger,
            reader=_FatalReader(),
            poll_interval_seconds=0.01,
        )
        self.addCleanup(monitor.stop)

        monitor.start()
        self.assertTrue(
            _wait_until(
                lambda: monitor.health().state is FalcoMonitorState.FAILED
            )
        )
        self.logger.exception.assert_called_once()
        self.assertFalse(monitor.start())

    def test_reader_close_failure_makes_stop_fail(self):
        reader = _CloseFailReader()
        monitor = FalcoMonitor(
            self.logger,
            reader=reader,
            poll_interval_seconds=0.01,
        )
        monitor.start()
        self.assertTrue(_wait_until(lambda: reader.poll_calls >= 1))

        self.assertFalse(monitor.stop())

        self.assertEqual(reader.close_calls, 1)
        self.assertEqual(monitor.stats().reader_errors, 1)
        self.assertEqual(monitor.health().state, FalcoMonitorState.FAILED)
        self.assertEqual(
            monitor.health().last_reader_error_code,
            "cursor_write_failed",
        )
        self.assertFalse(monitor.start())


class FalcoMonitorQueueTests(unittest.TestCase):
    def setUp(self):
        self.logger = Mock(spec=logging.Logger)

    def test_events_are_enqueued_and_drained_in_order(self):
        first = _event("first")
        second = _event("second")
        monitor = FalcoMonitor(
            self.logger,
            reader=_FakeReader([_batch(first, second)]),
            queue_max_size=4,
            poll_interval_seconds=0.01,
        )
        self.addCleanup(monitor.stop)

        monitor.start()
        self.assertTrue(_wait_until(lambda: monitor.health().queue_size == 2))

        self.assertEqual(monitor.drain(2), (first, second))
        stats = monitor.stats()
        self.assertEqual(stats.events_enqueued, 2)
        self.assertEqual(stats.events_dequeued, 2)
        self.assertEqual(stats.queue_high_watermark, 2)

    def test_get_event_nonblocking_returns_none_when_empty(self):
        monitor = FalcoMonitor(self.logger, reader=_FakeReader())

        self.assertIsNone(monitor.get_event())

    def test_get_event_timeout_returns_none_when_empty(self):
        monitor = FalcoMonitor(self.logger, reader=_FakeReader())

        self.assertIsNone(monitor.get_event(block=True, timeout=0.001))

    def test_queue_overflow_drops_newest_without_blocking_reader(self):
        events = tuple(_event(f"rule-{index}") for index in range(3))
        reader = _FakeReader([_batch(*events)])
        monitor = FalcoMonitor(
            self.logger,
            reader=reader,
            queue_max_size=2,
            poll_interval_seconds=0.01,
        )
        self.addCleanup(monitor.stop)

        monitor.start()
        self.assertTrue(_wait_until(lambda: monitor.stats().events_dropped == 1))

        self.assertEqual(monitor.drain(2), events[:2])
        self.assertEqual(monitor.health().state, FalcoMonitorState.DEGRADED)
        self.assertGreaterEqual(reader.poll_calls, 1)

    def test_rotation_and_truncation_are_counted(self):
        monitor = FalcoMonitor(
            self.logger,
            reader=_FakeReader([_batch(rotation=True, truncation=True)]),
            poll_interval_seconds=0.01,
        )
        self.addCleanup(monitor.stop)

        monitor.start()
        self.assertTrue(_wait_until(lambda: monitor.stats().polls_completed >= 1))

        stats = monitor.stats()
        self.assertEqual(stats.rotations, 1)
        self.assertEqual(stats.truncations, 1)


class FalcoMonitorIntegrationTests(unittest.TestCase):
    def test_real_reader_delivers_valid_jsonl_event(self):
        logger = Mock(spec=logging.Logger)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            event_log = root / "falco-events.jsonl"
            cursor = root / "falco-state" / "cursor.json"
            event_log.write_bytes(_event_json_line("real-reader"))
            event_log.chmod(0o600)
            monitor = FalcoMonitor(
                logger,
                event_log_path=event_log,
                cursor_path=cursor,
                expected_owner_uid=os.geteuid(),
                start_position="beginning",
                poll_interval_seconds=0.01,
            )
            self.addCleanup(monitor.stop)

            self.assertTrue(monitor.start())
            self.assertTrue(_wait_until(lambda: monitor.health().queue_size == 1))

            event = monitor.get_event()
            self.assertIsNotNone(event)
            self.assertEqual(event.rule, "real-reader")
            self.assertEqual(monitor.health().state, FalcoMonitorState.HEALTHY)


class FalcoMonitorErrorHandlingTests(unittest.TestCase):
    def setUp(self):
        self.logger = Mock(spec=logging.Logger)

    def test_reader_error_is_degraded_and_retried(self):
        reader = _FakeReader(
            [
                FalcoReaderError("source_missing", "missing"),
                _batch(),
            ]
        )
        monitor = FalcoMonitor(
            self.logger,
            reader=reader,
            poll_interval_seconds=0.01,
        )
        self.addCleanup(monitor.stop)

        monitor.start()
        self.assertTrue(_wait_until(lambda: monitor.stats().reader_errors == 1))
        self.assertTrue(_wait_until(lambda: monitor.stats().polls_completed >= 1))

        health = monitor.health()
        self.assertEqual(health.state, FalcoMonitorState.HEALTHY)
        self.assertIsNone(health.last_reader_error_code)

    def test_rejected_records_are_counted_without_entering_queue(self):
        monitor = FalcoMonitor(
            self.logger,
            reader=_FakeReader(
                [_batch(rejected=(("invalid_json", 3), ("invalid_utf8", 2)))]
            ),
            poll_interval_seconds=0.01,
        )
        self.addCleanup(monitor.stop)

        monitor.start()
        self.assertTrue(_wait_until(lambda: monitor.stats().polls_completed >= 1))

        self.assertEqual(monitor.stats().events_rejected, 5)
        self.assertEqual(monitor.health().queue_size, 0)
        self.assertEqual(monitor.health().state, FalcoMonitorState.DEGRADED)

    def test_warning_rate_limit_coalesces_repeated_rejections(self):
        monitor = FalcoMonitor(
            self.logger,
            reader=_FakeReader(),
            warning_interval_seconds=30,
        )
        monitor._now = Mock(side_effect=[100.0, 101.0, 131.0])

        self.assertTrue(
            monitor._warn_rate_limited(
                "rejected:invalid_json",
                "Falco input rejected: code=invalid_json",
                count=2,
            )
        )
        self.assertFalse(
            monitor._warn_rate_limited(
                "rejected:invalid_json",
                "Falco input rejected: code=invalid_json",
                count=3,
            )
        )
        self.assertTrue(
            monitor._warn_rate_limited(
                "rejected:invalid_json",
                "Falco input rejected: code=invalid_json",
                count=1,
            )
        )

        self.assertEqual(self.logger.warning.call_count, 2)
        self.assertEqual(
            self.logger.warning.call_args_list[1].args,
            (
                "%s count=%d suppressed_since_last=%d",
                "Falco input rejected: code=invalid_json",
                1,
                3,
            ),
        )

    def test_warning_cache_evicts_oldest_key(self):
        monitor = FalcoMonitor(
            self.logger,
            reader=_FakeReader(),
            warning_interval_seconds=30,
            warning_cache_max_entries=2,
        )
        monitor._now = Mock(side_effect=[1.0, 2.0, 3.0])

        monitor._warn_rate_limited("a", "a")
        monitor._warn_rate_limited("b", "b")
        monitor._warn_rate_limited("c", "c")

        self.assertEqual(tuple(monitor._warning_state), ("b", "c"))

    def test_reader_warning_logs_only_internal_error_code(self):
        reader = _FakeReader(
            [FalcoReaderError("source_missing", "attacker-controlled detail")]
        )
        monitor = FalcoMonitor(
            self.logger,
            reader=reader,
            poll_interval_seconds=0.01,
        )
        self.addCleanup(monitor.stop)

        monitor.start()
        self.assertTrue(_wait_until(lambda: monitor.stats().reader_errors >= 1))

        rendered = " ".join(
            str(value)
            for call in self.logger.warning.call_args_list
            for value in call.args
        )
        self.assertNotIn("attacker-controlled detail", rendered)
        self.assertIn("source_missing", rendered)


if __name__ == "__main__":
    unittest.main()
