import logging
import queue
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import Mock, patch


PROJECT_ROOT = Path(__file__).resolve().parents[1]
HERODIUM_ROOT = PROJECT_ROOT / "herodium"
if str(HERODIUM_ROOT) not in sys.path:
    sys.path.insert(0, str(HERODIUM_ROOT))

# Keep tests independent from optional runtime packages on the audit host.
if "pyclamd" not in sys.modules:
    pyclamd_stub = types.ModuleType("pyclamd")
    pyclamd_stub.ClamdUnixSocket = Mock()
    sys.modules["pyclamd"] = pyclamd_stub

if "watchdog" not in sys.modules:
    watchdog_stub = types.ModuleType("watchdog")
    watchdog_events_stub = types.ModuleType("watchdog.events")
    watchdog_observers_stub = types.ModuleType("watchdog.observers")

    class FileSystemEventHandler:
        pass

    class Observer:
        def __init__(self):
            self.started = False

        def start(self):
            self.started = True

        def is_alive(self):
            return self.started

        def stop(self):
            self.started = False

        def join(self):
            return None

        def schedule(self, *args, **kwargs):
            return object()

        def unschedule(self, watch):
            return watch

    watchdog_events_stub.FileSystemEventHandler = FileSystemEventHandler
    watchdog_observers_stub.Observer = Observer
    sys.modules["watchdog"] = watchdog_stub
    sys.modules["watchdog.events"] = watchdog_events_stub
    sys.modules["watchdog.observers"] = watchdog_observers_stub

from modules.fs_monitor import Handler, Watcher  # noqa: E402


class BoundedScanQueueTests(unittest.TestCase):
    def setUp(self):
        self.logger = Mock(spec=logging.Logger)
        self.scanner = Mock()

    def _watcher(
        self,
        max_size=2,
        warning_interval=30,
        clamav_temp_directory="/var/lib/clamav/herodium-tmp",
        **directory_values,
    ):
        directories = {
            "scan_queue_max_size": max_size,
            "scan_queue_warning_interval_seconds": warning_interval,
        }
        directories.update(directory_values)
        config = {
            "directories": directories,
            "clamav": {"temporary_directory": clamav_temp_directory},
        }

        with patch(
            "modules.fs_monitor.ClamAVScanner",
            return_value=self.scanner,
        ):
            return Watcher(config, self.logger)

    def test_queue_capacity_and_boolean_config_are_validated(self):
        watcher = self._watcher(
            max_size=0,
            warning_interval=99999,
            ignore_user_cache="false",
        )

        self.assertEqual(watcher.queue_max_size, 1)
        self.assertEqual(watcher.queue_warning_interval_seconds, 3600)
        self.assertFalse(watcher.ignore_user_cache)
        self.assertEqual(watcher.scan_queue.maxsize, 1)

    def test_queue_full_drop_rolls_back_pending_state(self):
        watcher = self._watcher(max_size=2)

        self.assertTrue(watcher._enqueue_once("/home/test/a"))
        self.assertTrue(watcher._enqueue_once("/home/test/b"))
        self.assertFalse(watcher._enqueue_once("/home/test/c"))

        stats = watcher.get_queue_stats()
        self.assertEqual(stats["queued"], 2)
        self.assertEqual(stats["pending"], 2)
        self.assertEqual(stats["dirty"], 0)
        self.assertEqual(stats["dropped_total"], 1)
        self.assertNotIn("/home/test/c", watcher._pending)
        self.assertNotIn("/home/test/c", watcher._dirty)

    def test_duplicate_events_mark_one_dirty_entry_without_growth(self):
        watcher = self._watcher(max_size=2)

        self.assertTrue(watcher._enqueue_once("/home/test/a"))
        for _ in range(100):
            self.assertFalse(watcher._enqueue_once("/home/test/a"))

        stats = watcher.get_queue_stats()
        self.assertEqual(stats["queued"], 1)
        self.assertEqual(stats["pending"], 1)
        self.assertEqual(stats["dirty"], 1)
        self.assertEqual(stats["deduplicated_total"], 100)

    def test_dirty_path_is_requeued_once_without_pending_growth(self):
        watcher = self._watcher(max_size=2)
        watcher._enqueue_once("/home/test/a")
        watcher._enqueue_once("/home/test/a")

        queued_path = watcher.scan_queue.get_nowait()
        self.assertEqual(queued_path, "/home/test/a")
        watcher._finish_path(queued_path)
        watcher.scan_queue.task_done()

        stats = watcher.get_queue_stats()
        self.assertEqual(stats["queued"], 1)
        self.assertEqual(stats["pending"], 1)
        self.assertEqual(stats["dirty"], 0)
        self.assertEqual(stats["requeued_total"], 1)
        self.assertEqual(stats["scanned_total"], 1)

    def test_dirty_requeue_full_rolls_back_for_future_events(self):
        watcher = self._watcher(max_size=1)
        watcher._enqueue_once("/home/test/a")

        queued_path = watcher.scan_queue.get_nowait()
        watcher._enqueue_once("/home/test/b")
        watcher._enqueue_once("/home/test/a")

        watcher._finish_path(queued_path)
        watcher.scan_queue.task_done()

        stats = watcher.get_queue_stats()
        self.assertEqual(stats["queued"], 1)
        self.assertEqual(stats["pending"], 1)
        self.assertEqual(stats["dirty"], 0)
        self.assertEqual(stats["dropped_total"], 1)
        self.assertNotIn("/home/test/a", watcher._pending)
        self.assertTrue(watcher._enqueue_once("/home/test/a") is False)
        self.assertNotIn("/home/test/a", watcher._pending)

    def test_pending_limit_bounds_inflight_plus_full_queue(self):
        watcher = self._watcher(max_size=1)
        watcher._enqueue_once("/home/test/a")
        inflight = watcher.scan_queue.get_nowait()
        watcher._enqueue_once("/home/test/b")

        self.assertFalse(watcher._enqueue_once("/home/test/c"))
        self.assertLessEqual(len(watcher._pending), watcher._pending_limit)
        self.assertEqual(watcher.get_queue_stats()["dropped_total"], 1)

        watcher._finish_path(inflight)
        watcher.scan_queue.task_done()

    def test_large_unique_burst_remains_bounded(self):
        watcher = self._watcher(max_size=4)

        for index in range(1000):
            watcher._enqueue_once(f"/home/test/file-{index}")

        stats = watcher.get_queue_stats()
        self.assertEqual(stats["queued"], 4)
        self.assertEqual(stats["pending"], 4)
        self.assertLessEqual(stats["dirty"], stats["pending"])
        self.assertEqual(stats["dropped_total"], 996)
        self.assertEqual(stats["events_dropped"], 996)
        self.assertEqual(stats["recovery_roots_pending"], 1)

    def test_initial_drive_walk_stops_after_recovery_is_scheduled(self):
        root = "/media/test/asd"
        watcher = self._watcher(
            max_size=1,
            watch_paths=[root],
        )
        watcher.recovery.add_watch_root(root)
        files = [f"file-{index}" for index in range(1000)]

        with patch(
            "modules.fs_monitor.os.walk",
            return_value=[(root, [], files)],
        ):
            watcher._queue_existing_files(root)

        stats = watcher.get_queue_stats()
        self.assertEqual(stats["queued"], 1)
        self.assertEqual(stats["events_dropped"], 1)
        self.assertEqual(stats["recovery_roots_pending"], 1)

    def test_queue_pressure_warning_is_rate_limited(self):
        watcher = self._watcher(max_size=1, warning_interval=30)
        watcher._enqueue_once("/home/test/a")

        with patch(
            "modules.fs_monitor.time.monotonic",
            side_effect=[100.0, 110.0, 131.0],
        ):
            watcher._enqueue_once("/home/test/b")
            watcher._enqueue_once("/home/test/c")
            watcher._enqueue_once("/home/test/d")

        self.assertEqual(self.logger.warning.call_count, 2)
        self.assertEqual(watcher.get_queue_stats()["dropped_total"], 3)

    def test_scanner_exception_is_counted_and_does_not_escape(self):
        watcher = self._watcher()
        self.scanner.scan_file.side_effect = RuntimeError("scanner failed")

        watcher._scan_path("/home/test/a")

        self.assertEqual(watcher.get_queue_stats()["scan_errors_total"], 1)
        self.logger.error.assert_called_once_with(
            "Scanner worker failed for /home/test/a: scanner failed"
        )

    def test_run_returns_true_when_observer_and_worker_start(self):
        watcher = self._watcher()

        class FakeThread:
            def __init__(self, *args, **kwargs):
                self.alive = False

            def start(self):
                self.alive = True

            def is_alive(self):
                return self.alive

        with patch("modules.fs_monitor.threading.Thread", FakeThread):
            self.assertTrue(watcher.run())

    def test_run_returns_false_when_observer_start_fails(self):
        watcher = self._watcher()
        watcher.observer.start = Mock(side_effect=RuntimeError("observer failed"))

        class FakeThread:
            def __init__(self, *args, **kwargs):
                self.alive = False

            def start(self):
                self.alive = True

            def is_alive(self):
                return self.alive

        with patch("modules.fs_monitor.threading.Thread", FakeThread):
            self.assertFalse(watcher.run())

        self.assertFalse(watcher.running)
        self.logger.error.assert_called_with("Observer failed: observer failed")

    def test_stop_drains_queue_and_clears_dedup_state(self):
        watcher = self._watcher(max_size=2)
        watcher._enqueue_once("/home/test/a")
        watcher._enqueue_once("/home/test/b")

        watcher.stop()

        stats = watcher.get_queue_stats()
        self.assertEqual(stats["queued"], 0)
        self.assertEqual(stats["pending"], 0)
        self.assertEqual(stats["dirty"], 0)
        self.assertEqual(stats["recovery_roots_pending"], 0)
        with self.assertRaises(queue.Empty):
            watcher.scan_queue.get_nowait()

    def test_enqueue_is_rejected_after_stop(self):
        watcher = self._watcher(max_size=2)
        watcher.stop()

        self.assertFalse(watcher._enqueue_once("/home/test/late-event"))
        self.assertEqual(watcher.get_queue_stats()["queued"], 0)


class HandlerFilteringTests(unittest.TestCase):
    def test_handler_ignores_system_and_user_cache_paths(self):
        enqueue = Mock()
        handler = Handler(
            enqueue,
            Mock(spec=logging.Logger),
            ("/proc", "/var/log"),
            ignore_user_cache=True,
            clamav_temp_directory="/var/lib/clamav/herodium-tmp",
        )

        self.assertTrue(handler._should_ignore("/proc/1/status"))
        self.assertTrue(handler._should_ignore("/home/alice/.cache/item"))
        self.assertTrue(
            handler._should_ignore(
                "/var/lib/clamav/herodium-tmp/clamav-abc.tmp"
            )
        )
        self.assertFalse(
            handler._should_ignore(
                "/var/lib/clamav/herodium-tmp-evil/sample.bin"
            )
        )
        self.assertFalse(handler._should_ignore("/home/alice/document.txt"))

    def test_handler_ignores_configured_clamav_workspace_only(self):
        handler = Handler(
            Mock(),
            Mock(spec=logging.Logger),
            (),
            clamav_temp_directory="/srv/clamav-work",
        )

        self.assertTrue(handler._should_ignore("/srv/clamav-work"))
        self.assertTrue(handler._should_ignore("/srv/clamav-work/a/b.tmp"))
        self.assertFalse(handler._should_ignore("/srv/clamav-work-other/a.tmp"))
        self.assertFalse(handler._should_ignore("/tmp/clamav-a.tmp"))


if __name__ == "__main__":
    unittest.main()
