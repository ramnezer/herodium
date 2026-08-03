import errno
import logging
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch


PROJECT_ROOT = Path(__file__).resolve().parents[1]
HERODIUM_ROOT = PROJECT_ROOT / "herodium"
if str(HERODIUM_ROOT) not in sys.path:
    sys.path.insert(0, str(HERODIUM_ROOT))

from modules.scan_recovery import ScanRecoveryController  # noqa: E402


class ScanRecoveryControllerTests(unittest.TestCase):
    def setUp(self):
        self.logger = Mock(spec=logging.Logger)
        self.scan_file = Mock()
        self.queue_depth = 0
        self.running = True

    def _controller(self, roots, queue_capacity=4, **values):
        config = {
            "scan_recovery_enable": True,
            "scan_recovery_max_roots": 4,
            "scan_recovery_queue_low_watermark_percent": 25,
            "scan_recovery_max_files_per_pass": 100,
            "scan_recovery_max_total_files_per_root": 1000,
            "scan_recovery_max_seconds_per_pass": 60,
            "scan_recovery_max_depth": 64,
            "scan_recovery_directory_warning_interval_seconds": 30,
        }
        config.update(values)
        return ScanRecoveryController(
            config,
            self.logger,
            queue_capacity=queue_capacity,
            scan_file=self.scan_file,
            should_ignore=lambda path: False,
            queue_size=lambda: self.queue_depth,
            is_running=lambda: self.running,
            watch_roots=roots,
        )

    def test_configuration_is_bounded_and_boolean_safe(self):
        controller = self._controller(
            ["/home"],
            scan_recovery_enable="false",
            scan_recovery_max_roots=9999,
            scan_recovery_queue_low_watermark_percent=999,
            scan_recovery_max_files_per_pass=0,
            scan_recovery_max_total_files_per_root=9999999,
            scan_recovery_max_seconds_per_pass=0,
            scan_recovery_max_depth=9999,
        )

        self.assertFalse(controller.enabled)
        self.assertEqual(controller.max_roots, 128)
        self.assertEqual(controller.low_watermark_percent, 90)
        self.assertEqual(controller.max_files_per_pass, 1)
        self.assertEqual(controller.max_total_files_per_root, 1000000)
        self.assertEqual(controller.max_seconds_per_pass, 1)
        self.assertEqual(controller.max_depth, 256)

    def test_schedule_coalesces_one_watched_root(self):
        controller = self._controller(["/home"])

        self.assertEqual(
            controller.schedule("/home/alice/first.bin"),
            "/home",
        )
        self.assertIsNone(controller.schedule("/home/alice/second.bin"))
        self.assertEqual(controller.stats()["recovery_roots_pending"], 1)

    def test_root_count_is_bounded(self):
        controller = self._controller(
            ["/home", "/tmp"],
            scan_recovery_max_roots=1,
        )

        self.assertEqual(controller.schedule("/home/a"), "/home")
        self.assertIsNone(controller.schedule("/tmp/b"))
        stats = controller.stats()
        self.assertEqual(stats["recovery_roots_pending"], 1)
        self.assertEqual(stats["recovery_roots_rejected"], 1)

    def test_recovery_waits_for_low_watermark(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            Path(temp_dir, "sample.bin").write_bytes(b"sample")
            controller = self._controller([temp_dir], queue_capacity=4)
            controller.schedule(str(Path(temp_dir, "dropped.bin")))
            self.queue_depth = 2

            self.assertFalse(controller.run_once())
            self.assertEqual(controller.stats()["recovery_scans_started"], 0)

            self.queue_depth = 1
            self.assertTrue(controller.run_once())
            self.assertEqual(controller.stats()["recovery_scans_started"], 1)

    def test_recovery_scans_venv_and_pycache_files(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            pyc = Path(temp_dir) / ".venv" / "lib" / "__pycache__" / "payload.pyc"
            pyc.parent.mkdir(parents=True)
            pyc.write_bytes(b"payload")
            controller = self._controller([temp_dir])
            controller.schedule(str(pyc), root_hint=temp_dir)

            self.assertTrue(controller.run_once())

            scanned = [call.args[0] for call in self.scan_file.call_args_list]
            self.assertIn(str(pyc), scanned)
            stats = controller.stats()
            self.assertEqual(stats["recovery_files_scanned"], 1)
            self.assertEqual(stats["recovery_roots_completed"], 1)
            self.assertEqual(stats["recovery_roots_pending"], 0)

    def test_recovery_resumes_without_starting_second_scan(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            for index in range(3):
                Path(temp_dir, f"file-{index}").write_bytes(b"x")
            controller = self._controller(
                [temp_dir],
                scan_recovery_max_files_per_pass=1,
            )
            controller.schedule(str(Path(temp_dir, "dropped")))

            for _ in range(4):
                controller.run_once()

            stats = controller.stats()
            self.assertEqual(stats["recovery_scans_started"], 1)
            self.assertEqual(stats["recovery_files_scanned"], 3)
            self.assertEqual(stats["recovery_roots_completed"], 1)

    def test_total_file_limit_truncates_root(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            for index in range(4):
                Path(temp_dir, f"file-{index}").write_bytes(b"x")
            controller = self._controller(
                [temp_dir],
                scan_recovery_max_total_files_per_root=2,
            )
            controller.schedule(str(Path(temp_dir, "dropped")))

            controller.run_once(events_dropped=10)

            stats = controller.stats()
            self.assertEqual(stats["recovery_files_scanned"], 2)
            self.assertEqual(stats["recovery_roots_truncated"], 1)
            self.assertEqual(stats["recovery_roots_pending"], 0)
            self.logger.warning.assert_called_with(
                "Scan recovery truncated: "
                f"root={temp_dir}, files_scanned=2, "
                "recovery_files_scanned_total=2, events_dropped=10, "
                "recovery_roots_pending=0"
            )

    def test_time_limit_pauses_and_preserves_iterator(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            controller = self._controller(
                [temp_dir],
                scan_recovery_max_seconds_per_pass=1,
            )
            controller.schedule(str(Path(temp_dir, "dropped")))
            first = str(Path(temp_dir, "one"))
            second = str(Path(temp_dir, "two"))
            controller._iter_files = Mock(
                return_value=iter([first, second])
            )

            with patch(
                "modules.scan_recovery.time.monotonic",
                side_effect=[0.0, 0.0, 2.0],
            ):
                self.assertTrue(controller.run_once())

            stats = controller.stats()
            self.assertEqual(stats["recovery_files_scanned"], 1)
            self.assertEqual(stats["recovery_roots_pending"], 1)
            self.assertEqual(stats["recovery_scans_started"], 1)

    def test_depth_limit_prunes_deeper_directories(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            direct = Path(temp_dir) / "level-1" / "direct.bin"
            deep = Path(temp_dir) / "level-1" / "level-2" / "deep.bin"
            direct.parent.mkdir(parents=True)
            deep.parent.mkdir(parents=True)
            direct.write_bytes(b"direct")
            deep.write_bytes(b"deep")
            controller = self._controller(
                [temp_dir],
                scan_recovery_max_depth=1,
            )
            controller.schedule(str(direct), root_hint=temp_dir)

            controller.run_once()

            scanned = [call.args[0] for call in self.scan_file.call_args_list]
            self.assertIn(str(direct), scanned)
            self.assertNotIn(str(deep), scanned)

    def test_transient_directory_errors_are_aggregated_without_warning_flood(self):
        controller = self._controller(["/home"])

        for index in range(20):
            controller._walk_error(
                FileNotFoundError(
                    errno.ENOENT,
                    "No such file or directory",
                    f"/home/disappeared-{index}",
                )
            )

        stats = controller.stats()
        self.assertEqual(stats["recovery_transient_directory_errors"], 20)
        self.assertEqual(stats["recovery_directory_errors"], 0)
        self.logger.warning.assert_not_called()
        self.assertEqual(self.logger.debug.call_count, 20)

    @patch("modules.scan_recovery.time.monotonic")
    def test_unexpected_directory_errors_are_rate_limited(self, monotonic):
        monotonic.side_effect = [100.0, 101.0, 131.0]
        controller = self._controller(["/home"])
        error = PermissionError(
            errno.EACCES,
            "Permission denied",
            "/home/protected",
        )

        controller._walk_error(error)
        controller._walk_error(error)
        controller._walk_error(error)

        self.assertEqual(controller.stats()["recovery_directory_errors"], 3)
        self.assertEqual(self.logger.warning.call_count, 2)

    @patch("modules.scan_recovery.os.path.ismount")
    def test_unmounted_removable_root_is_removed_not_completed(self, ismount):
        with tempfile.TemporaryDirectory() as temp_dir:
            controller = self._controller([temp_dir])
            controller.add_watch_root(temp_dir, removable=True)
            controller.schedule(str(Path(temp_dir, "dropped")), root_hint=temp_dir)
            controller._iter_files = Mock(return_value=iter(()))
            ismount.side_effect = [True, True, False]

            self.assertTrue(controller.run_once())

            stats = controller.stats()
            self.assertEqual(stats["recovery_roots_removed"], 1)
            self.assertEqual(stats["recovery_roots_completed"], 0)
            self.assertEqual(stats["recovery_roots_pending"], 0)
            self.logger.info.assert_any_call(
                f"Scan recovery root removed: root={temp_dir}, "
                "reason=disconnected"
            )

    def test_disconnected_root_is_removed_before_recovery(self):
        temp_dir = tempfile.mkdtemp()
        controller = self._controller([temp_dir])
        controller.schedule(str(Path(temp_dir, "dropped")))
        os.rmdir(temp_dir)

        self.assertFalse(controller.run_once())
        stats = controller.stats()
        self.assertEqual(stats["recovery_roots_removed"], 1)
        self.assertEqual(stats["recovery_roots_pending"], 0)

    def test_remove_watch_root_discards_pending_usb_recovery(self):
        root = "/media/test/asd"
        controller = self._controller([root])
        controller.schedule(f"{root}/dropped.bin", root_hint=root)

        self.assertEqual(controller.remove_watch_root(root, "drive_removed"), 1)
        stats = controller.stats()
        self.assertEqual(stats["recovery_roots_removed"], 1)
        self.assertEqual(stats["recovery_roots_pending"], 0)

    def test_only_one_recovery_runner_can_execute(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            controller = self._controller([temp_dir])
            controller.schedule(str(Path(temp_dir, "dropped")))

            self.assertTrue(controller._run_lock.acquire(blocking=False))
            try:
                self.assertFalse(controller.run_once())
            finally:
                controller._run_lock.release()
            self.assertEqual(controller.stats()["recovery_scans_started"], 0)

    def test_stop_clears_pending_state(self):
        controller = self._controller(["/home"])
        controller.schedule("/home/alice/dropped")

        controller.stop()

        self.assertEqual(controller.stats()["recovery_roots_pending"], 0)
        self.assertIsNone(controller.schedule("/home/alice/new"))


if __name__ == "__main__":
    unittest.main()
