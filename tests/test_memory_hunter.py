import logging
import stat
import sys
import tempfile
import types
import unittest
from importlib import import_module
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

PROJECT_ROOT = Path(__file__).resolve().parents[1]
HERODIUM_ROOT = PROJECT_ROOT / "herodium"
if str(HERODIUM_ROOT) not in sys.path:
    sys.path.insert(0, str(HERODIUM_ROOT))

# Keep tests independent from the host package set. Production uses the real
# pyClamd package installed by Herodium's requirements.
if "pyclamd" not in sys.modules:
    pyclamd_stub = types.ModuleType("pyclamd")
    pyclamd_stub.ClamdUnixSocket = Mock()
    sys.modules["pyclamd"] = pyclamd_stub

av_scanner_module = import_module("modules.av_scanner")
memory_hunter_module = import_module("modules.memory_hunter")

ScanReason = av_scanner_module.ScanReason
ScanResult = av_scanner_module.ScanResult
ScanStatus = av_scanner_module.ScanStatus
MemoryHunter = memory_hunter_module.MemoryHunter


class FakeProcess:
    def __init__(self, pid, name, exe, create_time, cmdline=None, cwd=None):
        self.info = {
            "pid": pid,
            "name": name,
            "exe": exe,
            "cmdline": cmdline or [exe],
            "create_time": create_time,
            "cwd": cwd,
        }
        self.terminated = False
        self.killed = False

    def terminate(self):
        self.terminated = True

    def wait(self, timeout):
        return timeout

    def kill(self):
        self.killed = True


class SequenceScanner:
    def __init__(self, results, action_policy="quarantine"):
        self.results = list(results)
        self.action_policy = action_policy
        self.calls = []

    def scan_file(self, path):
        self.calls.append(path)
        if not self.results:
            raise AssertionError("No scan result configured")
        return self.results.pop(0)


class MemoryHunterWhitelistTests(unittest.TestCase):
    def setUp(self):
        self.logger = Mock(spec=logging.Logger)

    def _hunter(self):
        hunter = object.__new__(MemoryHunter)
        hunter.logger = self.logger
        hunter.whitelist_identities = {}
        return hunter

    def test_name_only_whitelist_entry_is_rejected(self):
        hunter = self._hunter()

        hunter._register_whitelist_path("firefox")

        self.assertEqual(hunter.whitelist_identities, {})
        self.logger.warning.assert_called_once()

    def test_spoofed_basename_is_not_whitelisted(self):
        hunter = self._hunter()
        hunter.whitelist_identities = {
            "/usr/lib/firefox/firefox": (10, 20),
        }

        self.assertFalse(
            hunter._is_whitelisted_process(1234, "/tmp/firefox")
        )

    def test_exact_path_requires_matching_process_inode(self):
        hunter = self._hunter()
        trusted_path = "/usr/bin/gnome-shell"
        hunter.whitelist_identities = {trusted_path: (10, 20)}
        proc_metadata = SimpleNamespace(st_dev=10, st_ino=21)

        with (
            patch(
                "modules.memory_hunter.os.path.realpath",
                return_value=trusted_path,
            ),
            patch.object(
                hunter,
                "_trusted_executable_identity",
                return_value=(10, 20),
            ),
            patch("modules.memory_hunter.os.stat", return_value=proc_metadata),
        ):
            self.assertFalse(
                hunter._is_whitelisted_process(1234, trusted_path)
            )

    def test_exact_trusted_process_identity_is_whitelisted(self):
        hunter = self._hunter()
        trusted_path = "/usr/bin/gnome-shell"
        hunter.whitelist_identities = {trusted_path: (10, 20)}
        proc_metadata = SimpleNamespace(st_dev=10, st_ino=20)

        with (
            patch(
                "modules.memory_hunter.os.path.realpath",
                return_value=trusted_path,
            ),
            patch.object(
                hunter,
                "_trusted_executable_identity",
                return_value=(10, 20),
            ),
            patch("modules.memory_hunter.os.stat", return_value=proc_metadata),
        ):
            self.assertTrue(
                hunter._is_whitelisted_process(1234, trusted_path)
            )

    def test_replaced_whitelist_path_identity_is_rejected(self):
        hunter = self._hunter()
        trusted_path = "/usr/bin/gnome-shell"
        hunter.whitelist_identities = {trusted_path: (10, 20)}

        with (
            patch(
                "modules.memory_hunter.os.path.realpath",
                return_value=trusted_path,
            ),
            patch.object(
                hunter,
                "_trusted_executable_identity",
                return_value=(10, 99),
            ),
        ):
            self.assertFalse(
                hunter._is_whitelisted_process(1234, trusted_path)
            )

    def test_trusted_identity_requires_root_owned_nonwritable_executable(self):
        hunter = self._hunter()
        trusted = SimpleNamespace(
            st_mode=stat.S_IFREG | 0o755,
            st_uid=0,
            st_dev=10,
            st_ino=20,
        )

        with patch("modules.memory_hunter.os.stat", return_value=trusted):
            self.assertEqual(
                hunter._trusted_executable_identity("/trusted/tool"),
                (10, 20),
            )

        rejected = (
            SimpleNamespace(
                st_mode=stat.S_IFREG | 0o755,
                st_uid=1000,
                st_dev=10,
                st_ino=20,
            ),
            SimpleNamespace(
                st_mode=stat.S_IFREG | 0o775,
                st_uid=0,
                st_dev=10,
                st_ino=20,
            ),
            SimpleNamespace(
                st_mode=stat.S_IFREG | 0o644,
                st_uid=0,
                st_dev=10,
                st_ino=20,
            ),
        )
        for metadata in rejected:
            with self.subTest(metadata=metadata), patch(
                "modules.memory_hunter.os.stat",
                return_value=metadata,
            ):
                self.assertIsNone(
                    hunter._trusted_executable_identity("/trusted/tool")
                )


class MemoryHunterCacheTests(unittest.TestCase):
    def setUp(self):
        self.logger = Mock(spec=logging.Logger)
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.sample_path = Path(self.temp_dir.name) / "sample.bin"
        self.sample_path.write_bytes(b"sample")

    def _hunter(self, scanner):
        hunter = object.__new__(MemoryHunter)
        hunter.logger = self.logger
        hunter.scanner = scanner
        hunter.kill_infected_process = True
        hunter.whitelist_identities = {}
        hunter.scanned_cache = {}
        return hunter

    def _process(self, pid=100, create_time=10.0):
        return FakeProcess(
            pid=pid,
            name="sample-process",
            exe=str(self.sample_path),
            create_time=create_time,
        )

    def _run_scan(self, hunter, processes):
        with patch(
            "modules.memory_hunter.psutil.process_iter",
            return_value=processes,
        ):
            hunter.flash_scan()

    def test_spoofed_whitelist_basename_is_still_scanned(self):
        spoofed_path = Path(self.temp_dir.name) / "firefox"
        spoofed_path.write_bytes(b"not-a-trusted-firefox")
        clean = ScanResult(ScanStatus.CLEAN, str(spoofed_path))
        scanner = SequenceScanner([clean])
        hunter = self._hunter(scanner)
        hunter.whitelist_identities = {
            "/usr/lib/firefox/firefox": (10, 20),
        }
        process = FakeProcess(
            pid=100,
            name="firefox",
            exe=str(spoofed_path),
            create_time=10.0,
        )

        self._run_scan(hunter, [process])

        self.assertEqual(scanner.calls, [str(spoofed_path)])

    def test_clean_process_is_cached_and_not_rescanned(self):
        result = ScanResult(ScanStatus.CLEAN, str(self.sample_path))
        scanner = SequenceScanner([result])
        hunter = self._hunter(scanner)
        process = self._process()

        self._run_scan(hunter, [process])
        self._run_scan(hunter, [process])

        self.assertEqual(scanner.calls, [str(self.sample_path)])
        self.assertEqual(hunter.scanned_cache, {100: 10.0})

    def test_unavailable_process_is_left_uncached_and_retried(self):
        unavailable = ScanResult(
            ScanStatus.UNAVAILABLE,
            str(self.sample_path),
            ScanReason.CLAMAV_UNAVAILABLE,
        )
        clean = ScanResult(ScanStatus.CLEAN, str(self.sample_path))
        scanner = SequenceScanner([unavailable, clean])
        hunter = self._hunter(scanner)
        process = self._process()

        self._run_scan(hunter, [process])
        self.assertNotIn(100, hunter.scanned_cache)

        self._run_scan(hunter, [process])

        self.assertEqual(
            scanner.calls,
            [str(self.sample_path), str(self.sample_path)],
        )
        self.assertEqual(hunter.scanned_cache, {100: 10.0})

    def test_error_process_is_left_uncached_and_retried(self):
        error = ScanResult(
            ScanStatus.ERROR,
            str(self.sample_path),
            ScanReason.READ_FAILED,
        )
        clean = ScanResult(ScanStatus.CLEAN, str(self.sample_path))
        scanner = SequenceScanner([error, clean])
        hunter = self._hunter(scanner)
        process = self._process()

        self._run_scan(hunter, [process])
        self.assertNotIn(100, hunter.scanned_cache)

        self._run_scan(hunter, [process])

        self.assertEqual(len(scanner.calls), 2)
        self.assertEqual(hunter.scanned_cache, {100: 10.0})

    def test_relative_command_file_is_resolved_against_process_cwd(self):
        script_path = Path(self.temp_dir.name) / "evil.py"
        script_path.write_bytes(b"script")

        executable_clean = ScanResult(ScanStatus.CLEAN, str(self.sample_path))
        script_clean = ScanResult(ScanStatus.CLEAN, str(script_path))
        scanner = SequenceScanner([executable_clean, script_clean])
        hunter = self._hunter(scanner)
        process = FakeProcess(
            pid=100,
            name="python3",
            exe=str(self.sample_path),
            create_time=10.0,
            cmdline=[str(self.sample_path), "./evil.py"],
            cwd=self.temp_dir.name,
        )

        self._run_scan(hunter, [process])

        self.assertEqual(
            scanner.calls,
            sorted([str(self.sample_path), str(script_path)]),
        )

    def test_bare_relative_command_file_is_resolved_against_process_cwd(self):
        script_path = Path(self.temp_dir.name) / "payload.sh"
        script_path.write_bytes(b"script")

        executable_clean = ScanResult(ScanStatus.CLEAN, str(self.sample_path))
        script_clean = ScanResult(ScanStatus.CLEAN, str(script_path))
        scanner = SequenceScanner([executable_clean, script_clean])
        hunter = self._hunter(scanner)
        process = FakeProcess(
            pid=100,
            name="bash",
            exe=str(self.sample_path),
            create_time=10.0,
            cmdline=[str(self.sample_path), "payload.sh"],
            cwd=self.temp_dir.name,
        )

        self._run_scan(hunter, [process])

        self.assertEqual(
            scanner.calls,
            sorted([str(self.sample_path), str(script_path)]),
        )

    def test_relative_command_file_without_absolute_cwd_is_not_guessed(self):
        script_path = Path(self.temp_dir.name) / "evil.py"
        script_path.write_bytes(b"script")

        executable_clean = ScanResult(ScanStatus.CLEAN, str(self.sample_path))
        scanner = SequenceScanner([executable_clean])
        hunter = self._hunter(scanner)
        process = FakeProcess(
            pid=100,
            name="python3",
            exe=str(self.sample_path),
            create_time=10.0,
            cmdline=[str(self.sample_path), "./evil.py"],
            cwd=None,
        )

        self._run_scan(hunter, [process])

        self.assertEqual(scanner.calls, [str(self.sample_path)])

    def test_command_file_argument_rejects_nul_and_relative_invalid_cwd(self):
        hunter = self._hunter(SequenceScanner([]))

        self.assertIsNone(
            hunter._resolve_command_file_argument(
                "evil.py\x00ignored",
                self.temp_dir.name,
            )
        )
        self.assertIsNone(
            hunter._resolve_command_file_argument("evil.py", "relative/cwd")
        )

    def test_option_like_relative_argument_is_not_treated_as_file(self):
        option_path = Path(self.temp_dir.name) / "-c"
        option_path.write_bytes(b"not a command file")

        executable_clean = ScanResult(ScanStatus.CLEAN, str(self.sample_path))
        scanner = SequenceScanner([executable_clean])
        hunter = self._hunter(scanner)
        process = FakeProcess(
            pid=100,
            name="python3",
            exe=str(self.sample_path),
            create_time=10.0,
            cmdline=[str(self.sample_path), "-c", "print('ok')"],
            cwd=self.temp_dir.name,
        )

        self._run_scan(hunter, [process])

        self.assertEqual(scanner.calls, [str(self.sample_path)])

    def test_process_is_not_cached_when_any_related_file_needs_retry(self):
        second_path = Path(self.temp_dir.name) / "second.bin"
        second_path.write_bytes(b"second")

        clean = ScanResult(ScanStatus.CLEAN, str(self.sample_path))
        error = ScanResult(
            ScanStatus.ERROR,
            str(second_path),
            ScanReason.READ_FAILED,
        )
        scanner = SequenceScanner([clean, error])
        hunter = self._hunter(scanner)
        process = FakeProcess(
            pid=100,
            name="sample-process",
            exe=str(self.sample_path),
            create_time=10.0,
            cmdline=[str(self.sample_path), str(second_path)],
        )

        self._run_scan(hunter, [process])

        self.assertEqual(
            scanner.calls,
            sorted([str(self.sample_path), str(second_path)]),
        )
        self.assertNotIn(100, hunter.scanned_cache)

    def test_unavailable_scanner_stops_cycle_and_preserves_unvisited_cache(self):
        unavailable = ScanResult(
            ScanStatus.UNAVAILABLE,
            str(self.sample_path),
            ScanReason.SCAN_FAILED,
        )
        scanner = SequenceScanner([unavailable])
        hunter = self._hunter(scanner)
        hunter.scanned_cache = {999: 99.0}

        first = self._process(pid=100, create_time=10.0)
        second = self._process(pid=200, create_time=20.0)

        self._run_scan(hunter, [first, second])

        self.assertEqual(scanner.calls, [str(self.sample_path)])
        self.assertNotIn(100, hunter.scanned_cache)
        self.assertEqual(hunter.scanned_cache.get(999), 99.0)

    def test_unexpected_scan_error_preserves_unvisited_cache(self):
        scanner = SequenceScanner([])
        hunter = self._hunter(scanner)
        hunter.scanned_cache = {999: 99.0}

        self._run_scan(hunter, [self._process()])

        self.assertEqual(hunter.scanned_cache.get(999), 99.0)
        self.logger.error.assert_called_once()

    def test_non_retryable_skipped_result_can_be_cached(self):
        skipped = ScanResult(
            ScanStatus.SKIPPED,
            str(self.sample_path),
            ScanReason.FILE_TOO_LARGE,
        )
        scanner = SequenceScanner([skipped])
        hunter = self._hunter(scanner)

        self._run_scan(hunter, [self._process()])

        self.assertEqual(hunter.scanned_cache, {100: 10.0})

    def test_infected_alert_only_process_is_cached_after_detection(self):
        infected = ScanResult(
            ScanStatus.INFECTED,
            str(self.sample_path),
            threat_name="Test.Signature",
        )
        scanner = SequenceScanner([infected], action_policy="alert")
        hunter = self._hunter(scanner)

        self._run_scan(hunter, [self._process()])

        self.assertEqual(hunter.scanned_cache, {100: 10.0})
        self.logger.warning.assert_called()


    def test_process_identity_is_stable_if_psutil_info_changes_during_scan(self):
        process = self._process()
        infected = ScanResult(
            ScanStatus.INFECTED,
            str(self.sample_path),
            threat_name="Test.Signature",
        )

        class InfoMutatingScanner:
            action_policy = "quarantine"

            def scan_file(self, path):
                process.info.clear()
                return infected

        hunter = self._hunter(InfoMutatingScanner())

        self._run_scan(hunter, [process])

        self.assertTrue(process.terminated)
        self.assertNotIn(100, hunter.scanned_cache)
        self.logger.error.assert_not_called()
        self.logger.critical.assert_any_call(
            "KILLING INFECTED PROCESS: sample-process (PID: 100)"
        )

    def test_infected_terminated_process_is_not_cached(self):
        infected = ScanResult(
            ScanStatus.INFECTED,
            str(self.sample_path),
            threat_name="Test.Signature",
        )
        scanner = SequenceScanner([infected])
        hunter = self._hunter(scanner)
        hunter._kill_process = Mock()

        self._run_scan(hunter, [self._process()])

        hunter._kill_process.assert_called_once()
        self.assertNotIn(100, hunter.scanned_cache)

    def test_completed_cycle_removes_cache_for_expired_processes(self):
        scanner = SequenceScanner([])
        hunter = self._hunter(scanner)
        hunter.scanned_cache = {999: 99.0}

        self._run_scan(hunter, [])

        self.assertEqual(hunter.scanned_cache, {})


if __name__ == "__main__":
    unittest.main()
