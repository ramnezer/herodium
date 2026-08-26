import logging
import sys
import tempfile
import threading
import types
import unittest
from importlib import import_module
from pathlib import Path
from unittest.mock import Mock, patch

PROJECT_ROOT = Path(__file__).resolve().parents[1]
HERODIUM_ROOT = PROJECT_ROOT / "herodium"
if str(HERODIUM_ROOT) not in sys.path:
    sys.path.insert(0, str(HERODIUM_ROOT))

# Keep contract tests independent from the host package set. Production uses
# the real pyClamd package installed by Herodium's requirements.
if "pyclamd" not in sys.modules:
    pyclamd_stub = types.ModuleType("pyclamd")
    pyclamd_stub.ClamdUnixSocket = Mock()
    sys.modules["pyclamd"] = pyclamd_stub

av_scanner_module = import_module("modules.av_scanner")

ClamAVScanner = av_scanner_module.ClamAVScanner
ScanReason = av_scanner_module.ScanReason
ScanResult = av_scanner_module.ScanResult
ScanStatus = av_scanner_module.ScanStatus


class FakeClamd:
    def __init__(self, response=None, error=None):
        self.response = response
        self.error = error
        self.received = []

    def scan_stream(self, content):
        self.received.append(content)
        if self.error is not None:
            raise self.error
        return self.response


class ReplacingClamd:
    def __init__(self, path, replacement, response):
        self.path = Path(path)
        self.replacement = replacement
        self.response = response
        self.received = []

    def scan_stream(self, content):
        self.received.append(content)
        self.path.unlink()
        self.path.write_bytes(self.replacement)
        return self.response


class ClamAVScanContractTests(unittest.TestCase):
    def setUp(self):
        self.logger = Mock(spec=logging.Logger)

    def _scanner(self, clamd=None):
        scanner = object.__new__(ClamAVScanner)
        scanner.config = {}
        scanner.logger = self.logger
        scanner.quarantine_dir = str(
            Path(tempfile.gettempdir()) / "herodium-test-quarantine"
        )
        scanner.socket_path = "/run/clamav/clamd.ctl"
        scanner.max_file_size_mb = 25
        scanner.stream_max_length_mb = 25
        scanner.effective_max_file_size_mb = 25
        scanner.action_policy = "alert"
        scanner.lock = threading.Lock()
        scanner.cd = clamd
        scanner.notifier = Mock()
        scanner._connect = Mock(return_value=clamd is not None)
        scanner._handle_threat = Mock()
        return scanner

    def test_connect_accepts_pyclamd_boolean_ping_response(self):
        scanner = self._scanner(None)
        client = Mock()
        client.ping.return_value = True

        with patch.object(
            av_scanner_module.pyclamd,
            "ClamdUnixSocket",
            return_value=client,
        ):
            connected = ClamAVScanner._connect(scanner)

        self.assertTrue(connected)
        self.assertIs(scanner.cd, client)
        self.logger.info.assert_called_with("Connected to ClamAV Daemon.")

    def test_connect_accepts_protocol_pong_response(self):
        scanner = self._scanner(None)
        client = Mock()
        client.ping.return_value = b"PONG\n"

        with patch.object(
            av_scanner_module.pyclamd,
            "ClamdUnixSocket",
            return_value=client,
        ):
            connected = ClamAVScanner._connect(scanner)

        self.assertTrue(connected)
        self.assertIs(scanner.cd, client)

    def test_connect_rejects_invalid_ping_response(self):
        scanner = self._scanner(None)
        client = Mock()
        client.ping.return_value = False

        with patch.object(
            av_scanner_module.pyclamd,
            "ClamdUnixSocket",
            return_value=client,
        ):
            connected = ClamAVScanner._connect(scanner)

        self.assertFalse(connected)
        self.assertIsNone(scanner.cd)
        self.logger.error.assert_called_with(
            "ClamAV Connection Failed: invalid ping response False"
        )

    def test_health_check_accepts_existing_live_client(self):
        client = Mock()
        client.ping.return_value = True
        scanner = self._scanner(client)
        scanner._connect = Mock(return_value=False)

        self.assertTrue(scanner.health_check())
        scanner._connect.assert_not_called()

    def test_health_check_reconnects_after_invalid_existing_client(self):
        client = Mock()
        client.ping.return_value = False
        scanner = self._scanner(client)
        replacement = Mock()

        def reconnect():
            scanner.cd = replacement
            return True

        scanner._connect = Mock(side_effect=reconnect)

        self.assertTrue(scanner.health_check())
        self.assertIs(scanner.cd, replacement)
        scanner._connect.assert_called_once_with()

    def test_clean_file_returns_clean_status(self):
        clamd = FakeClamd(response=None)
        scanner = self._scanner(clamd)

        with tempfile.NamedTemporaryFile() as sample:
            sample.write(b"clean content")
            sample.flush()
            result = scanner.scan_file(sample.name)

        self.assertEqual(result.status, ScanStatus.CLEAN)
        self.assertTrue(result.completed)
        self.assertFalse(result.retryable)
        self.assertEqual(clamd.received, [b"clean content"])

    def test_found_response_returns_infected_and_executes_policy(self):
        clamd = FakeClamd(
            response={"stream": ("FOUND", "Test.Signature")}
        )
        scanner = self._scanner(clamd)

        with tempfile.NamedTemporaryFile() as sample:
            sample.write(b"infected content")
            sample.flush()
            result = scanner.scan_file(sample.name)

        self.assertEqual(result.status, ScanStatus.INFECTED)
        self.assertEqual(result.threat_name, "Test.Signature")
        scanner._handle_threat.assert_called_once()

    def test_delete_refuses_replacement_created_after_scanned_bytes_are_read(self):
        with tempfile.TemporaryDirectory() as temp_root:
            root = Path(temp_root)
            source = root / "infected.bin"
            source.write_bytes(b"original infected content")
            clamd = ReplacingClamd(
                source,
                b"replacement benign content",
                {"stream": ("FOUND", "Test.Signature")},
            )
            scanner = self._scanner(clamd)
            scanner.action_policy = "delete"
            scanner._handle_threat = ClamAVScanner._handle_threat.__get__(scanner)

            result = scanner.scan_file(source)

            self.assertEqual(result.status, ScanStatus.INFECTED)
            self.assertEqual(clamd.received, [b"original infected content"])
            self.assertEqual(source.read_bytes(), b"replacement benign content")
            scanner.notifier.send_notification.assert_not_called()
            self.logger.error.assert_called_with(
                "Delete refused because source identity changed after scan: "
                f"{source}"
            )

    def test_quarantine_refuses_replacement_created_after_scanned_bytes_are_read(self):
        with tempfile.TemporaryDirectory() as temp_root:
            root = Path(temp_root)
            source = root / "infected.bin"
            quarantine = root / "quarantine"
            source.write_bytes(b"original infected content")
            clamd = ReplacingClamd(
                source,
                b"replacement benign content",
                {"stream": ("FOUND", "Test.Signature")},
            )
            scanner = self._scanner(clamd)
            scanner.action_policy = "quarantine"
            scanner.quarantine_dir = str(quarantine)
            scanner._handle_threat = ClamAVScanner._handle_threat.__get__(scanner)

            result = scanner.scan_file(source)

            self.assertEqual(result.status, ScanStatus.INFECTED)
            self.assertEqual(clamd.received, [b"original infected content"])
            self.assertEqual(source.read_bytes(), b"replacement benign content")
            self.assertFalse(quarantine.exists())
            scanner.notifier.send_notification.assert_not_called()
            self.logger.error.assert_called_with(
                "Quarantine refused because source identity changed after scan: "
                f"{source}"
            )

    def test_delete_removes_same_file_identity_that_was_scanned(self):
        clamd = FakeClamd(response={"stream": ("FOUND", "Test.Signature")})
        scanner = self._scanner(clamd)
        scanner.action_policy = "delete"
        scanner._handle_threat = ClamAVScanner._handle_threat.__get__(scanner)

        with tempfile.TemporaryDirectory() as temp_root:
            source = Path(temp_root) / "infected.bin"
            source.write_bytes(b"infected content")

            result = scanner.scan_file(source)

            self.assertEqual(result.status, ScanStatus.INFECTED)
            self.assertFalse(source.exists())
            scanner.notifier.send_notification.assert_called_once()

    def test_quarantine_removes_same_file_identity_that_was_scanned(self):
        clamd = FakeClamd(response={"stream": ("FOUND", "Test.Signature")})
        scanner = self._scanner(clamd)
        scanner.action_policy = "quarantine"
        scanner._handle_threat = ClamAVScanner._handle_threat.__get__(scanner)

        with tempfile.TemporaryDirectory() as temp_root:
            root = Path(temp_root)
            source = root / "infected.bin"
            quarantine = root / "quarantine"
            source.write_bytes(b"infected content")
            scanner.quarantine_dir = str(quarantine)

            with (
                patch.object(av_scanner_module.os, "chown"),
                patch.object(av_scanner_module.os, "fchown"),
            ):
                result = scanner.scan_file(source)

            self.assertEqual(result.status, ScanStatus.INFECTED)
            self.assertFalse(source.exists())
            quarantined = list(quarantine.iterdir())
            self.assertEqual(len(quarantined), 1)
            self.assertEqual(quarantined[0].read_bytes(), b"infected content")
            scanner.notifier.send_notification.assert_called_once()

    def test_missing_file_returns_skipped(self):
        scanner = self._scanner(FakeClamd())

        missing_path = Path(tempfile.gettempdir()) / "herodium-missing-sample"
        result = scanner.scan_file(missing_path)

        self.assertEqual(result.status, ScanStatus.SKIPPED)
        self.assertEqual(result.reason, ScanReason.FILE_NOT_FOUND)

    def test_empty_file_returns_skipped(self):
        scanner = self._scanner(FakeClamd())

        with tempfile.NamedTemporaryFile() as sample:
            result = scanner.scan_file(sample.name)

        self.assertEqual(result.status, ScanStatus.SKIPPED)
        self.assertEqual(result.reason, ScanReason.EMPTY_FILE)

    def test_oversized_file_returns_skipped(self):
        scanner = self._scanner(FakeClamd())
        scanner.effective_max_file_size_mb = 1

        with tempfile.NamedTemporaryFile() as sample:
            sample.truncate((1024 * 1024) + 1)
            result = scanner.scan_file(sample.name)

        self.assertEqual(result.status, ScanStatus.SKIPPED)
        self.assertEqual(result.reason, ScanReason.FILE_TOO_LARGE)

    def test_unavailable_daemon_is_explicit(self):
        scanner = self._scanner(None)

        with tempfile.NamedTemporaryFile() as sample:
            sample.write(b"content")
            sample.flush()
            result = scanner.scan_file(sample.name)

        self.assertEqual(result.status, ScanStatus.UNAVAILABLE)
        self.assertEqual(result.reason, ScanReason.CLAMAV_UNAVAILABLE)
        self.assertTrue(result.retryable)

    def test_transport_failure_resets_client_and_is_retryable(self):
        scanner = self._scanner(FakeClamd(error=BrokenPipeError("closed")))

        with tempfile.NamedTemporaryFile() as sample:
            sample.write(b"content")
            sample.flush()
            result = scanner.scan_file(sample.name)

        self.assertEqual(result.status, ScanStatus.UNAVAILABLE)
        self.assertEqual(result.reason, ScanReason.SCAN_FAILED)
        self.assertIsNone(scanner.cd)
        self.assertTrue(result.retryable)

    def test_invalid_response_returns_error(self):
        scanner = self._scanner(FakeClamd(response={"unexpected": "value"}))

        with tempfile.NamedTemporaryFile() as sample:
            sample.write(b"content")
            sample.flush()
            result = scanner.scan_file(sample.name)

        self.assertEqual(result.status, ScanStatus.ERROR)
        self.assertEqual(result.reason, ScanReason.INVALID_RESPONSE)
        self.assertTrue(result.retryable)

    def test_scan_result_rejects_implicit_boolean_use(self):
        sample_path = str(Path(tempfile.gettempdir()) / "sample")
        result = ScanResult(ScanStatus.CLEAN, sample_path)

        with self.assertRaisesRegex(TypeError, "inspect result.status explicitly"):
            bool(result)

    def test_quarantine_normalizes_root_ownership_and_private_modes(self):
        scanner = self._scanner(None)
        scanner.notifier = Mock()

        with tempfile.TemporaryDirectory() as temp_root:
            root = Path(temp_root)
            source = root / "infected.bin"
            quarantine = root / "quarantine"
            source.write_bytes(b"infected")
            scanner.quarantine_dir = str(quarantine)

            with (
                patch.object(av_scanner_module.os, "chown") as chown,
                patch.object(av_scanner_module.os, "fchown") as fchown,
            ):
                scanner._quarantine(str(source), "Test.Signature")

            quarantined = list(quarantine.iterdir())
            self.assertEqual(len(quarantined), 1)
            destination = quarantined[0]
            self.assertEqual(destination.read_bytes(), b"infected")
            self.assertFalse(source.exists())
            self.assertEqual(quarantine.stat().st_mode & 0o777, 0o700)
            self.assertEqual(destination.stat().st_mode & 0o777, 0o600)
            chown.assert_called_once_with(str(quarantine), 0, 0)
            fchown.assert_called_once()
            self.assertEqual(fchown.call_args.args[1:], (0, 0))
            scanner.notifier.send_notification.assert_called_once()

    def test_quarantine_rejects_symlink_source_without_touching_target(self):
        scanner = self._scanner(None)
        scanner.notifier = Mock()

        with tempfile.TemporaryDirectory() as temp_root:
            root = Path(temp_root)
            target = root / "target.bin"
            source = root / "infected-link"
            quarantine = root / "quarantine"
            target.write_bytes(b"keep")
            source.symlink_to(target)
            scanner.quarantine_dir = str(quarantine)

            scanner._quarantine(str(source), "Test.Signature")

            self.assertTrue(source.is_symlink())
            self.assertEqual(target.read_bytes(), b"keep")
            self.assertFalse(quarantine.exists())
            scanner.notifier.send_notification.assert_not_called()
            self.logger.error.assert_called_with(
                f"Quarantine refused non-regular source path: {source}"
            )

    def test_quarantine_hardening_failure_removes_incomplete_copy(self):
        scanner = self._scanner(None)
        scanner.notifier = Mock()

        with tempfile.TemporaryDirectory() as temp_root:
            root = Path(temp_root)
            source = root / "infected.bin"
            quarantine = root / "quarantine"
            source.write_bytes(b"infected")
            scanner.quarantine_dir = str(quarantine)

            with (
                patch.object(av_scanner_module.os, "chown"),
                patch.object(
                    av_scanner_module.os,
                    "fchown",
                    side_effect=PermissionError("simulated chown failure"),
                ),
            ):
                scanner._quarantine(str(source), "Test.Signature")

            self.assertEqual(list(quarantine.iterdir()), [])
            self.assertTrue(source.exists())
            scanner.notifier.send_notification.assert_not_called()
            self.logger.error.assert_called()


if __name__ == "__main__":
    unittest.main()
