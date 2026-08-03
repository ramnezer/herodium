import logging
import sys
import tempfile
import threading
import types
import unittest
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

import modules.av_scanner as av_scanner_module  # noqa: E402
from modules.av_scanner import (  # noqa: E402
    ClamAVScanner,
    ScanReason,
    ScanResult,
    ScanStatus,
)


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


if __name__ == "__main__":
    unittest.main()
