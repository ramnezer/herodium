import logging
import socket
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, call, patch


PROJECT_ROOT = Path(__file__).resolve().parents[1]
HERODIUM_ROOT = PROJECT_ROOT / "herodium"
if str(HERODIUM_ROOT) not in sys.path:
    sys.path.insert(0, str(HERODIUM_ROOT))

from modules.network_monitor import MaltrailEvent, NetworkMonitor  # noqa: E402


class NetworkMonitorMaltrailParsingTests(unittest.TestCase):
    def setUp(self):
        config = {
            "notifications": {"enable": False},
            "maltrail": {
                "enable": True,
                "block_traffic": True,
                "desktop_notifications": False,
            },
        }
        self.logger = Mock(spec=logging.Logger)
        self.monitor = NetworkMonitor(config, self.logger)
        self.monitor._block = Mock()
        self.monitor._resolve_and_block = Mock(return_value=True)

    def test_parser_preserves_quoted_fields(self):
        line = (
            '"2026-07-29 14:05:22.994452" sensor 10.0.0.2 55555 '
            '1.1.1.1 443 TCP DNS bad.example "known malicious site" '
            '"reference with ""quoted"" text"\n'
        )

        event = self.monitor._parse_maltrail_line(line)

        self.assertIsInstance(event, MaltrailEvent)
        self.assertEqual(event.trail, "bad.example")
        self.assertEqual(event.trail_info, "known malicious site")
        self.assertEqual(event.reference, 'reference with "quoted" text')

    def test_ip_event_blocks_only_the_trail_ip(self):
        line = (
            '"2026-07-29 14:05:22.994452" sensor 198.51.100.10 55555 '
            '1.1.1.1 443 TCP IP 203.0.113.77 "known malicious" '
            '"reference 9.9.9.9 example.org"\n'
        )

        self.monitor._process_line(line)

        self.monitor._block.assert_called_once_with("203.0.113.77")
        self.monitor._resolve_and_block.assert_not_called()

    def test_decorated_ip_trail_uses_only_the_leading_ip(self):
        line = (
            '"2026-07-29 14:05:22.994452" sensor 198.51.100.10 55555 '
            '1.1.1.1 443 TCP IP "203.0.113.77 (bad.example)" '
            '"known malicious" reference\n'
        )

        self.monitor._process_line(line)

        self.monitor._block.assert_called_once_with("203.0.113.77")
        self.monitor._resolve_and_block.assert_not_called()

    def test_dns_event_resolves_only_the_trail_domain(self):
        line = (
            '"2026-07-29 14:05:22.994452" sensor 198.51.100.10 55555 '
            '1.1.1.1 53 UDP DNS "sub.(bad.example)" "known malicious" '
            '"reference 9.9.9.9 good.example"\n'
        )

        self.monitor._process_line(line)

        self.monitor._resolve_and_block.assert_called_once_with("sub.bad.example")
        self.monitor._block.assert_not_called()

    def test_url_event_resolves_only_the_trail_host(self):
        line = (
            '"2026-07-29 14:05:22.994452" sensor 198.51.100.10 55555 '
            '1.1.1.1 80 TCP URL "https://bad.example/dropper.exe" '
            '"known malicious" "reference good.example"\n'
        )

        self.monitor._process_line(line)

        self.monitor._resolve_and_block.assert_called_once_with("bad.example")
        self.monitor._block.assert_not_called()

    def test_iport_event_extracts_only_the_trail_ip(self):
        line = (
            '"2026-07-29 14:05:22.994452" sensor 198.51.100.10 55555 '
            '1.1.1.1 443 TCP IPORT 203.0.113.77:8443 "known malicious" '
            'reference\n'
        )

        self.monitor._process_line(line)

        self.monitor._block.assert_called_once_with("203.0.113.77")
        self.monitor._resolve_and_block.assert_not_called()

    def test_official_maltrail_sample_uses_only_trail_field(self):
        line = (
            '"2015-10-19 15:48:41.152513" beast 192.168.5.33 32985 '
            '8.8.8.8 53 UDP DNS 0000mps.webpreview.dsl.net malicious '
            'siteinspector.comodo.com\n'
        )

        self.monitor._process_line(line)

        self.monitor._resolve_and_block.assert_called_once_with(
            "0000mps.webpreview.dsl.net"
        )
        self.monitor._block.assert_not_called()

    def test_non_network_trail_type_alerts_without_blocking(self):
        line = (
            '"2026-07-29 14:05:22.994452" sensor 198.51.100.10 55555 '
            '1.1.1.1 80 TCP UA "agent.bad.example" "suspicious user agent" '
            'reference\n'
        )

        self.monitor._process_line(line)

        self.monitor._block.assert_not_called()
        self.monitor._resolve_and_block.assert_not_called()
        self.logger.warning.assert_called_once()

    def test_malformed_line_is_ignored(self):
        self.monitor._process_line("not a valid Maltrail event")

        self.monitor._block.assert_not_called()
        self.monitor._resolve_and_block.assert_not_called()
        self.logger.warning.assert_not_called()

    def test_invalid_domain_alerts_without_blocking(self):
        line = (
            '"2026-07-29 14:05:22.994452" sensor 198.51.100.10 55555 '
            '1.1.1.1 53 UDP DNS bad..example "known malicious" reference\n'
        )

        self.monitor._process_line(line)

        self.monitor._block.assert_not_called()
        self.monitor._resolve_and_block.assert_not_called()
        self.logger.warning.assert_called_once()


class NetworkMonitorAlertThrottleTests(unittest.TestCase):
    def setUp(self):
        config = {
            "notifications": {"enable": True},
            "maltrail": {
                "enable": True,
                "block_traffic": True,
                "desktop_notifications": True,
                "alert_cooldown_seconds": 300,
                "alert_cache_max_entries": 32,
            },
        }
        self.logger = Mock(spec=logging.Logger)
        self.monitor = NetworkMonitor(config, self.logger)
        self.monitor.notifier.send_notification = Mock(return_value=True)

    @patch("modules.network_monitor.socket.getaddrinfo")
    def test_repeated_unresolved_dns_alerts_are_coalesced(
        self, getaddrinfo
    ):
        self.monitor._alert_now = Mock(
            side_effect=[100.0, 101.0, 401.0]
        )
        self.monitor._dns_now = Mock(
            side_effect=[100.0, 100.0, 101.0, 401.0, 401.0]
        )
        getaddrinfo.side_effect = socket.gaierror(-2, "Name or service not known")
        line = (
            '"2026-07-31 14:00:00.000000" sensor 192.0.2.10 53000 '
            '192.0.2.53 53 UDP DNS morphed.ru malicious reference\n'
        )

        self.monitor._process_line(line)
        self.monitor._process_line(line)
        self.monitor._process_line(line)

        self.assertEqual(
            self.monitor.notifier.send_notification.call_count,
            2,
        )
        self.assertEqual(self.logger.warning.call_count, 2)
        self.logger.debug.assert_any_call(
            "Suppressed duplicate Maltrail alert: %r",
            ("not-blocked", "DNS", "morphed.ru"),
        )
        second_message = (
            self.monitor.notifier.send_notification.call_args_list[1].args[1]
        )
        self.assertIn("1 duplicate alert(s) suppressed", second_message)

    def test_continuous_duplicates_extend_the_quiet_window(self):
        self.monitor._alert_now = Mock(
            side_effect=[100.0, 399.0, 401.0, 702.0]
        )

        for _ in range(4):
            self.monitor._emit_alert(
                ("not-blocked", "DNS", "morphed.ru"),
                "MALTRAIL DETECTION (NOT BLOCKED): type=DNS trail=morphed.ru",
                "Maltrail Detection",
                "Detected DNS: morphed.ru (Not Blocked)",
            )

        self.assertEqual(
            self.monitor.notifier.send_notification.call_count,
            2,
        )
        second_message = (
            self.monitor.notifier.send_notification.call_args_list[1].args[1]
        )
        self.assertIn("2 duplicate alert(s) suppressed", second_message)

    @patch("modules.network_monitor.socket.getaddrinfo")
    def test_dns_flood_does_not_delay_later_ip_enforcement(self, getaddrinfo):
        self.monitor._alert_now = Mock(return_value=100.0)
        self.monitor._dns_now = Mock(return_value=100.0)
        self.monitor._block = Mock()
        getaddrinfo.side_effect = socket.gaierror(
            -2,
            "Name or service not known",
        )
        dns_line = (
            '"2026-08-01 15:00:00.000000" sensor 192.0.2.10 53000 '
            '192.0.2.53 53 UDP DNS morphed.ru malicious reference\n'
        )
        ip_line = (
            '"2026-08-01 15:00:01.000000" sensor 192.0.2.10 53000 '
            '192.0.2.53 53 ICMP IP 136.161.101.53 malicious reference\n'
        )

        for _ in range(700):
            self.monitor._process_line(dns_line)
        self.monitor._process_line(ip_line)

        getaddrinfo.assert_called_once_with("morphed.ru", None)
        self.monitor._block.assert_called_once_with("136.161.101.53")
        self.assertEqual(
            self.monitor.notifier.send_notification.call_count,
            1,
        )

    def test_successful_reblock_after_external_flush_notifies_again(self):
        self.monitor._run_system_tool = Mock(
            side_effect=(
                Mock(returncode=0, stderr=""),
                Mock(returncode=0, stderr=""),
            )
        )

        self.monitor._block("136.161.101.53")
        # A second successful add models an external or scheduled ipset flush
        # between detections. It is a new enforcement transition, not a duplicate.
        self.monitor._block("136.161.101.53")

        self.assertEqual(
            self.monitor.notifier.send_notification.call_count,
            2,
        )
        self.assertEqual(self.logger.warning.call_count, 2)
        self.monitor.notifier.send_notification.assert_has_calls(
            [
                call(
                    "Maltrail Detection",
                    "Blocked Threat: 136.161.101.53",
                    level="critical",
                ),
                call(
                    "Maltrail Detection",
                    "Blocked Threat: 136.161.101.53",
                    level="critical",
                ),
            ]
        )

    def test_existing_ipset_member_does_not_repeat_notification(self):
        self.monitor._run_system_tool = Mock(
            return_value=Mock(returncode=1, stderr="already added")
        )

        self.monitor._block("136.161.101.53")

        self.monitor.notifier.send_notification.assert_not_called()
        self.logger.warning.assert_not_called()

    @patch("modules.network_monitor.time.monotonic")
    def test_alert_cache_is_bounded(self, monotonic):
        monotonic.side_effect = [float(index) for index in range(40)]
        self.monitor.alert_cooldown_seconds = 0
        self.monitor.alert_cache_max_entries = 16

        for index in range(40):
            self.monitor._emit_alert(
                ("test", index),
                f"event {index}",
                "Maltrail Detection",
                f"event {index}",
            )

        self.assertEqual(len(self.monitor._alert_state), 16)


class NetworkMonitorResolutionTests(unittest.TestCase):
    def setUp(self):
        config = {
            "notifications": {"enable": False},
            "maltrail": {
                "enable": True,
                "block_traffic": True,
                "desktop_notifications": False,
            },
        }
        self.logger = Mock(spec=logging.Logger)
        self.monitor = NetworkMonitor(config, self.logger)
        self.monitor._block = Mock()

    @patch("modules.network_monitor.socket.getaddrinfo")
    def test_resolution_deduplicates_addresses(self, getaddrinfo):
        getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.77", 0)),
            (socket.AF_INET, socket.SOCK_DGRAM, 17, "", ("203.0.113.77", 0)),
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::77", 0, 0, 0)),
        ]

        result = self.monitor._resolve_and_block("bad.example")

        self.assertTrue(result)
        self.assertEqual(
            self.monitor._block.call_args_list,
            [
                call("203.0.113.77"),
                call("2001:db8::77"),
            ],
        )

    @patch("modules.network_monitor.socket.getaddrinfo")
    def test_negative_dns_result_is_cached(self, getaddrinfo):
        self.monitor._dns_now = Mock(return_value=100.0)
        getaddrinfo.side_effect = socket.gaierror(
            -2,
            "Name or service not known",
        )

        for _ in range(20):
            self.assertFalse(self.monitor._resolve_and_block("morphed.ru"))

        getaddrinfo.assert_called_once_with("morphed.ru", None)
        self.monitor._block.assert_not_called()


class NetworkMonitorSystemToolTests(unittest.TestCase):
    def setUp(self):
        config = {
            "notifications": {"enable": False},
            "maltrail": {
                "enable": True,
                "block_traffic": True,
                "desktop_notifications": False,
            },
        }
        self.logger = Mock(spec=logging.Logger)
        self.monitor = NetworkMonitor(config, self.logger)

    @patch("modules.network_monitor.subprocess.run")
    def test_system_tool_runner_uses_resolved_absolute_path(self, run):
        self.monitor._system_tools["ipset"] = "/usr/sbin/ipset"

        self.monitor._run_system_tool(
            "ipset",
            ["add", "herodium_blacklist", "203.0.113.77"],
            check=False,
        )

        run.assert_called_once_with(
            [
                "/usr/sbin/ipset",
                "add",
                "herodium_blacklist",
                "203.0.113.77",
            ],
            shell=False,
            check=False,
        )

    def test_system_tool_runner_rejects_unavailable_tool(self):
        self.monitor._system_tools["ipset"] = None

        with self.assertRaisesRegex(
            FileNotFoundError,
            "Required system tool is unavailable: ipset",
        ):
            self.monitor._run_system_tool("ipset", ["list"])




class NetworkMonitorStartupTests(unittest.TestCase):
    def setUp(self):
        self.logger = Mock(spec=logging.Logger)

    @staticmethod
    def _thread_class():
        class FakeThread:
            def __init__(self, *args, **kwargs):
                self.alive = False

            def start(self):
                self.alive = True

            def is_alive(self):
                return self.alive

        return FakeThread

    def test_alert_only_start_reports_healthy_threads(self):
        monitor = NetworkMonitor(
            {
                "notifications": {"enable": False},
                "maltrail": {
                    "enable": True,
                    "block_traffic": False,
                    "desktop_notifications": False,
                },
            },
            self.logger,
        )
        monitor._refresh_critical_infrastructure = Mock()

        with patch(
            "modules.network_monitor.threading.Thread",
            self._thread_class(),
        ):
            self.assertTrue(monitor.start_monitoring())

    def test_blocking_start_reports_failure_when_ipset_is_unavailable(self):
        monitor = NetworkMonitor(
            {
                "notifications": {"enable": False},
                "maltrail": {
                    "enable": True,
                    "block_traffic": True,
                    "desktop_notifications": False,
                },
            },
            self.logger,
        )
        monitor._refresh_critical_infrastructure = Mock()
        monitor._system_tools["ipset"] = None

        self.assertFalse(monitor.start_monitoring())
        self.assertFalse(monitor.running)
        self.logger.error.assert_called_once()

if __name__ == "__main__":
    unittest.main()
