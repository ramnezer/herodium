import logging
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch


PROJECT_ROOT = Path(__file__).resolve().parents[1]
HERODIUM_ROOT = PROJECT_ROOT / "herodium"
if str(HERODIUM_ROOT) not in sys.path:
    sys.path.insert(0, str(HERODIUM_ROOT))

from modules.notifier import Notifier  # noqa: E402


class NotifierTests(unittest.TestCase):
    def test_string_false_disables_notifications(self):
        notifier = Notifier(
            {"notifications": {"enable": "false"}},
            Mock(spec=logging.Logger),
        )
        self.assertFalse(notifier.enabled)
        self.assertFalse(notifier.send_notification("title", "message"))

    def test_dispatch_uses_fixed_resolved_executables(self):
        logger = Mock(spec=logging.Logger)
        notifier = Notifier({}, logger)
        completed = SimpleNamespace(returncode=0, stdout="", stderr="")

        resolved = {
            "env": Path("/usr/bin/env"),
            "notify-send": Path("/usr/bin/notify-send"),
        }
        with patch(
            "modules.notifier.resolve_system_tool",
            side_effect=lambda name: resolved[name],
        ), patch(
            "modules.notifier.system_tool_available",
            side_effect=lambda name: name == "sudo",
        ), patch(
            "modules.notifier.run_system_tool",
            return_value=completed,
        ) as run_mock:
            result = notifier._dispatch(
                "test",
                1000,
                Path("/run/user/1000/bus"),
                "Title",
                "Message",
                "critical",
            )

        self.assertTrue(result)
        tool_name, arguments = run_mock.call_args.args[:2]
        self.assertEqual(tool_name, "sudo")
        self.assertEqual(
            arguments[:4],
            [
                "-u",
                "test",
                "/usr/bin/env",
                "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus",
            ],
        )
        self.assertIn("/usr/bin/notify-send", arguments)
        self.assertTrue(run_mock.call_args.kwargs["quiet"])


if __name__ == "__main__":
    unittest.main()
