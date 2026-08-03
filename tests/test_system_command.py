import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


PROJECT_ROOT = Path(__file__).resolve().parents[1]
HERODIUM_ROOT = PROJECT_ROOT / "herodium"
if str(HERODIUM_ROOT) not in sys.path:
    sys.path.insert(0, str(HERODIUM_ROOT))

from core.system_command import (  # noqa: E402
    SystemToolUnavailableError,
    run_system_tool,
)


class SystemCommandTests(unittest.TestCase):
    def test_unknown_tool_is_rejected(self):
        with self.assertRaises(SystemToolUnavailableError):
            run_system_tool("not-allowlisted")

    def test_runner_uses_absolute_resolved_path_and_disables_shell(self):
        completed = SimpleNamespace(returncode=0, stdout="ok", stderr="")
        with patch(
            "core.system_command.resolve_system_tool",
            return_value=Path("/usr/bin/systemctl"),
        ), patch(
            "core.system_command.subprocess.run",
            return_value=completed,
        ) as run_mock:
            result = run_system_tool(
                "systemctl",
                ("is-active", "herodium.service"),
                capture=True,
                timeout=5,
            )

        self.assertIs(result, completed)
        command = run_mock.call_args.args[0]
        kwargs = run_mock.call_args.kwargs
        self.assertEqual(
            command,
            ["/usr/bin/systemctl", "is-active", "herodium.service"],
        )
        self.assertIs(kwargs["shell"], False)
        self.assertIs(kwargs["check"], False)
        self.assertIs(kwargs["capture_output"], True)
        self.assertEqual(kwargs["timeout"], 5)

    def test_capture_and_quiet_are_mutually_exclusive(self):
        with self.assertRaises(ValueError):
            run_system_tool("systemctl", capture=True, quiet=True)


if __name__ == "__main__":
    unittest.main()
