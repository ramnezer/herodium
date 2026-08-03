import importlib.util
import io
import unittest
from contextlib import redirect_stderr
from importlib.machinery import SourceFileLoader
from pathlib import Path
from unittest.mock import Mock, patch


PROJECT_ROOT = Path(__file__).resolve().parents[1]
INSTALLER = PROJECT_ROOT / "installer/install.sh"
UNINSTALLER = PROJECT_ROOT / "installer/uninstall.sh"
SCHEDULER = PROJECT_ROOT / "herodium/modules/scheduler.py"
MANAGER = PROJECT_ROOT / "herodium/modules/rkhunter_manager.py"
TOOL = PROJECT_ROOT / "installer/bin/herodium-rkhunter-baseline"
README = PROJECT_ROOT / "README.md"


def _load_tool_module():
    loader = SourceFileLoader("herodium_rkhunter_baseline_test", str(TOOL))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    if spec is None:
        raise RuntimeError("Unable to load operator tool")
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


class RkhunterBaselineContractTests(unittest.TestCase):
    def test_automatic_paths_do_not_call_propupd(self):
        installer = INSTALLER.read_text(encoding="utf-8")
        scheduler = SCHEDULER.read_text(encoding="utf-8")

        self.assertNotIn("rkhunter --propupd", installer)
        self.assertNotIn("propupd", scheduler)
        self.assertIn("--propupd", MANAGER.read_text(encoding="utf-8"))

    def test_operator_tool_is_installed_and_removed(self):
        installer = INSTALLER.read_text(encoding="utf-8")
        uninstaller = UNINSTALLER.read_text(encoding="utf-8")

        tool_source = installer.index(
            '"${REPO_DIR}/installer/bin/herodium-rkhunter-baseline"'
        )
        tool_destination = installer.index(
            "/usr/local/sbin/herodium-rkhunter-baseline",
            tool_source,
        )
        self.assertLess(tool_source, tool_destination)
        self.assertIn(
            "rm -f /usr/local/sbin/herodium-rkhunter-baseline",
            uninstaller,
        )

    def test_update_requires_acknowledgement_and_reason(self):
        module = _load_tool_module()
        manager = Mock()

        with patch.object(module.os, "geteuid", return_value=0), patch.object(
            module,
            "RkhunterManager",
            return_value=manager,
        ), redirect_stderr(io.StringIO()):
            missing_ack = module.main(["--update", "--reason", "reviewed"])
            missing_reason = module.main(
                ["--update", "--acknowledge-reviewed-warnings"]
            )

        self.assertEqual(missing_ack, 64)
        self.assertEqual(missing_reason, 64)
        manager.review_then_update_properties.assert_not_called()


    def test_audit_preflight_failure_blocks_propupd(self):
        module = _load_tool_module()
        manager = Mock()

        with patch.object(module.os, "geteuid", return_value=0), patch.object(
            module,
            "RkhunterManager",
            return_value=manager,
        ), patch.object(
            module,
            "_append_audit",
            side_effect=PermissionError("unsafe audit path"),
        ), redirect_stderr(io.StringIO()):
            result = module.main(
                [
                    "--update",
                    "--acknowledge-reviewed-warnings",
                    "--reason",
                    "verified package upgrade",
                ]
            )

        self.assertEqual(result, 74)
        manager.review_then_update_properties.assert_not_called()

    def test_readme_documents_explicit_audited_workflow(self):
        content = README.read_text(encoding="utf-8")

        self.assertIn("never runs `rkhunter --propupd` automatically", content)
        self.assertIn("herodium-rkhunter-baseline --review", content)
        self.assertIn("--acknowledge-reviewed-warnings", content)
        self.assertIn("/var/log/herodium/rkhunter-baseline.log", content)


if __name__ == "__main__":
    unittest.main()
