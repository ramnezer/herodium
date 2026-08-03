import importlib.util
import tempfile
import unittest
from importlib.machinery import SourceFileLoader
from pathlib import Path
from unittest.mock import patch


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = PROJECT_ROOT / "installer" / "bin" / "herodium-top"


def load_dashboard_module():
    loader = SourceFileLoader("herodium_top_test", str(SCRIPT_PATH))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    if spec is None:
        raise RuntimeError("Unable to create module specification")
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


class HerodiumTopTests(unittest.TestCase):
    def test_log_helpers_read_bounded_tail(self):
        module = load_dashboard_module()
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "herodium.log"
            log_path.write_text(
                "old entry\n"
                "2026 - [HERODIUM] - INFO - Memory Scan: checked 247 processes\n"
                "2026 - [HERODIUM] - CRITICAL - VIRUS DETECTED: /tmp/bad.exe -> Test.Signature\n"
                "2026 - [HERODIUM] - INFO - Memory Scan: checked 3 processes\n",
                encoding="utf-8",
            )
            module.LOG_FILE = str(log_path)

            self.assertEqual(module.get_last_memory_scan_count(), "3")
            self.assertEqual(
                module.get_recent_detections(),
                ["VIRUS DETECTED: bad.exe -> Test.Signature"],
            )

    def test_cgroup_status_does_not_need_subprocess(self):
        module = load_dashboard_module()
        with patch.object(module, "_cgroup_has_live_processes", return_value=True), patch.object(
            module, "_engine_process_is_running", return_value=False
        ):
            self.assertEqual(module.get_system_status(), "active")

    def test_source_does_not_import_subprocess(self):
        source = SCRIPT_PATH.read_text(encoding="utf-8")
        self.assertNotIn("import subprocess", source)
        self.assertNotIn("subprocess.", source)


if __name__ == "__main__":
    unittest.main()
