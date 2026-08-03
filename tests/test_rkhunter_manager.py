import logging
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock


PROJECT_ROOT = Path(__file__).resolve().parents[1]
HERODIUM_ROOT = PROJECT_ROOT / "herodium"
if str(HERODIUM_ROOT) not in sys.path:
    sys.path.insert(0, str(HERODIUM_ROOT))

from modules.rkhunter_manager import RkhunterManager  # noqa: E402


class RkhunterManagerTests(unittest.TestCase):
    def _manager(self, directory, script):
        path = Path(directory) / "rkhunter"
        path.write_text(script, encoding="utf-8")
        path.chmod(0o700)
        return RkhunterManager(
            Mock(spec=logging.Logger),
            executable_candidates=(path,),
            lock_path=Path(directory) / "rkhunter.lock",
            trusted_owner_uid=os.getuid(),
        )

    def test_check_uses_warnings_only_arguments(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "arguments.log"
            manager = self._manager(
                temp_dir,
                "#!/bin/sh\nprintf '%s\\n' \"$*\" > "
                f"'{log_path}'\n"
                "printf 'warning sample\\n'\n"
                "exit 1\n",
            )

            result = manager.check()

            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout.strip(), "warning sample")
            self.assertEqual(
                log_path.read_text(encoding="utf-8").strip(),
                "--check --sk --rwo --nocolors",
            )

    def test_update_data_accepts_exit_code_two(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = self._manager(
                temp_dir,
                "#!/bin/sh\nexit 2\n",
            )

            result = manager.update_data()

            self.assertEqual(result.returncode, 2)
            self.assertFalse(result.lock_busy)

    def test_review_and_propupd_share_one_explicit_operation(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "arguments.log"
            manager = self._manager(
                temp_dir,
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> "
                f"'{log_path}'\n"
                "case \"$1\" in\n"
                "  --check) printf 'reviewed warning\\n'; exit 1 ;;\n"
                "  --propupd) exit 0 ;;\n"
                "  *) exit 9 ;;\n"
                "esac\n",
            )

            review, update = manager.review_then_update_properties()

            self.assertEqual(review.returncode, 1)
            self.assertIsNotNone(update)
            self.assertEqual(update.returncode, 0)
            self.assertEqual(
                log_path.read_text(encoding="utf-8").splitlines(),
                [
                    "--check --sk --rwo --nocolors",
                    "--propupd --nocolors",
                ],
            )

    def test_untrusted_group_writable_executable_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = self._manager(
                temp_dir,
                "#!/bin/sh\nexit 0\n",
            )
            manager.executable_candidates[0].chmod(0o720)

            result = manager.check()

            self.assertEqual(result.returncode, 127)
            self.assertIn("group/other writable", result.stderr)

    def test_lock_prevents_overlapping_operation(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = self._manager(
                temp_dir,
                "#!/bin/sh\nexit 0\n",
            )

            with manager._operation_lock(blocking=False):
                result = manager.check()

            self.assertTrue(result.lock_busy)
            self.assertEqual(result.returncode, 75)


if __name__ == "__main__":
    unittest.main()
