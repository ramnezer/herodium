import logging
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch


PROJECT_ROOT = Path(__file__).resolve().parents[1]
HERODIUM_ROOT = PROJECT_ROOT / "herodium"
if str(HERODIUM_ROOT) not in sys.path:
    sys.path.insert(0, str(HERODIUM_ROOT))

from modules.apparmor_manager import AppArmorManager  # noqa: E402
from modules.apparmor_state import AppArmorStateError  # noqa: E402


class FakeStateStore:
    def __init__(self, level=-1, baseline_exists=False):
        self.level = level
        self.has_baseline = baseline_exists
        self.prepared = 0
        self.saved = []
        self.restored = []
        self.written = []
        self.prepare_error = None

    def prepare(self):
        self.prepared += 1
        if self.prepare_error is not None:
            raise self.prepare_error

    def read_level(self):
        return self.level

    def baseline_exists(self):
        return self.has_baseline

    def save_baseline(self, source):
        self.saved.append(source)
        self.has_baseline = True
        return True

    def restore_baseline(self, destination):
        self.restored.append(destination)
        return self.has_baseline

    def write_level(self, level):
        self.written.append(level)
        self.level = level


class AppArmorManagerStateTests(unittest.TestCase):
    def setUp(self):
        self.logger = Mock(spec=logging.Logger)

    def _manager(self, level, store, create_backup=False):
        config = {
            "apparmor": {
                "level": level,
                "create_backup": create_backup,
            }
        }
        return AppArmorManager(config, self.logger, state_store=store)

    def test_same_verified_level_skips_policy_change(self):
        store = FakeStateStore(level=2, baseline_exists=True)
        manager = self._manager(2, store)
        manager._runtime_requirements_ok = Mock()

        self.assertTrue(manager.apply_policy())

        manager._runtime_requirements_ok.assert_not_called()
        self.assertEqual(store.written, [])

    def test_state_prepare_failure_aborts_policy_change(self):
        store = FakeStateStore(level=1)
        store.prepare_error = AppArmorStateError("unsafe state")
        manager = self._manager(2, store)

        self.assertFalse(manager.apply_policy())

        self.assertEqual(store.written, [])
        self.logger.error.assert_called()

    def test_failed_policy_command_is_not_persisted(self):
        store = FakeStateStore(level=1, baseline_exists=True)
        manager = self._manager(2, store)
        manager._runtime_requirements_ok = Mock(return_value=True)
        manager._mode_light = Mock(return_value=False)

        self.assertFalse(manager.apply_policy())

        self.assertEqual(store.written, [])

    def test_successful_policy_change_is_persisted(self):
        store = FakeStateStore(level=1, baseline_exists=True)
        manager = self._manager(2, store)
        manager._runtime_requirements_ok = Mock(return_value=True)
        manager._mode_light = Mock(return_value=True)

        self.assertTrue(manager.apply_policy())

        self.assertEqual(store.written, [2])

    def test_first_non_default_level_saves_baseline_once(self):
        store = FakeStateStore(level=1, baseline_exists=False)
        manager = self._manager(3, store)
        manager._runtime_requirements_ok = Mock(return_value=True)
        manager._mode_medium = Mock(return_value=True)

        self.assertTrue(manager.apply_policy())

        self.assertEqual(store.saved, [manager.force_complain_dir])
        self.assertEqual(store.written, [3])

    def test_default_level_restore_failure_is_not_persisted(self):
        store = FakeStateStore(level=3, baseline_exists=True)
        manager = self._manager(1, store)
        manager._runtime_requirements_ok = Mock(return_value=True)

        with patch.object(manager, "_reload_apparmor", return_value=False):
            self.assertFalse(manager.apply_policy())

        self.assertEqual(store.written, [])


if __name__ == "__main__":
    unittest.main()
