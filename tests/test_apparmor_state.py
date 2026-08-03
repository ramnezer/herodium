import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
HERODIUM_ROOT = PROJECT_ROOT / "herodium"
if str(HERODIUM_ROOT) not in sys.path:
    sys.path.insert(0, str(HERODIUM_ROOT))

from modules.apparmor_state import (  # noqa: E402
    AppArmorStateError,
    AppArmorStateStore,
    DEFAULT_LEGACY_BASELINE,
    DEFAULT_LEGACY_LEVEL,
    DEFAULT_STATE_ROOT,
)


class AppArmorStateStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.root = Path(self.temp_dir.name)
        self.state_root = self.root / "var/lib/herodium/apparmor"
        self.legacy_level = self.root / "opt/herodium/apparmor_state"
        self.legacy_baseline = (
            self.root
            / "opt/herodium/apparmor_state_data/baseline_force-complain"
        )
        self.force_complain = self.root / "etc/apparmor.d/force-complain"

    def _store(self):
        return AppArmorStateStore(
            state_root=self.state_root,
            legacy_level_file=self.legacy_level,
            legacy_baseline_dir=self.legacy_baseline,
        )

    def test_default_paths_are_outside_deployment_tree(self):
        self.assertEqual(DEFAULT_STATE_ROOT, Path("/var/lib/herodium/apparmor"))
        self.assertEqual(DEFAULT_LEGACY_LEVEL, Path("/opt/herodium/apparmor_state"))
        self.assertEqual(
            DEFAULT_LEGACY_BASELINE,
            Path(
                "/opt/herodium/apparmor_state_data/baseline_force-complain"
            ),
        )

    def test_prepare_creates_private_state_directories(self):
        store = self._store()

        store.prepare()

        self.assertTrue(self.state_root.is_dir())
        self.assertEqual(stat.S_IMODE(self.state_root.stat().st_mode), 0o700)
        self.assertEqual(
            stat.S_IMODE(self.state_root.parent.stat().st_mode),
            0o700,
        )

    def test_missing_level_returns_unknown(self):
        self.assertEqual(self._store().read_level(), -1)

    def test_level_write_is_atomic_and_private(self):
        store = self._store()

        store.write_level(3)

        self.assertEqual(store.read_level(), 3)
        self.assertEqual(store.level_file.read_bytes(), b"3")
        self.assertEqual(stat.S_IMODE(store.level_file.stat().st_mode), 0o600)
        self.assertEqual(list(self.state_root.glob("*.tmp-*")), [])
        self.assertEqual(list(self.state_root.glob(".*.tmp-*")), [])

    def test_valid_legacy_level_migrates_byte_for_byte(self):
        self.legacy_level.parent.mkdir(parents=True)
        self.legacy_level.write_bytes(b"3\n")
        store = self._store()

        store.prepare()

        self.assertEqual(store.level_file.read_bytes(), b"3\n")
        self.assertEqual(store.read_level(), 3)
        self.assertTrue(self.legacy_level.exists())

    def test_valid_persistent_level_is_authoritative(self):
        self.state_root.mkdir(parents=True)
        persistent = self.state_root / "current_level"
        persistent.write_bytes(b"2\n")
        self.legacy_level.parent.mkdir(parents=True)
        self.legacy_level.write_bytes(b"4\n")
        store = self._store()

        store.prepare()

        self.assertEqual(persistent.read_bytes(), b"2\n")
        self.assertEqual(store.read_level(), 2)

    def test_invalid_persistent_level_does_not_fall_back_to_legacy(self):
        self.state_root.mkdir(parents=True)
        (self.state_root / "current_level").write_text("invalid")
        self.legacy_level.parent.mkdir(parents=True)
        self.legacy_level.write_text("3")

        with self.assertRaises(AppArmorStateError):
            self._store().prepare()

        self.assertEqual((self.state_root / "current_level").read_text(), "invalid")

    def test_persistent_level_symlink_is_rejected(self):
        self.state_root.mkdir(parents=True)
        target = self.root / "target"
        target.write_text("1")
        (self.state_root / "current_level").symlink_to(target)

        with self.assertRaisesRegex(AppArmorStateError, "regular file"):
            self._store().prepare()

        self.assertEqual(target.read_text(), "1")

    def test_legacy_level_symlink_is_rejected(self):
        self.legacy_level.parent.mkdir(parents=True)
        target = self.root / "legacy-target"
        target.write_text("2")
        self.legacy_level.symlink_to(target)

        with self.assertRaisesRegex(AppArmorStateError, "regular file"):
            self._store().prepare()

        self.assertFalse((self.state_root / "current_level").exists())

    def test_legacy_baseline_migration_preserves_symlinks(self):
        self.legacy_baseline.mkdir(parents=True)
        (self.legacy_baseline / "usr.bin.example").symlink_to(
            "../usr.bin.example"
        )
        store = self._store()

        store.prepare()

        migrated = store.baseline_dir / "usr.bin.example"
        self.assertTrue(migrated.is_symlink())
        self.assertEqual(os.readlink(migrated), "../usr.bin.example")
        self.assertEqual(stat.S_IMODE(store.baseline_dir.stat().st_mode), 0o700)

    def test_persistent_baseline_is_authoritative(self):
        persistent = self.state_root / "baseline_force-complain"
        persistent.mkdir(parents=True)
        (persistent / "persistent-marker").write_text("keep")
        self.legacy_baseline.mkdir(parents=True)
        (self.legacy_baseline / "legacy-marker").write_text("replace")
        store = self._store()

        store.prepare()

        self.assertTrue((persistent / "persistent-marker").exists())
        self.assertFalse((persistent / "legacy-marker").exists())

    def test_legacy_baseline_root_symlink_is_rejected(self):
        self.legacy_baseline.parent.mkdir(parents=True)
        target = self.root / "legacy-baseline-target"
        target.mkdir()
        self.legacy_baseline.symlink_to(target, target_is_directory=True)

        with self.assertRaisesRegex(AppArmorStateError, "real directory"):
            self._store().prepare()

    def test_baseline_is_saved_only_once(self):
        source = self.force_complain
        source.mkdir(parents=True)
        (source / "original").symlink_to("../original")
        store = self._store()

        self.assertTrue(store.save_baseline(source))
        (source / "later").symlink_to("../later")
        self.assertFalse(store.save_baseline(source))

        self.assertTrue((store.baseline_dir / "original").is_symlink())
        self.assertFalse((store.baseline_dir / "later").exists())

    def test_restore_replaces_destination_atomically(self):
        source = self.force_complain
        source.mkdir(parents=True)
        (source / "saved-profile").symlink_to("../saved-profile")
        store = self._store()
        store.save_baseline(source)

        for path in source.iterdir():
            path.unlink()
        (source / "current-profile").symlink_to("../current-profile")

        restored = store.restore_baseline(source)

        self.assertTrue(restored)
        self.assertTrue((source / "saved-profile").is_symlink())
        self.assertFalse((source / "current-profile").exists())
        self.assertEqual(
            list(source.parent.glob(".force-complain.herodium-*-*")),
            [],
        )


if __name__ == "__main__":
    unittest.main()
