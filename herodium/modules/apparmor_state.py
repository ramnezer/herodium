#!/usr/bin/env python3

from __future__ import annotations

import argparse
import os
import secrets
import shutil
import stat
import sys
from pathlib import Path
from typing import Final


DEFAULT_STATE_ROOT: Final[Path] = Path("/var/lib/herodium/apparmor")
DEFAULT_LEGACY_LEVEL: Final[Path] = Path("/opt/herodium/apparmor_state")
DEFAULT_LEGACY_BASELINE: Final[Path] = Path(
    "/opt/herodium/apparmor_state_data/baseline_force-complain"
)
DEFAULT_FORCE_COMPLAIN: Final[Path] = Path("/etc/apparmor.d/force-complain")
VALID_LEVELS: Final[frozenset[int]] = frozenset({1, 2, 3, 4})
MAX_LEVEL_FILE_BYTES: Final[int] = 32


class AppArmorStateError(RuntimeError):
    """Raised when persistent or legacy AppArmor state is unsafe or invalid."""


class AppArmorStateStore:
    """Secure persistent storage for Herodium's AppArmor state."""

    def __init__(
        self,
        state_root: Path | str = DEFAULT_STATE_ROOT,
        legacy_level_file: Path | str = DEFAULT_LEGACY_LEVEL,
        legacy_baseline_dir: Path | str = DEFAULT_LEGACY_BASELINE,
    ) -> None:
        self.state_root = Path(state_root)
        self.level_file = self.state_root / "current_level"
        self.baseline_dir = self.state_root / "baseline_force-complain"
        self.legacy_level_file = Path(legacy_level_file)
        self.legacy_baseline_dir = Path(legacy_baseline_dir)

    def prepare(self) -> None:
        """Create secure state directories and migrate valid legacy state."""
        self._ensure_private_directory(self.state_root.parent)
        self._ensure_private_directory(self.state_root)
        self._validate_persistent_paths()
        self._migrate_legacy_level()
        self._migrate_legacy_baseline()
        self._validate_persistent_paths()

    def read_level(self) -> int:
        self.prepare()
        if not self.level_file.exists():
            return -1
        return self._parse_level_bytes(
            self._read_regular_file(self.level_file),
            self.level_file,
        )

    def write_level(self, level: int) -> None:
        if level not in VALID_LEVELS:
            raise AppArmorStateError(f"Invalid AppArmor level: {level}")
        self.prepare()
        self._atomic_write(self.level_file, str(level).encode("ascii"))

    def baseline_exists(self) -> bool:
        self.prepare()
        return self.baseline_dir.is_dir()

    def save_baseline(self, source_dir: Path | str) -> bool:
        """Save the baseline once. Existing persistent state is authoritative."""
        self.prepare()
        if self.baseline_dir.exists():
            self._require_real_directory(self.baseline_dir)
            return False

        source = Path(source_dir)
        self._atomic_copy_directory(source, self.baseline_dir, allow_missing=True)
        return True

    def restore_baseline(self, destination_dir: Path | str) -> bool:
        """Atomically restore the saved baseline into the system directory."""
        self.prepare()
        if not self.baseline_dir.exists():
            return False

        self._require_real_directory(self.baseline_dir)
        destination = Path(destination_dir)
        parent = destination.parent
        self._require_real_directory(parent)

        if destination.exists() or destination.is_symlink():
            self._require_real_directory(destination)

        token = secrets.token_hex(8)
        staged = parent / f".{destination.name}.herodium-new-{token}"
        previous = parent / f".{destination.name}.herodium-old-{token}"

        self._copy_directory(self.baseline_dir, staged)
        replaced_existing = False

        try:
            if destination.exists():
                os.rename(destination, previous)
                replaced_existing = True
            os.rename(staged, destination)
            self._fsync_directory(parent)
        except OSError as exc:
            if staged.exists():
                shutil.rmtree(staged, ignore_errors=True)
            if replaced_existing and previous.exists() and not destination.exists():
                os.rename(previous, destination)
            raise AppArmorStateError(
                f"Unable to restore AppArmor baseline: {exc}"
            ) from exc
        else:
            if previous.exists():
                shutil.rmtree(previous)
            self._fsync_directory(parent)
            return True

    def _validate_persistent_paths(self) -> None:
        if self.level_file.exists() or self.level_file.is_symlink():
            data = self._read_regular_file(self.level_file)
            self._parse_level_bytes(data, self.level_file)
            os.chmod(self.level_file, 0o600, follow_symlinks=False)

        if self.baseline_dir.exists() or self.baseline_dir.is_symlink():
            self._require_real_directory(self.baseline_dir)
            os.chmod(self.baseline_dir, 0o700, follow_symlinks=False)

    def _migrate_legacy_level(self) -> None:
        if self.level_file.exists():
            return
        if not (self.legacy_level_file.exists() or self.legacy_level_file.is_symlink()):
            return

        data = self._read_regular_file(self.legacy_level_file)
        self._parse_level_bytes(data, self.legacy_level_file)
        self._atomic_write(self.level_file, data)

    def _migrate_legacy_baseline(self) -> None:
        if self.baseline_dir.exists():
            return
        if not (
            self.legacy_baseline_dir.exists()
            or self.legacy_baseline_dir.is_symlink()
        ):
            return

        self._require_real_directory(self.legacy_baseline_dir)
        self._atomic_copy_directory(
            self.legacy_baseline_dir,
            self.baseline_dir,
            allow_missing=False,
        )

    @staticmethod
    def _parse_level_bytes(data: bytes, source: Path) -> int:
        if len(data) > MAX_LEVEL_FILE_BYTES:
            raise AppArmorStateError(f"AppArmor level file is too large: {source}")
        try:
            value = int(data.decode("ascii").strip())
        except (UnicodeDecodeError, ValueError) as exc:
            raise AppArmorStateError(
                f"Invalid AppArmor level state: {source}"
            ) from exc
        if value not in VALID_LEVELS:
            raise AppArmorStateError(
                f"AppArmor level is outside the supported range: {source}"
            )
        return value

    @staticmethod
    def _read_regular_file(path: Path) -> bytes:
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise AppArmorStateError(f"Unable to inspect state file {path}: {exc}") from exc

        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise AppArmorStateError(f"State path is not a regular file: {path}")

        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW

        try:
            descriptor = os.open(path, flags)
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode):
                os.close(descriptor)
                raise AppArmorStateError(
                    f"Opened state path is not a regular file: {path}"
                )
            if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                os.close(descriptor)
                raise AppArmorStateError(
                    f"State file changed while it was being opened: {path}"
                )
            with os.fdopen(descriptor, "rb") as handle:
                return handle.read(MAX_LEVEL_FILE_BYTES + 1)
        except AppArmorStateError:
            raise
        except OSError as exc:
            raise AppArmorStateError(f"Unable to read state file {path}: {exc}") from exc

    @classmethod
    def _ensure_private_directory(cls, path: Path) -> None:
        if path.exists() or path.is_symlink():
            cls._require_real_directory(path)
        else:
            try:
                path.mkdir(mode=0o700, parents=True, exist_ok=False)
            except FileExistsError:
                cls._require_real_directory(path)
            except OSError as exc:
                raise AppArmorStateError(
                    f"Unable to create AppArmor state directory {path}: {exc}"
                ) from exc
        os.chmod(path, 0o700, follow_symlinks=False)

    @staticmethod
    def _require_real_directory(path: Path) -> None:
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise AppArmorStateError(f"Unable to inspect directory {path}: {exc}") from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise AppArmorStateError(f"State path is not a real directory: {path}")

    def _atomic_write(self, destination: Path, data: bytes) -> None:
        self._ensure_private_directory(destination.parent)
        if destination.exists() or destination.is_symlink():
            self._read_regular_file(destination)

        temporary = destination.parent / (
            f".{destination.name}.tmp-{os.getpid()}-{secrets.token_hex(8)}"
        )
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW

        descriptor = -1
        try:
            descriptor = os.open(temporary, flags, 0o600)
            with os.fdopen(descriptor, "wb", closefd=True) as handle:
                descriptor = -1
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, destination)
            os.chmod(destination, 0o600, follow_symlinks=False)
            self._fsync_directory(destination.parent)
        except OSError as exc:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
            raise AppArmorStateError(
                f"Unable to write AppArmor state atomically: {exc}"
            ) from exc

    def _atomic_copy_directory(
        self,
        source: Path,
        destination: Path,
        *,
        allow_missing: bool,
    ) -> None:
        if destination.exists() or destination.is_symlink():
            self._require_real_directory(destination)
            return

        token = secrets.token_hex(8)
        staged = destination.parent / f".{destination.name}.tmp-{token}"

        if source.exists() or source.is_symlink():
            self._require_real_directory(source)
            self._copy_directory(source, staged)
        elif allow_missing:
            staged.mkdir(mode=0o700)
        else:
            raise AppArmorStateError(f"Legacy AppArmor baseline is missing: {source}")

        try:
            os.rename(staged, destination)
            os.chmod(destination, 0o700, follow_symlinks=False)
            self._fsync_directory(destination.parent)
        except OSError as exc:
            if staged.exists():
                shutil.rmtree(staged, ignore_errors=True)
            raise AppArmorStateError(
                f"Unable to migrate AppArmor baseline atomically: {exc}"
            ) from exc

    @classmethod
    def _copy_directory(cls, source: Path, destination: Path) -> None:
        try:
            shutil.copytree(source, destination, symlinks=True)
            os.chmod(destination, 0o700, follow_symlinks=False)
            cls._fsync_tree(destination)
        except OSError as exc:
            if destination.exists():
                shutil.rmtree(destination, ignore_errors=True)
            raise AppArmorStateError(
                f"Unable to copy AppArmor baseline from {source}: {exc}"
            ) from exc

    @classmethod
    def _fsync_tree(cls, root: Path) -> None:
        for current_root, directories, files in os.walk(root, followlinks=False):
            current_path = Path(current_root)
            for filename in files:
                path = current_path / filename
                if path.is_symlink():
                    continue
                try:
                    descriptor = os.open(path, os.O_RDONLY)
                except OSError as exc:
                    raise AppArmorStateError(f"Unable to open {path} for fsync: {exc}") from exc
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            for dirname in directories:
                path = current_path / dirname
                if not path.is_symlink():
                    os.chmod(path, 0o700, follow_symlinks=False)
            cls._fsync_directory(current_path)

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        flags = os.O_RDONLY
        if hasattr(os, "O_DIRECTORY"):
            flags |= os.O_DIRECTORY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            raise AppArmorStateError(f"Unable to open directory {path}: {exc}") from exc
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Manage Herodium AppArmor state")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("migrate", help="Migrate legacy state into persistent storage")

    restore = subparsers.add_parser("restore", help="Restore the saved baseline")
    restore.add_argument(
        "--destination",
        type=Path,
        default=DEFAULT_FORCE_COMPLAIN,
    )

    write_level = subparsers.add_parser("write-level", help="Persist the verified level")
    write_level.add_argument("level", type=int, choices=sorted(VALID_LEVELS))
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _build_parser().parse_args(argv)
    store = AppArmorStateStore()

    try:
        if arguments.command == "migrate":
            store.prepare()
            print(f"[PASS] AppArmor state ready: {store.state_root}")
            return 0
        if arguments.command == "restore":
            if not store.restore_baseline(arguments.destination):
                print("[INFO] No Herodium AppArmor baseline found.")
                return 2
            print(f"[PASS] AppArmor baseline restored to: {arguments.destination}")
            return 0
        if arguments.command == "write-level":
            store.write_level(arguments.level)
            print(f"[PASS] AppArmor level persisted: {arguments.level}")
            return 0
    except AppArmorStateError as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 1

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
