from __future__ import annotations

import json
import os
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Final

from modules.falco_event import (
    FalcoEvent,
    FalcoEventLimits,
    FalcoEventParseError,
    parse_falco_event,
)

DEFAULT_EVENT_LOG_PATH: Final[Path] = Path(
    "/var/log/herodium/falco-events.jsonl"
)
DEFAULT_CURSOR_PATH: Final[Path] = Path(
    "/var/lib/herodium/falco/cursor.json"
)
_CURSOR_VERSION: Final[int] = 1
_MAX_CURSOR_BYTES: Final[int] = 1024
_MAX_ID: Final[int] = (2**64) - 1
_MAX_OFFSET: Final[int] = (2**63) - 1
_UNSAFE_WRITE_BITS: Final[int] = stat.S_IWGRP | stat.S_IWOTH


class FalcoReaderError(RuntimeError):
    """Raised when the Falco event stream cannot be consumed safely."""

    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


@dataclass(frozen=True)
class FalcoReaderLimits:
    max_records_per_poll: int = 512
    max_bytes_per_poll: int = 1024 * 1024

    def validate(self, event_limits: FalcoEventLimits) -> None:
        if isinstance(self.max_records_per_poll, bool) or not isinstance(
            self.max_records_per_poll, int
        ):
            raise TypeError("max_records_per_poll must be an integer.")
        if not 1 <= self.max_records_per_poll <= 100000:
            raise ValueError("max_records_per_poll is outside the safe range.")
        if isinstance(self.max_bytes_per_poll, bool) or not isinstance(
            self.max_bytes_per_poll, int
        ):
            raise TypeError("max_bytes_per_poll must be an integer.")
        minimum_bytes = event_limits.max_line_bytes + 1
        if not minimum_bytes <= self.max_bytes_per_poll <= 64 * 1024 * 1024:
            raise ValueError("max_bytes_per_poll is outside the safe range.")


@dataclass(frozen=True)
class FalcoCursor:
    device: int
    inode: int
    offset: int
    discard_until_newline: bool = False


@dataclass(frozen=True)
class FalcoReadBatch:
    events: tuple[FalcoEvent, ...]
    rejected: tuple[tuple[str, int], ...]
    records_consumed: int
    bytes_consumed: int
    rotation_detected: bool
    truncation_detected: bool


@dataclass(frozen=True)
class FalcoReaderStats:
    events_accepted: int
    events_rejected: int
    records_consumed: int
    bytes_consumed: int
    rotations: int
    truncations: int


class FalcoCursorStore:
    """Atomic, private storage for the Falco JSONL reader cursor."""

    def __init__(
        self,
        path: Path | str = DEFAULT_CURSOR_PATH,
        *,
        expected_owner_uid: int = 0,
    ) -> None:
        self.path = Path(path)
        if not self.path.is_absolute():
            raise ValueError("Falco cursor path must be absolute.")
        self.state_dir = self.path.parent
        self.expected_owner_uid = _validate_uid(expected_owner_uid)

    def load(self) -> FalcoCursor | None:
        self._prepare_directory()
        if not (self.path.exists() or self.path.is_symlink()):
            return None

        data = self._read_regular_file()
        try:
            payload = json.loads(
                data.decode("utf-8", errors="strict"),
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_invalid_constant,
            )
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            ValueError,
            RecursionError,
        ) as exc:
            raise FalcoReaderError(
                "invalid_cursor",
                "Falco cursor state is not valid bounded JSON.",
            ) from exc

        if not isinstance(payload, dict) or set(payload) != {
            "version",
            "device",
            "inode",
            "offset",
            "discard_until_newline",
        }:
            raise FalcoReaderError(
                "invalid_cursor",
                "Falco cursor state has an unsupported schema.",
            )

        version = _require_cursor_integer(payload, "version", minimum=1)
        if version != _CURSOR_VERSION:
            raise FalcoReaderError(
                "invalid_cursor",
                "Falco cursor state uses an unsupported version.",
            )

        discard = payload["discard_until_newline"]
        if not isinstance(discard, bool):
            raise FalcoReaderError(
                "invalid_cursor",
                "Falco cursor discard state must be boolean.",
            )

        return FalcoCursor(
            device=_require_cursor_integer(
                payload,
                "device",
                minimum=0,
                maximum=_MAX_ID,
            ),
            inode=_require_cursor_integer(
                payload,
                "inode",
                minimum=1,
                maximum=_MAX_ID,
            ),
            offset=_require_cursor_integer(
                payload,
                "offset",
                minimum=0,
                maximum=_MAX_OFFSET,
            ),
            discard_until_newline=discard,
        )

    def save(self, cursor: FalcoCursor) -> None:
        self._prepare_directory()
        self._validate_cursor(cursor)
        if os.geteuid() != self.expected_owner_uid:
            raise FalcoReaderError(
                "cursor_owner_mismatch",
                "Falco cursor cannot be written by an unexpected effective UID.",
            )

        if self.path.exists() or self.path.is_symlink():
            self._read_regular_file()

        payload = {
            "device": cursor.device,
            "discard_until_newline": cursor.discard_until_newline,
            "inode": cursor.inode,
            "offset": cursor.offset,
            "version": _CURSOR_VERSION,
        }
        data = (
            json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("utf-8")

        temporary = self.state_dir / (
            f".{self.path.name}.tmp-{os.getpid()}-{secrets.token_hex(8)}"
        )
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW

        descriptor = -1
        try:
            descriptor = os.open(temporary, flags, 0o600)
            opened = os.fstat(descriptor)
            _validate_owned_regular_metadata(
                opened,
                expected_owner_uid=self.expected_owner_uid,
                kind="cursor temporary file",
            )
            with os.fdopen(descriptor, "wb", closefd=True) as handle:
                descriptor = -1
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
            os.chmod(self.path, 0o600, follow_symlinks=False)
            _fsync_directory(self.state_dir)
        except FalcoReaderError:
            if descriptor >= 0:
                os.close(descriptor)
            _unlink_if_present(temporary)
            raise
        except OSError as exc:
            if descriptor >= 0:
                os.close(descriptor)
            _unlink_if_present(temporary)
            raise FalcoReaderError(
                "cursor_write_failed",
                f"Unable to persist Falco cursor state: {exc}",
            ) from exc

    def _prepare_directory(self) -> None:
        parent = self.state_dir.parent
        parent_metadata = _require_real_directory(
            parent,
            kind="cursor parent directory",
        )
        _validate_owned_directory_metadata(
            parent_metadata,
            expected_owner_uid=self.expected_owner_uid,
            kind="cursor parent directory",
        )

        if self.state_dir.exists() or self.state_dir.is_symlink():
            metadata = _require_real_directory(
                self.state_dir,
                kind="cursor state directory",
            )
            _validate_owned_directory_metadata(
                metadata,
                expected_owner_uid=self.expected_owner_uid,
                kind="cursor state directory",
            )
        else:
            if os.geteuid() != self.expected_owner_uid:
                raise FalcoReaderError(
                    "cursor_owner_mismatch",
                    "Falco cursor directory cannot be created by an unexpected UID.",
                )
            try:
                self.state_dir.mkdir(mode=0o700, exist_ok=False)
            except FileExistsError:
                metadata = _require_real_directory(
                    self.state_dir,
                    kind="cursor state directory",
                )
                _validate_owned_directory_metadata(
                    metadata,
                    expected_owner_uid=self.expected_owner_uid,
                    kind="cursor state directory",
                )
            except OSError as exc:
                raise FalcoReaderError(
                    "cursor_directory_failed",
                    f"Unable to create Falco cursor directory: {exc}",
                ) from exc

        os.chmod(self.state_dir, 0o700, follow_symlinks=False)

    def _read_regular_file(self) -> bytes:
        try:
            metadata = self.path.lstat()
        except OSError as exc:
            raise FalcoReaderError(
                "cursor_read_failed",
                f"Unable to inspect Falco cursor state: {exc}",
            ) from exc

        _validate_owned_regular_metadata(
            metadata,
            expected_owner_uid=self.expected_owner_uid,
            kind="cursor file",
        )
        if metadata.st_size > _MAX_CURSOR_BYTES:
            raise FalcoReaderError(
                "invalid_cursor",
                "Falco cursor state exceeds its size limit.",
            )

        flags = os.O_RDONLY
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW

        descriptor = -1
        try:
            descriptor = os.open(self.path, flags)
            opened = os.fstat(descriptor)
            _validate_owned_regular_metadata(
                opened,
                expected_owner_uid=self.expected_owner_uid,
                kind="cursor file",
            )
            if (opened.st_dev, opened.st_ino) != (
                metadata.st_dev,
                metadata.st_ino,
            ):
                raise FalcoReaderError(
                    "unsafe_cursor",
                    "Falco cursor changed while it was being opened.",
                )
            with os.fdopen(descriptor, "rb", closefd=True) as handle:
                descriptor = -1
                data = handle.read(_MAX_CURSOR_BYTES + 1)
            if len(data) > _MAX_CURSOR_BYTES:
                raise FalcoReaderError(
                    "invalid_cursor",
                    "Falco cursor state exceeds its size limit.",
                )
            return data
        except FalcoReaderError:
            if descriptor >= 0:
                os.close(descriptor)
            raise
        except OSError as exc:
            if descriptor >= 0:
                os.close(descriptor)
            raise FalcoReaderError(
                "cursor_read_failed",
                f"Unable to read Falco cursor state: {exc}",
            ) from exc

    @staticmethod
    def _validate_cursor(cursor: FalcoCursor) -> None:
        if not isinstance(cursor, FalcoCursor):
            raise TypeError("cursor must be a FalcoCursor instance.")
        for name, value, minimum, maximum in (
            ("device", cursor.device, 0, _MAX_ID),
            ("inode", cursor.inode, 1, _MAX_ID),
            ("offset", cursor.offset, 0, _MAX_OFFSET),
        ):
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"cursor {name} must be an integer.")
            if not minimum <= value <= maximum:
                raise ValueError(f"cursor {name} is outside the safe range.")
        if not isinstance(cursor.discard_until_newline, bool):
            raise TypeError("cursor discard state must be boolean.")


class FalcoJSONLReader:
    """Bounded, resumable reader for Falco's one-event-per-line JSON output."""

    def __init__(
        self,
        event_log_path: Path | str = DEFAULT_EVENT_LOG_PATH,
        cursor_path: Path | str = DEFAULT_CURSOR_PATH,
        *,
        expected_owner_uid: int = 0,
        start_position: str = "end",
        event_limits: FalcoEventLimits | None = None,
        reader_limits: FalcoReaderLimits | None = None,
    ) -> None:
        self.event_log_path = Path(event_log_path)
        if not self.event_log_path.is_absolute():
            raise ValueError("Falco event log path must be absolute.")
        self.expected_owner_uid = _validate_uid(expected_owner_uid)
        if start_position not in {"beginning", "end"}:
            raise ValueError("start_position must be 'beginning' or 'end'.")
        self.start_position = start_position
        self.event_limits = event_limits or FalcoEventLimits()
        self.reader_limits = reader_limits or FalcoReaderLimits()
        self.reader_limits.validate(self.event_limits)
        self.cursor_store = FalcoCursorStore(
            cursor_path,
            expected_owner_uid=self.expected_owner_uid,
        )

        self._handle: BinaryIO | None = None
        self._device: int | None = None
        self._inode: int | None = None
        self._discard_until_newline = False
        self._cursor_loaded = False
        self._saved_cursor: FalcoCursor | None = None

        self._events_accepted = 0
        self._events_rejected = 0
        self._records_consumed = 0
        self._bytes_consumed = 0
        self._rotations = 0
        self._truncations = 0

    def poll(self) -> FalcoReadBatch:
        rotation_detected = False
        truncation_detected = False
        events: list[FalcoEvent] = []
        rejected: dict[str, int] = {}
        records_consumed = 0
        bytes_consumed = 0

        if self._handle is None:
            rotation, truncation = self._open_path_and_position()
            rotation_detected |= rotation
            truncation_detected |= truncation

        while (
            records_consumed < self.reader_limits.max_records_per_poll
            and bytes_consumed < self.reader_limits.max_bytes_per_poll
        ):
            if self._handle is None:
                break

            truncation = self._rewind_if_truncated()
            truncation_detected |= truncation

            remaining = self.reader_limits.max_bytes_per_poll - bytes_consumed
            if self._discard_until_newline:
                consumed, finished = self._discard_oversized_fragment(remaining)
                bytes_consumed += consumed
                if not finished and consumed == 0:
                    break
                continue

            if remaining < self.event_limits.max_line_bytes + 1:
                break

            line_start = self._handle.tell()
            line = self._handle.readline(self.event_limits.max_line_bytes + 1)
            if not line:
                switched = self._switch_after_rotation()
                if switched:
                    rotation_detected = True
                    continue
                break

            if (
                not line.endswith(b"\n")
                and len(line) <= self.event_limits.max_line_bytes
            ):
                self._handle.seek(line_start, os.SEEK_SET)
                break

            bytes_consumed += len(line)
            records_consumed += 1

            if len(line) > self.event_limits.max_line_bytes:
                _increment(rejected, "line_too_large")
                self._events_rejected += 1
                if not line.endswith(b"\n"):
                    self._discard_until_newline = True
                continue

            try:
                event = parse_falco_event(line, limits=self.event_limits)
            except FalcoEventParseError as exc:
                _increment(rejected, exc.code)
                self._events_rejected += 1
            else:
                events.append(event)
                self._events_accepted += 1

        self._records_consumed += records_consumed
        self._bytes_consumed += bytes_consumed
        if rotation_detected:
            self._rotations += 1
        if truncation_detected:
            self._truncations += 1
        self._persist_cursor()

        return FalcoReadBatch(
            events=tuple(events),
            rejected=tuple(sorted(rejected.items())),
            records_consumed=records_consumed,
            bytes_consumed=bytes_consumed,
            rotation_detected=rotation_detected,
            truncation_detected=truncation_detected,
        )

    def stats(self) -> FalcoReaderStats:
        return FalcoReaderStats(
            events_accepted=self._events_accepted,
            events_rejected=self._events_rejected,
            records_consumed=self._records_consumed,
            bytes_consumed=self._bytes_consumed,
            rotations=self._rotations,
            truncations=self._truncations,
        )

    def close(self) -> None:
        if self._handle is None:
            return
        self._persist_cursor()
        self._handle.close()
        self._handle = None
        self._device = None
        self._inode = None

    def _open_path_and_position(self) -> tuple[bool, bool]:
        handle, metadata = self._open_safe_source()
        try:
            cursor = (
                self.cursor_store.load()
                if not self._cursor_loaded
                else self._saved_cursor
            )
        except Exception:
            handle.close()
            raise
        self._cursor_loaded = True

        rotation_detected = False
        truncation_detected = False
        identity = (metadata.st_dev, metadata.st_ino)

        if cursor is None:
            offset = metadata.st_size if self.start_position == "end" else 0
            discard = False
        elif (cursor.device, cursor.inode) != identity:
            offset = 0
            discard = False
            rotation_detected = True
        elif cursor.offset > metadata.st_size:
            offset = 0
            discard = False
            truncation_detected = True
        else:
            offset = cursor.offset
            discard = cursor.discard_until_newline

        try:
            handle.seek(offset, os.SEEK_SET)
        except OSError as exc:
            handle.close()
            raise FalcoReaderError(
                "source_seek_failed",
                f"Unable to position Falco event stream: {exc}",
            ) from exc

        self._handle = handle
        self._device = metadata.st_dev
        self._inode = metadata.st_ino
        self._discard_until_newline = discard
        self._persist_cursor()
        return rotation_detected, truncation_detected

    def _open_safe_source(self) -> tuple[BinaryIO, os.stat_result]:
        parent_metadata = _require_real_directory(
            self.event_log_path.parent,
            kind="Falco event-log directory",
        )
        _validate_owned_directory_metadata(
            parent_metadata,
            expected_owner_uid=self.expected_owner_uid,
            kind="Falco event-log directory",
        )
        try:
            metadata = self.event_log_path.lstat()
        except FileNotFoundError as exc:
            raise FalcoReaderError(
                "source_missing",
                "Falco event log does not exist.",
            ) from exc
        except OSError as exc:
            raise FalcoReaderError(
                "source_open_failed",
                f"Unable to inspect Falco event log: {exc}",
            ) from exc

        _validate_owned_regular_metadata(
            metadata,
            expected_owner_uid=self.expected_owner_uid,
            kind="Falco event log",
        )

        flags = os.O_RDONLY
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW

        descriptor = -1
        try:
            descriptor = os.open(self.event_log_path, flags)
            opened = os.fstat(descriptor)
            _validate_owned_regular_metadata(
                opened,
                expected_owner_uid=self.expected_owner_uid,
                kind="Falco event log",
            )
            if (opened.st_dev, opened.st_ino) != (
                metadata.st_dev,
                metadata.st_ino,
            ):
                raise FalcoReaderError(
                    "unsafe_source",
                    "Falco event log changed while it was being opened.",
                )
            handle = os.fdopen(descriptor, "rb", closefd=True)
            descriptor = -1
            return handle, opened
        except FalcoReaderError:
            if descriptor >= 0:
                os.close(descriptor)
            raise
        except OSError as exc:
            if descriptor >= 0:
                os.close(descriptor)
            raise FalcoReaderError(
                "source_open_failed",
                f"Unable to open Falco event log safely: {exc}",
            ) from exc

    def _rewind_if_truncated(self) -> bool:
        if self._handle is None:
            return False
        try:
            metadata = os.fstat(self._handle.fileno())
            offset = self._handle.tell()
        except OSError as exc:
            raise FalcoReaderError(
                "source_stat_failed",
                f"Unable to inspect open Falco event log: {exc}",
            ) from exc

        _validate_owned_regular_metadata(
            metadata,
            expected_owner_uid=self.expected_owner_uid,
            kind="Falco event log",
        )
        if metadata.st_size >= offset:
            return False

        self._handle.seek(0, os.SEEK_SET)
        self._discard_until_newline = False
        return True

    def _switch_after_rotation(self) -> bool:
        if self._handle is None or self._device is None or self._inode is None:
            return False

        try:
            current = self.event_log_path.lstat()
        except FileNotFoundError:
            return False
        except OSError as exc:
            raise FalcoReaderError(
                "source_open_failed",
                f"Unable to inspect Falco event log after EOF: {exc}",
            ) from exc

        _validate_owned_regular_metadata(
            current,
            expected_owner_uid=self.expected_owner_uid,
            kind="Falco event log",
        )
        if (current.st_dev, current.st_ino) == (self._device, self._inode):
            return False

        self._persist_cursor()
        old_handle = self._handle
        new_handle, metadata = self._open_safe_source()
        self._handle = new_handle
        self._device = metadata.st_dev
        self._inode = metadata.st_ino
        self._discard_until_newline = False
        self._handle.seek(0, os.SEEK_SET)
        old_handle.close()
        return True

    def _discard_oversized_fragment(self, remaining: int) -> tuple[int, bool]:
        if self._handle is None or remaining <= 0:
            return 0, False

        chunk_size = min(
            self.event_limits.max_line_bytes + 1,
            remaining,
        )
        chunk = self._handle.readline(chunk_size)
        if not chunk:
            return 0, False
        if chunk.endswith(b"\n"):
            self._discard_until_newline = False
            return len(chunk), True
        return len(chunk), False

    def _persist_cursor(self) -> None:
        if self._handle is None or self._device is None or self._inode is None:
            return
        try:
            offset = self._handle.tell()
        except OSError as exc:
            raise FalcoReaderError(
                "source_seek_failed",
                f"Unable to read Falco event stream position: {exc}",
            ) from exc

        cursor = FalcoCursor(
            device=self._device,
            inode=self._inode,
            offset=offset,
            discard_until_newline=self._discard_until_newline,
        )
        if cursor == self._saved_cursor:
            return
        self.cursor_store.save(cursor)
        self._saved_cursor = cursor


def _validate_uid(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError("expected_owner_uid must be a non-negative integer.")
    return value


def _require_cursor_integer(
    payload: dict[str, object],
    name: str,
    *,
    minimum: int,
    maximum: int = _MAX_OFFSET,
) -> int:
    value = payload[name]
    if isinstance(value, bool) or not isinstance(value, int):
        raise FalcoReaderError(
            "invalid_cursor",
            f"Falco cursor field {name} must be an integer.",
        )
    if not minimum <= value <= maximum:
        raise FalcoReaderError(
            "invalid_cursor",
            f"Falco cursor field {name} is outside the safe range.",
        )
    return value


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_invalid_constant(_value: str) -> None:
    raise ValueError("invalid JSON number")


def _validate_owned_regular_metadata(
    metadata: os.stat_result,
    *,
    expected_owner_uid: int,
    kind: str,
) -> None:
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise FalcoReaderError(
            "unsafe_path",
            f"{kind} is not a regular non-symlink file.",
        )
    if metadata.st_uid != expected_owner_uid:
        raise FalcoReaderError(
            "unsafe_owner",
            f"{kind} is not owned by the expected UID.",
        )
    if metadata.st_mode & _UNSAFE_WRITE_BITS:
        raise FalcoReaderError(
            "unsafe_permissions",
            f"{kind} is writable by group or other users.",
        )


def _validate_owned_directory_metadata(
    metadata: os.stat_result,
    *,
    expected_owner_uid: int,
    kind: str,
) -> None:
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise FalcoReaderError(
            "unsafe_path",
            f"{kind} is not a real directory.",
        )
    if metadata.st_uid != expected_owner_uid:
        raise FalcoReaderError(
            "unsafe_owner",
            f"{kind} is not owned by the expected UID.",
        )
    if metadata.st_mode & _UNSAFE_WRITE_BITS:
        raise FalcoReaderError(
            "unsafe_permissions",
            f"{kind} is writable by group or other users.",
        )


def _require_real_directory(path: Path, *, kind: str) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise FalcoReaderError(
            "unsafe_path",
            f"Unable to inspect {kind}: {exc}",
        ) from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise FalcoReaderError(
            "unsafe_path",
            f"{kind} is not a real directory.",
        )
    return metadata


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        os.fsync(descriptor)
    except OSError as exc:
        raise FalcoReaderError(
            "cursor_write_failed",
            f"Unable to synchronize Falco cursor directory: {exc}",
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _unlink_if_present(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        pass


def _increment(counter: dict[str, int], key: str) -> None:
    counter[key] = counter.get(key, 0) + 1
