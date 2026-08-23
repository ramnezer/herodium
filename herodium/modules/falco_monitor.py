from __future__ import annotations

import logging
import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Final

from modules.falco_event import FalcoEvent
from modules.falco_reader import (
    DEFAULT_CURSOR_PATH,
    DEFAULT_EVENT_LOG_PATH,
    FalcoJSONLReader,
    FalcoReadBatch,
    FalcoReaderError,
)

_DEFAULT_QUEUE_MAX_SIZE: Final[int] = 2048
_DEFAULT_POLL_INTERVAL_SECONDS: Final[float] = 0.25
_DEFAULT_WARNING_INTERVAL_SECONDS: Final[float] = 30.0
_DEFAULT_WARNING_KEYS: Final[int] = 64
_MAX_QUEUE_SIZE: Final[int] = 65536
_MAX_WARNING_KEYS: Final[int] = 1024
_MAX_INTERVAL_SECONDS: Final[float] = 3600.0
_FALCO_CONFIG_KEYS: Final = frozenset(
    {
        "enable",
        "mode",
        "event_log_path",
        "cursor_path",
        "start_position",
        "queue_max_size",
        "poll_interval_seconds",
        "warning_interval_seconds",
        "warning_cache_max_entries",
        "dispatch",
    }
)


class FalcoMonitorState(str, Enum):
    STOPPED = "STOPPED"
    STARTING = "STARTING"
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    FAILED = "FAILED"


@dataclass(frozen=True)
class FalcoMonitorStats:
    polls_completed: int
    events_enqueued: int
    events_dequeued: int
    events_dropped: int
    events_rejected: int
    reader_errors: int
    rotations: int
    truncations: int
    queue_high_watermark: int


@dataclass(frozen=True)
class FalcoMonitorHealth:
    state: FalcoMonitorState
    thread_alive: bool
    queue_size: int
    queue_capacity: int
    last_reader_error_code: str | None
    fatal_error: bool
    stats: FalcoMonitorStats


@dataclass
class _WarningEntry:
    last_emitted: float
    suppressed: int = 0


class FalcoMonitor:
    """Threaded, bounded runtime bridge between Falco JSONL and Herodium."""

    @classmethod
    def from_config(
        cls,
        logger: logging.Logger,
        section: object,
    ) -> FalcoMonitor:
        if section is None:
            section = {}
        if not isinstance(section, dict):
            raise TypeError("Falco configuration section must be a mapping.")

        unknown = set(section).difference(_FALCO_CONFIG_KEYS)
        if unknown:
            raise ValueError("Falco configuration contains unsupported keys.")

        mode = section.get("mode", "alert_only")
        if mode != "alert_only":
            raise ValueError("Falco mode must be 'alert_only'.")

        dispatch = section.get("dispatch", {})
        if dispatch is not None and not isinstance(dispatch, dict):
            raise TypeError("Falco dispatch configuration must be a mapping.")

        return cls(
            logger,
            event_log_path=section.get(
                "event_log_path",
                DEFAULT_EVENT_LOG_PATH,
            ),
            cursor_path=section.get("cursor_path", DEFAULT_CURSOR_PATH),
            start_position=section.get("start_position", "end"),
            queue_max_size=section.get(
                "queue_max_size",
                _DEFAULT_QUEUE_MAX_SIZE,
            ),
            poll_interval_seconds=section.get(
                "poll_interval_seconds",
                _DEFAULT_POLL_INTERVAL_SECONDS,
            ),
            warning_interval_seconds=section.get(
                "warning_interval_seconds",
                _DEFAULT_WARNING_INTERVAL_SECONDS,
            ),
            warning_cache_max_entries=section.get(
                "warning_cache_max_entries",
                _DEFAULT_WARNING_KEYS,
            ),
        )

    def __init__(
        self,
        logger: logging.Logger,
        *,
        reader: FalcoJSONLReader | None = None,
        event_log_path: Path | str = DEFAULT_EVENT_LOG_PATH,
        cursor_path: Path | str = DEFAULT_CURSOR_PATH,
        expected_owner_uid: int = 0,
        start_position: str = "end",
        queue_max_size: int = _DEFAULT_QUEUE_MAX_SIZE,
        poll_interval_seconds: float = _DEFAULT_POLL_INTERVAL_SECONDS,
        warning_interval_seconds: float = _DEFAULT_WARNING_INTERVAL_SECONDS,
        warning_cache_max_entries: int = _DEFAULT_WARNING_KEYS,
    ) -> None:
        if not isinstance(logger, logging.Logger):
            raise TypeError("logger must be a logging.Logger instance.")
        self.logger = logger
        self.queue_max_size = _require_int(
            queue_max_size,
            name="queue_max_size",
            minimum=1,
            maximum=_MAX_QUEUE_SIZE,
        )
        self.poll_interval_seconds = _require_float(
            poll_interval_seconds,
            name="poll_interval_seconds",
            minimum=0.001,
            maximum=_MAX_INTERVAL_SECONDS,
        )
        self.warning_interval_seconds = _require_float(
            warning_interval_seconds,
            name="warning_interval_seconds",
            minimum=0.0,
            maximum=_MAX_INTERVAL_SECONDS,
        )
        self.warning_cache_max_entries = _require_int(
            warning_cache_max_entries,
            name="warning_cache_max_entries",
            minimum=1,
            maximum=_MAX_WARNING_KEYS,
        )

        self.reader = (
            reader
            if reader is not None
            else FalcoJSONLReader(
                event_log_path=event_log_path,
                cursor_path=cursor_path,
                expected_owner_uid=expected_owner_uid,
                start_position=start_position,
            )
        )
        self._queue: deque[FalcoEvent] = deque()
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._queue_condition = threading.Condition(self._lock)
        self._warning_lock = threading.Lock()
        self._warning_state: OrderedDict[str, _WarningEntry] = OrderedDict()
        self._thread: threading.Thread | None = None
        self._started = False
        self._stopping = False
        self._successful_poll = False
        self._last_reader_error_code: str | None = None
        self._fatal_error = False

        self._polls_completed = 0
        self._events_enqueued = 0
        self._events_dequeued = 0
        self._events_dropped = 0
        self._events_rejected = 0
        self._reader_errors = 0
        self._rotations = 0
        self._truncations = 0
        self._queue_high_watermark = 0

    def start(self) -> bool:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return True
            if self._fatal_error:
                return False
            if self._stopping:
                return False

            self._stop_event.clear()
            self._started = True
            thread = threading.Thread(
                target=self._run,
                name="herodium-falco-monitor",
                daemon=True,
            )
            self._thread = thread
            thread.start()
        return thread.is_alive()

    def stop(self, timeout: float = 5.0) -> bool:
        timeout_value = _require_float(
            timeout,
            name="timeout",
            minimum=0.0,
            maximum=_MAX_INTERVAL_SECONDS,
        )
        with self._lock:
            thread = self._thread
            if thread is None:
                self._started = False
                return True
            self._stopping = True
            self._stop_event.set()

        if thread is not threading.current_thread():
            thread.join(timeout_value)

        alive = thread.is_alive()
        if alive:
            self._warn_rate_limited(
                "stop_timeout",
                "Falco monitor did not stop before the timeout.",
            )
            return False

        close_succeeded = True
        try:
            self.reader.close()
        except FalcoReaderError as exc:
            close_succeeded = False
            with self._lock:
                self._fatal_error = True
            self._record_reader_error(exc.code)
        except OSError:
            close_succeeded = False
            with self._lock:
                self._fatal_error = True
            self._record_reader_error("reader_close_failed")
        finally:
            with self._lock:
                self._thread = None
                self._started = False
                self._stopping = False
        return close_succeeded

    def get_event(
        self,
        *,
        block: bool = False,
        timeout: float | None = None,
    ) -> FalcoEvent | None:
        timeout_value: float | None = None
        if timeout is not None:
            timeout_value = _require_float(
                timeout,
                name="timeout",
                minimum=0.0,
                maximum=_MAX_INTERVAL_SECONDS,
            )
            if not block:
                raise ValueError("timeout requires block=True.")

        with self._queue_condition:
            if block:
                if timeout_value is None:
                    while not self._queue:
                        self._queue_condition.wait()
                else:
                    deadline = time.monotonic() + timeout_value
                    while not self._queue:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            return None
                        self._queue_condition.wait(remaining)
            elif not self._queue:
                return None

            event = self._queue.popleft()
            self._events_dequeued += 1
            return event

    def drain(self, max_events: int = 256) -> tuple[FalcoEvent, ...]:
        limit = _require_int(
            max_events,
            name="max_events",
            minimum=1,
            maximum=self.queue_max_size,
        )
        events: list[FalcoEvent] = []
        for _ in range(limit):
            event = self.get_event()
            if event is None:
                break
            events.append(event)
        return tuple(events)

    def stats(self) -> FalcoMonitorStats:
        with self._lock:
            return self._stats_unlocked()

    def health(self) -> FalcoMonitorHealth:
        with self._lock:
            thread = self._thread
            thread_alive = thread is not None and thread.is_alive()
            if self._fatal_error or (
                self._started and not self._stopping and not thread_alive
            ):
                state = FalcoMonitorState.FAILED
            elif not self._started:
                state = FalcoMonitorState.STOPPED
            elif self._stopping or (
                self._last_reader_error_code is not None
                or self._events_dropped > 0
                or self._events_rejected > 0
            ):
                state = FalcoMonitorState.DEGRADED
            elif not self._successful_poll:
                state = FalcoMonitorState.STARTING
            else:
                state = FalcoMonitorState.HEALTHY

            return FalcoMonitorHealth(
                state=state,
                thread_alive=thread_alive,
                queue_size=len(self._queue),
                queue_capacity=self.queue_max_size,
                last_reader_error_code=self._last_reader_error_code,
                fatal_error=self._fatal_error,
                stats=self._stats_unlocked(),
            )

    def _stats_unlocked(self) -> FalcoMonitorStats:
        return FalcoMonitorStats(
            polls_completed=self._polls_completed,
            events_enqueued=self._events_enqueued,
            events_dequeued=self._events_dequeued,
            events_dropped=self._events_dropped,
            events_rejected=self._events_rejected,
            reader_errors=self._reader_errors,
            rotations=self._rotations,
            truncations=self._truncations,
            queue_high_watermark=self._queue_high_watermark,
        )

    def _run(self) -> None:
        try:
            while not self._stop_event.is_set():
                try:
                    batch = self.reader.poll()
                except FalcoReaderError as exc:
                    self._record_reader_error(exc.code)
                    self._stop_event.wait(self.poll_interval_seconds)
                    continue

                self._record_successful_batch(batch)
                self._stop_event.wait(self.poll_interval_seconds)
        except Exception:  # pragma: no cover - defensive thread boundary
            with self._lock:
                self._fatal_error = True
            self.logger.exception(
                "Falco monitor stopped after an unexpected runtime failure."
            )

    def _record_successful_batch(self, batch: FalcoReadBatch) -> None:
        dropped = 0
        for event in batch.events:
            with self._queue_condition:
                if len(self._queue) >= self.queue_max_size:
                    dropped += 1
                    continue
                self._queue.append(event)
                self._events_enqueued += 1
                self._queue_high_watermark = max(
                    self._queue_high_watermark,
                    len(self._queue),
                )
                self._queue_condition.notify()

        rejected_count = sum(count for _, count in batch.rejected)
        with self._lock:
            self._polls_completed += 1
            self._successful_poll = True
            self._last_reader_error_code = None
            self._events_dropped += dropped
            self._events_rejected += rejected_count
            self._rotations += int(batch.rotation_detected)
            self._truncations += int(batch.truncation_detected)

        for code, count in batch.rejected:
            self._warn_rate_limited(
                f"rejected:{code}",
                f"Falco input rejected: code={code}",
                count=count,
            )
        if dropped:
            self._warn_rate_limited(
                "queue_full",
                "Falco event queue is full; event delivery was dropped.",
                count=dropped,
            )

    def _record_reader_error(self, code: str) -> None:
        with self._lock:
            self._reader_errors += 1
            self._last_reader_error_code = code
        self._warn_rate_limited(
            f"reader:{code}",
            f"Falco reader unavailable: code={code}",
        )

    def _warn_rate_limited(
        self,
        key: str,
        message: str,
        *,
        count: int = 1,
    ) -> bool:
        if count <= 0:
            return False
        now = self._now()
        with self._warning_lock:
            entry = self._warning_state.pop(key, None)
            if entry is not None and (
                now - entry.last_emitted < self.warning_interval_seconds
            ):
                entry.suppressed += count
                self._warning_state[key] = entry
                return False

            suppressed = 0 if entry is None else entry.suppressed
            self._warning_state[key] = _WarningEntry(last_emitted=now)
            while len(self._warning_state) > self.warning_cache_max_entries:
                self._warning_state.popitem(last=False)

        if suppressed:
            self.logger.warning(
                "%s count=%d suppressed_since_last=%d",
                message,
                count,
                suppressed,
            )
        else:
            self.logger.warning("%s count=%d", message, count)
        return True

    @staticmethod
    def _now() -> float:
        return time.monotonic()


def _require_int(value: int, *, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer.")
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} is outside the safe range.")
    return value


def _require_float(
    value: float,
    *,
    name: str,
    minimum: float,
    maximum: float,
) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{name} must be numeric.")
    result = float(value)
    if not minimum <= result <= maximum:
        raise ValueError(f"{name} is outside the safe range.")
    return result
