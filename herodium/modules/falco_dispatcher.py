from __future__ import annotations

import logging
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Final

from modules.falco_event import FalcoEvent, FalcoPriority, FalcoScalar
from modules.falco_monitor import FalcoMonitor

_DEFAULT_MAX_EVENTS_PER_CYCLE: Final[int] = 256
_DEFAULT_ALERT_COOLDOWN_SECONDS: Final[float] = 60.0
_DEFAULT_ALERT_CACHE_MAX_ENTRIES: Final[int] = 1024
_DEFAULT_MINIMUM_PRIORITY: Final[FalcoPriority] = FalcoPriority.ERROR
_DEFAULT_NOTIFICATION_MINIMUM_PRIORITY: Final[FalcoPriority] = FalcoPriority.ERROR
_MAX_ALERT_CACHE_ENTRIES: Final[int] = 65536
_MAX_COOLDOWN_SECONDS: Final[float] = 86400.0
_MAX_CONTEXT_CHARS: Final[int] = 256
_MAX_NOTIFICATION_CHARS: Final[int] = 512
_DISPATCH_CONFIG_KEYS: Final = frozenset(
    {
        "max_events_per_cycle",
        "alert_cooldown_seconds",
        "alert_cache_max_entries",
        "minimum_priority",
        "notification_minimum_priority",
        "desktop_notifications",
    }
)
_DEDUP_FIELDS: Final = (
    "proc.exepath",
    "proc.name",
    "proc.pname",
    "user.uid",
    "user.name",
    "fd.name",
    "evt.type",
    "container.id",
)
_CONTEXT_FIELDS: Final = (
    ("process", ("proc.exepath", "proc.name")),
    ("parent", ("proc.pname",)),
    ("user", ("user.name", "user.uid")),
    ("target", ("fd.name",)),
)
_PRIORITY_RANK: Final = {
    FalcoPriority.DEBUG: 0,
    FalcoPriority.INFORMATIONAL: 1,
    FalcoPriority.NOTICE: 2,
    FalcoPriority.WARNING: 3,
    FalcoPriority.ERROR: 4,
    FalcoPriority.CRITICAL: 5,
    FalcoPriority.ALERT: 6,
    FalcoPriority.EMERGENCY: 7,
}
_LOG_LEVEL: Final = {
    FalcoPriority.DEBUG: logging.DEBUG,
    FalcoPriority.INFORMATIONAL: logging.INFO,
    FalcoPriority.NOTICE: logging.INFO,
    FalcoPriority.WARNING: logging.WARNING,
    FalcoPriority.ERROR: logging.ERROR,
    FalcoPriority.CRITICAL: logging.CRITICAL,
    FalcoPriority.ALERT: logging.CRITICAL,
    FalcoPriority.EMERGENCY: logging.CRITICAL,
}


@dataclass(frozen=True)
class FalcoDispatchConfig:
    max_events_per_cycle: int
    alert_cooldown_seconds: float
    alert_cache_max_entries: int
    minimum_priority: FalcoPriority
    notification_minimum_priority: FalcoPriority
    desktop_notifications: bool


@dataclass(frozen=True)
class FalcoDispatchStats:
    events_seen: int
    events_filtered: int
    events_logged: int
    events_suppressed: int
    notifications_attempted: int
    notifications_delivered: int
    notification_failures: int
    dispatch_failures: int
    cache_evictions: int


@dataclass
class _AlertEntry:
    last_emitted: float
    suppressed: int = 0


class FalcoEventDispatcher:
    """Bounded alert-only delivery of validated Falco events."""

    @classmethod
    def from_config(
        cls,
        logger: logging.Logger,
        notifier: object,
        monitor: FalcoMonitor,
        falco_section: object,
    ) -> FalcoEventDispatcher:
        config = cls._parse_dispatch_config(falco_section)
        return cls(
            logger,
            notifier,
            monitor,
            max_events_per_cycle=config.max_events_per_cycle,
            alert_cooldown_seconds=config.alert_cooldown_seconds,
            alert_cache_max_entries=config.alert_cache_max_entries,
            minimum_priority=config.minimum_priority,
            notification_minimum_priority=config.notification_minimum_priority,
            desktop_notifications=config.desktop_notifications,
        )

    @classmethod
    def validate_config(
        cls,
        falco_section: object,
        *,
        queue_capacity: int,
    ) -> None:
        config = cls._parse_dispatch_config(falco_section)
        if config.max_events_per_cycle > queue_capacity:
            raise ValueError(
                "Falco dispatch max_events_per_cycle cannot exceed queue capacity."
            )

    @classmethod
    def _parse_dispatch_config(cls, falco_section: object) -> FalcoDispatchConfig:
        if falco_section is None:
            falco_section = {}
        if not isinstance(falco_section, dict):
            raise TypeError("Falco configuration section must be a mapping.")

        dispatch = falco_section.get("dispatch", {})
        if dispatch is None:
            dispatch = {}
        if not isinstance(dispatch, dict):
            raise TypeError("Falco dispatch configuration must be a mapping.")

        unknown = set(dispatch).difference(_DISPATCH_CONFIG_KEYS)
        if unknown:
            raise ValueError("Falco dispatch configuration contains unsupported keys.")

        return FalcoDispatchConfig(
            max_events_per_cycle=_require_int(
                dispatch.get(
                    "max_events_per_cycle",
                    _DEFAULT_MAX_EVENTS_PER_CYCLE,
                ),
                name="max_events_per_cycle",
                minimum=1,
                maximum=65536,
            ),
            alert_cooldown_seconds=_require_float(
                dispatch.get(
                    "alert_cooldown_seconds",
                    _DEFAULT_ALERT_COOLDOWN_SECONDS,
                ),
                name="alert_cooldown_seconds",
                minimum=0.0,
                maximum=_MAX_COOLDOWN_SECONDS,
            ),
            alert_cache_max_entries=_require_int(
                dispatch.get(
                    "alert_cache_max_entries",
                    _DEFAULT_ALERT_CACHE_MAX_ENTRIES,
                ),
                name="alert_cache_max_entries",
                minimum=1,
                maximum=_MAX_ALERT_CACHE_ENTRIES,
            ),
            minimum_priority=_parse_priority(
                dispatch.get(
                    "minimum_priority",
                    _DEFAULT_MINIMUM_PRIORITY.value,
                ),
                name="minimum_priority",
            ),
            notification_minimum_priority=_parse_priority(
                dispatch.get(
                    "notification_minimum_priority",
                    _DEFAULT_NOTIFICATION_MINIMUM_PRIORITY.value,
                ),
                name="notification_minimum_priority",
            ),
            desktop_notifications=_require_bool(
                dispatch.get("desktop_notifications", True),
                name="desktop_notifications",
            ),
        )

    def __init__(
        self,
        logger: logging.Logger,
        notifier: object,
        monitor: FalcoMonitor,
        *,
        max_events_per_cycle: int = _DEFAULT_MAX_EVENTS_PER_CYCLE,
        alert_cooldown_seconds: float = _DEFAULT_ALERT_COOLDOWN_SECONDS,
        alert_cache_max_entries: int = _DEFAULT_ALERT_CACHE_MAX_ENTRIES,
        minimum_priority: FalcoPriority = _DEFAULT_MINIMUM_PRIORITY,
        notification_minimum_priority: FalcoPriority = (
            _DEFAULT_NOTIFICATION_MINIMUM_PRIORITY
        ),
        desktop_notifications: bool = True,
    ) -> None:
        if not isinstance(logger, logging.Logger):
            raise TypeError("logger must be a logging.Logger instance.")
        if not isinstance(monitor, FalcoMonitor):
            raise TypeError("monitor must be a FalcoMonitor instance.")

        self.logger = logger
        self.notifier = notifier
        self.monitor = monitor
        self.max_events_per_cycle = _require_int(
            max_events_per_cycle,
            name="max_events_per_cycle",
            minimum=1,
            maximum=monitor.queue_max_size,
        )
        self.alert_cooldown_seconds = _require_float(
            alert_cooldown_seconds,
            name="alert_cooldown_seconds",
            minimum=0.0,
            maximum=_MAX_COOLDOWN_SECONDS,
        )
        self.alert_cache_max_entries = _require_int(
            alert_cache_max_entries,
            name="alert_cache_max_entries",
            minimum=1,
            maximum=_MAX_ALERT_CACHE_ENTRIES,
        )
        if not isinstance(minimum_priority, FalcoPriority):
            raise TypeError("minimum_priority must be a FalcoPriority.")
        self.minimum_priority = minimum_priority
        if not isinstance(notification_minimum_priority, FalcoPriority):
            raise TypeError(
                "notification_minimum_priority must be a FalcoPriority."
            )
        self.notification_minimum_priority = notification_minimum_priority
        self.desktop_notifications = _require_bool(
            desktop_notifications,
            name="desktop_notifications",
        )

        self._lock = threading.Lock()
        self._alerts: OrderedDict[tuple[object, ...], _AlertEntry] = OrderedDict()
        self._events_seen = 0
        self._events_filtered = 0
        self._events_logged = 0
        self._events_suppressed = 0
        self._notifications_attempted = 0
        self._notifications_delivered = 0
        self._notification_failures = 0
        self._dispatch_failures = 0
        self._cache_evictions = 0

    def service_once(self) -> int:
        events = self.monitor.drain(self.max_events_per_cycle)
        first_error: Exception | None = None
        for event in events:
            try:
                self.dispatch(event)
            # A single bad delivery must not discard the remainder of a drained
            # batch.
            except Exception as exc:  # noqa: BLE001
                with self._lock:
                    self._dispatch_failures += 1
                if first_error is None:
                    first_error = exc

        if first_error is not None:
            raise first_error
        return len(events)

    def dispatch(self, event: FalcoEvent) -> bool:
        if not isinstance(event, FalcoEvent):
            raise TypeError("event must be a FalcoEvent instance.")

        with self._lock:
            self._events_seen += 1
            if not self._meets_minimum_priority(event.priority):
                self._events_filtered += 1
                return False

        now = self._now()
        key = self._event_key(event)
        with self._lock:
            entry = self._alerts.pop(key, None)
            if entry is not None and (
                now - entry.last_emitted < self.alert_cooldown_seconds
            ):
                entry.suppressed += 1
                self._events_suppressed += 1
                self._alerts[key] = entry
                return False

            suppressed = 0 if entry is None else entry.suppressed
            self._alerts[key] = _AlertEntry(last_emitted=now)
            while len(self._alerts) > self.alert_cache_max_entries:
                self._alerts.popitem(last=False)
                self._cache_evictions += 1

        summary = self._summary(event, suppressed=suppressed)
        self.logger.log(_LOG_LEVEL[event.priority], "%s", summary)
        with self._lock:
            self._events_logged += 1

        if self._should_notify(event.priority):
            self._notify(event, summary)
        return True

    def stats(self) -> FalcoDispatchStats:
        with self._lock:
            return FalcoDispatchStats(
                events_seen=self._events_seen,
                events_filtered=self._events_filtered,
                events_logged=self._events_logged,
                events_suppressed=self._events_suppressed,
                notifications_attempted=self._notifications_attempted,
                notifications_delivered=self._notifications_delivered,
                notification_failures=self._notification_failures,
                dispatch_failures=self._dispatch_failures,
                cache_evictions=self._cache_evictions,
            )

    def _notify(self, event: FalcoEvent, summary: str) -> None:
        if not self.desktop_notifications:
            return

        level = (
            "critical"
            if _PRIORITY_RANK[event.priority] >= _PRIORITY_RANK[FalcoPriority.ERROR]
            else "normal"
        )
        message = _truncate(summary, _MAX_NOTIFICATION_CHARS)
        with self._lock:
            self._notifications_attempted += 1

        delivered = False
        try:
            delivered = bool(
                self.notifier.send_notification(
                    "Herodium Falco Alert",
                    message,
                    level=level,
                )
            )
        # Notification backends are optional; never break the security engine.
        except Exception as exc:  # noqa: BLE001
            self.logger.error(
                "Falco desktop notification delivery failed: %s",
                type(exc).__name__,
            )

        with self._lock:
            if delivered:
                self._notifications_delivered += 1
            else:
                self._notification_failures += 1

    def _meets_minimum_priority(self, priority: FalcoPriority) -> bool:
        return (
            _PRIORITY_RANK[priority]
            >= _PRIORITY_RANK[self.minimum_priority]
        )

    def _should_notify(self, priority: FalcoPriority) -> bool:
        return (
            self.desktop_notifications
            and _PRIORITY_RANK[priority]
            >= _PRIORITY_RANK[self.notification_minimum_priority]
        )

    @staticmethod
    def _event_key(event: FalcoEvent) -> tuple[object, ...]:
        return (
            event.rule,
            event.priority.value,
            event.hostname,
            event.source,
            *(event.field(name) for name in _DEDUP_FIELDS),
        )

    @staticmethod
    def _summary(event: FalcoEvent, *, suppressed: int) -> str:
        parts = [
            "Falco alert:",
            f"rule={_truncate(event.rule, _MAX_CONTEXT_CHARS)}",
            f"priority={event.priority.value}",
            f"host={_truncate(event.hostname, _MAX_CONTEXT_CHARS)}",
            f"source={_truncate(event.source, _MAX_CONTEXT_CHARS)}",
        ]
        for label, field_names in _CONTEXT_FIELDS:
            value = _first_field(event, field_names)
            if value is not None:
                rendered = _truncate(_scalar_text(value), _MAX_CONTEXT_CHARS)
                parts.append(f"{label}={rendered}")
        if suppressed:
            parts.append(f"suppressed_since_last={suppressed}")
        return " ".join(parts)

    @staticmethod
    def _now() -> float:
        return time.monotonic()


def _first_field(
    event: FalcoEvent,
    names: tuple[str, ...],
) -> FalcoScalar:
    for name in names:
        value = event.field(name)
        if value is not None:
            return value
    return None


def _scalar_text(value: FalcoScalar) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _truncate(value: str, maximum: int) -> str:
    if len(value) <= maximum:
        return value
    if maximum <= 1:
        return value[:maximum]
    return value[: maximum - 1] + "\u2026"


def _parse_priority(value: object, *, name: str) -> FalcoPriority:
    if isinstance(value, FalcoPriority):
        return value
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string.")
    normalized = value.strip().upper()
    try:
        return FalcoPriority(normalized)
    except ValueError as exc:
        raise ValueError(f"{name} is not a supported Falco priority.") from exc


def _require_int(
    value: object,
    *,
    name: str,
    minimum: int,
    maximum: int,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer.")
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} is outside the safe range.")
    return value


def _require_float(
    value: object,
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


def _require_bool(value: object, *, name: str) -> bool:
    if not isinstance(value, bool):
        raise TypeError(f"{name} must be boolean.")
    return value
