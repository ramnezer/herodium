from __future__ import annotations

import json
import math
import re
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Final, TypeAlias

FalcoScalar: TypeAlias = str | int | float | bool | None

_REQUIRED_ROOT_FIELDS: Final = frozenset(
    {
        "time",
        "rule",
        "priority",
        "output",
        "hostname",
        "source",
        "tags",
        "output_fields",
    }
)
_ALLOWED_ROOT_FIELDS: Final = _REQUIRED_ROOT_FIELDS
_TIMESTAMP_PATTERN: Final = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"
    r"(?P<fraction>\.\d{1,9})?"
    r"(?P<timezone>Z|[+-]\d{2}:\d{2})$"
)
_MIN_INTEGER: Final = -(2**63)
_MAX_INTEGER: Final = (2**64) - 1


class FalcoPriority(str, Enum):
    EMERGENCY = "EMERGENCY"
    ALERT = "ALERT"
    CRITICAL = "CRITICAL"
    ERROR = "ERROR"
    WARNING = "WARNING"
    NOTICE = "NOTICE"
    INFORMATIONAL = "INFORMATIONAL"
    DEBUG = "DEBUG"


@dataclass(frozen=True)
class FalcoEventLimits:
    max_line_bytes: int = 65536
    max_root_fields: int = 16
    max_rule_bytes: int = 256
    max_output_bytes: int = 8192
    max_hostname_bytes: int = 255
    max_source_bytes: int = 64
    max_tags: int = 32
    max_tag_bytes: int = 128
    max_output_fields: int = 128
    max_output_field_name_bytes: int = 256
    max_output_field_value_bytes: int = 8192


@dataclass(frozen=True)
class FalcoEvent:
    timestamp: datetime
    timestamp_text: str
    rule: str
    priority: FalcoPriority
    output: str
    hostname: str
    source: str
    tags: tuple[str, ...]
    output_fields: tuple[tuple[str, FalcoScalar], ...]
    raw_size_bytes: int

    def field(self, name: str, default: FalcoScalar = None) -> FalcoScalar:
        for field_name, value in self.output_fields:
            if field_name == name:
                return value
        return default


class FalcoEventParseError(ValueError):
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


class _DuplicateJSONKeyError(ValueError):
    pass


class _InvalidJSONConstantError(ValueError):
    pass


def parse_falco_event(
    line: str | bytes,
    *,
    limits: FalcoEventLimits | None = None,
) -> FalcoEvent:
    """Parse one bounded Falco JSON output line into an immutable event."""
    active_limits = limits or FalcoEventLimits()
    text, raw_size = _decode_line(line, active_limits.max_line_bytes)
    payload = _load_json_object(text)

    if len(payload) > active_limits.max_root_fields:
        raise FalcoEventParseError(
            "too_many_root_fields",
            "Falco event contains too many top-level fields.",
        )

    missing = _REQUIRED_ROOT_FIELDS.difference(payload)
    if missing:
        raise FalcoEventParseError(
            "missing_root_field",
            "Falco event is missing a required top-level field.",
        )

    unknown = set(payload).difference(_ALLOWED_ROOT_FIELDS)
    if unknown:
        raise FalcoEventParseError(
            "unknown_root_field",
            "Falco event contains an unsupported top-level field.",
        )

    timestamp_text = _require_identifier(
        payload,
        "time",
        maximum_bytes=64,
    )
    timestamp = _parse_timestamp(timestamp_text)
    rule = _require_identifier(
        payload,
        "rule",
        maximum_bytes=active_limits.max_rule_bytes,
    )
    priority = _parse_priority(payload.get("priority"))
    output = _require_display_text(
        payload,
        "output",
        maximum_bytes=active_limits.max_output_bytes,
    )
    hostname = _require_identifier(
        payload,
        "hostname",
        maximum_bytes=active_limits.max_hostname_bytes,
    )
    source = _require_identifier(
        payload,
        "source",
        maximum_bytes=active_limits.max_source_bytes,
    )
    tags = _parse_tags(payload.get("tags"), active_limits)
    output_fields = _parse_output_fields(
        payload.get("output_fields"),
        active_limits,
    )

    return FalcoEvent(
        timestamp=timestamp,
        timestamp_text=timestamp_text,
        rule=rule,
        priority=priority,
        output=output,
        hostname=hostname,
        source=source,
        tags=tags,
        output_fields=output_fields,
        raw_size_bytes=raw_size,
    )


def _decode_line(line: str | bytes, maximum_bytes: int) -> tuple[str, int]:
    if isinstance(line, bytes):
        raw_size = len(line)
        if raw_size > maximum_bytes:
            raise FalcoEventParseError(
                "line_too_large",
                "Falco event exceeds the configured line-size limit.",
            )
        try:
            text = line.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise FalcoEventParseError(
                "invalid_utf8",
                "Falco event is not valid UTF-8.",
            ) from exc
    elif isinstance(line, str):
        try:
            encoded = line.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise FalcoEventParseError(
                "invalid_text",
                "Falco event contains invalid Unicode text.",
            ) from exc
        raw_size = len(encoded)
        if raw_size > maximum_bytes:
            raise FalcoEventParseError(
                "line_too_large",
                "Falco event exceeds the configured line-size limit.",
            )
        text = line
    else:
        raise FalcoEventParseError(
            "invalid_input_type",
            "Falco event input must be text or bytes.",
        )

    if not text.strip():
        raise FalcoEventParseError(
            "empty_line",
            "Falco event line is empty.",
        )

    return text, raw_size


def _load_json_object(text: str) -> dict[str, Any]:
    try:
        payload = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_invalid_constant,
        )
    except _DuplicateJSONKeyError as exc:
        raise FalcoEventParseError(
            "duplicate_json_key",
            "Falco event contains a duplicate JSON key.",
        ) from exc
    except _InvalidJSONConstantError as exc:
        raise FalcoEventParseError(
            "invalid_json_number",
            "Falco event contains a non-finite JSON number.",
        ) from exc
    except (json.JSONDecodeError, RecursionError) as exc:
        raise FalcoEventParseError(
            "invalid_json",
            "Falco event is not a valid bounded JSON object.",
        ) from exc

    if not isinstance(payload, dict):
        raise FalcoEventParseError(
            "invalid_root_type",
            "Falco event root must be a JSON object.",
        )

    return payload


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJSONKeyError(key)
        result[key] = value
    return result


def _reject_invalid_constant(value: str) -> None:
    raise _InvalidJSONConstantError(value)


def _require_identifier(
    payload: dict[str, Any],
    key: str,
    *,
    maximum_bytes: int,
) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise FalcoEventParseError(
            "invalid_text_field",
            "Falco event contains an invalid required text field.",
        )
    _validate_identifier(value, maximum_bytes=maximum_bytes)
    return value


def _require_display_text(
    payload: dict[str, Any],
    key: str,
    *,
    maximum_bytes: int,
) -> str:
    value = payload.get(key)
    if not isinstance(value, str):
        raise FalcoEventParseError(
            "invalid_text_field",
            "Falco event contains an invalid required text field.",
        )
    return _sanitize_display_text(value, maximum_bytes=maximum_bytes)


def _validate_identifier(value: str, *, maximum_bytes: int) -> None:
    if value != value.strip():
        raise FalcoEventParseError(
            "unsafe_identifier",
            "Falco event identifier contains surrounding whitespace.",
        )

    for character in value:
        category = unicodedata.category(character)
        if category.startswith("C") or category in ("Zl", "Zp"):
            raise FalcoEventParseError(
                "unsafe_identifier",
                "Falco event identifier contains unsafe control text.",
            )

    _validate_utf8_size(value, maximum_bytes=maximum_bytes)


def _sanitize_display_text(value: str, *, maximum_bytes: int) -> str:
    characters: list[str] = []
    for character in value:
        category = unicodedata.category(character)
        if category == "Cs":
            raise FalcoEventParseError(
                "invalid_text",
                "Falco event contains invalid Unicode text.",
            )
        if category.startswith("C") or category in ("Zl", "Zp"):
            codepoint = ord(character)
            if codepoint <= 0xFF:
                characters.append(f"\\x{codepoint:02x}")
            elif codepoint <= 0xFFFF:
                characters.append(f"\\u{codepoint:04x}")
            else:
                characters.append(f"\\U{codepoint:08x}")
        else:
            characters.append(character)

    sanitized = "".join(characters)
    _validate_utf8_size(sanitized, maximum_bytes=maximum_bytes)
    return sanitized


def _validate_utf8_size(value: str, *, maximum_bytes: int) -> None:
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise FalcoEventParseError(
            "invalid_text",
            "Falco event contains invalid Unicode text.",
        ) from exc

    if len(encoded) > maximum_bytes:
        raise FalcoEventParseError(
            "text_field_too_large",
            "Falco event text field exceeds its size limit.",
        )


def _parse_timestamp(value: str) -> datetime:
    match = _TIMESTAMP_PATTERN.fullmatch(value)
    if match is None:
        raise FalcoEventParseError(
            "invalid_timestamp",
            "Falco event timestamp is not a supported ISO-8601 value.",
        )

    fraction = match.group("fraction") or ""
    if fraction:
        fraction = f".{fraction[1:7].ljust(6, '0')}"

    zone = match.group("timezone")
    if zone == "Z":
        zone = "+00:00"

    normalized = f"{match.group('date')}{fraction}{zone}"
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise FalcoEventParseError(
            "invalid_timestamp",
            "Falco event timestamp is not a valid calendar value.",
        ) from exc

    if parsed.tzinfo is None:
        raise FalcoEventParseError(
            "invalid_timestamp",
            "Falco event timestamp must include a timezone.",
        )

    return parsed.astimezone(timezone.utc)


def _parse_priority(value: Any) -> FalcoPriority:
    if not isinstance(value, str) or not value:
        raise FalcoEventParseError(
            "invalid_priority",
            "Falco event priority must be a supported text value.",
        )
    _validate_identifier(value, maximum_bytes=32)
    try:
        return FalcoPriority(value.upper())
    except ValueError as exc:
        raise FalcoEventParseError(
            "invalid_priority",
            "Falco event priority is unsupported.",
        ) from exc


def _parse_tags(value: Any, limits: FalcoEventLimits) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise FalcoEventParseError(
            "invalid_tags",
            "Falco event tags must be a JSON array.",
        )
    if len(value) > limits.max_tags:
        raise FalcoEventParseError(
            "too_many_tags",
            "Falco event contains too many tags.",
        )

    result: list[str] = []
    seen: set[str] = set()
    for tag in value:
        if not isinstance(tag, str) or not tag:
            raise FalcoEventParseError(
                "invalid_tag",
                "Falco event contains an invalid tag.",
            )
        _validate_identifier(tag, maximum_bytes=limits.max_tag_bytes)
        if tag not in seen:
            result.append(tag)
            seen.add(tag)

    return tuple(result)


def _parse_output_fields(
    value: Any,
    limits: FalcoEventLimits,
) -> tuple[tuple[str, FalcoScalar], ...]:
    if not isinstance(value, dict):
        raise FalcoEventParseError(
            "invalid_output_fields",
            "Falco output_fields must be a JSON object.",
        )
    if len(value) > limits.max_output_fields:
        raise FalcoEventParseError(
            "too_many_output_fields",
            "Falco event contains too many output fields.",
        )

    result: list[tuple[str, FalcoScalar]] = []
    for field_name, field_value in value.items():
        if not isinstance(field_name, str) or not field_name:
            raise FalcoEventParseError(
                "invalid_output_field_name",
                "Falco event contains an invalid output-field name.",
            )
        _validate_identifier(
            field_name,
            maximum_bytes=limits.max_output_field_name_bytes,
        )
        normalized = _normalize_scalar(
            field_value,
            maximum_text_bytes=limits.max_output_field_value_bytes,
        )
        result.append((field_name, normalized))

    result.sort(key=lambda item: item[0])
    return tuple(result)


def _normalize_scalar(
    value: Any,
    *,
    maximum_text_bytes: int,
) -> FalcoScalar:
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, str):
        return _sanitize_display_text(
            value,
            maximum_bytes=maximum_text_bytes,
        )
    if isinstance(value, int):
        if value < _MIN_INTEGER or value > _MAX_INTEGER:
            raise FalcoEventParseError(
                "integer_out_of_range",
                "Falco event integer is outside the supported range.",
            )
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise FalcoEventParseError(
                "invalid_json_number",
                "Falco event contains a non-finite number.",
            )
        return value

    raise FalcoEventParseError(
        "nested_output_field",
        "Falco output-field values must be scalar JSON values.",
    )
