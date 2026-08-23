import json
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
HERODIUM_ROOT = PROJECT_ROOT / "herodium"
if str(HERODIUM_ROOT) not in sys.path:
    sys.path.insert(0, str(HERODIUM_ROOT))

from modules.falco_event import (
    FalcoEventLimits,
    FalcoEventParseError,
    FalcoPriority,
    parse_falco_event,
)


def valid_event(**overrides):
    event = {
        "hostname": "test-host",
        "output": (
            "A shell was spawned "
            "(user=root process=sh command=sh -c id)"
        ),
        "priority": "Critical",
        "rule": "Terminal shell in container",
        "source": "syscall",
        "tags": ["container", "mitre_execution", "shell"],
        "time": "2026-08-05T00:44:05.478445995Z",
        "output_fields": {
            "evt.time": 1785887045478445995,
            "proc.cmdline": "sh -c id",
            "proc.name": "sh",
            "proc.pname": "runc",
            "user.loginuid": -1,
            "user.name": "root",
        },
    }
    event.update(overrides)
    return event


def encode_event(**overrides):
    return json.dumps(valid_event(**overrides), separators=(",", ":"))


class FalcoEventParsingTests(unittest.TestCase):
    def test_parses_official_json_shape(self):
        line = encode_event()

        event = parse_falco_event(line)

        self.assertEqual(event.rule, "Terminal shell in container")
        self.assertIs(event.priority, FalcoPriority.CRITICAL)
        self.assertEqual(event.hostname, "test-host")
        self.assertEqual(event.source, "syscall")
        self.assertEqual(
            event.tags,
            ("container", "mitre_execution", "shell"),
        )
        self.assertEqual(event.field("proc.name"), "sh")
        self.assertEqual(event.field("user.loginuid"), -1)
        self.assertIsNone(event.field("missing"))
        self.assertEqual(event.raw_size_bytes, len(line.encode("utf-8")))

    def test_accepts_utf8_bytes(self):
        event = parse_falco_event(encode_event().encode("utf-8"))

        self.assertEqual(event.rule, "Terminal shell in container")

    def test_normalizes_nanosecond_timestamp_to_utc(self):
        event = parse_falco_event(
            encode_event(time="2026-08-05T03:44:05.478445995+03:00")
        )

        self.assertEqual(
            event.timestamp,
            datetime(
                2026,
                8,
                5,
                0,
                44,
                5,
                478445,
                tzinfo=timezone.utc,
            ),
        )
        self.assertEqual(
            event.timestamp_text,
            "2026-08-05T03:44:05.478445995+03:00",
        )

    def test_priority_is_case_insensitive(self):
        event = parse_falco_event(encode_event(priority="warning"))

        self.assertIs(event.priority, FalcoPriority.WARNING)

    def test_duplicate_tags_are_coalesced_in_original_order(self):
        event = parse_falco_event(
            encode_event(tags=["host", "process", "host"])
        )

        self.assertEqual(event.tags, ("host", "process"))

    def test_output_fields_are_sorted_for_determinism(self):
        event = parse_falco_event(
            encode_event(output_fields={"z.field": 1, "a.field": 2})
        )

        self.assertEqual(
            event.output_fields,
            (("a.field", 2), ("z.field", 1)),
        )

    def test_control_characters_are_escaped_in_display_text(self):
        event = parse_falco_event(
            encode_event(
                output="safe\nforged\x1b[31m",
                output_fields={"proc.cmdline": "id\r\nforged"},
            )
        )

        self.assertEqual(event.output, "safe\\x0aforged\\x1b[31m")
        self.assertEqual(
            event.field("proc.cmdline"),
            "id\\x0d\\x0aforged",
        )

    def test_boolean_is_preserved_as_boolean(self):
        event = parse_falco_event(
            encode_event(output_fields={"container.privileged": True})
        )

        self.assertIs(event.field("container.privileged"), True)


class FalcoEventRejectionTests(unittest.TestCase):
    def assert_error(self, expected_code, line, *, limits=None):
        with self.assertRaises(FalcoEventParseError) as caught:
            parse_falco_event(line, limits=limits)
        self.assertEqual(caught.exception.code, expected_code)

    def test_rejects_invalid_input_type(self):
        self.assert_error("invalid_input_type", object())

    def test_rejects_empty_line(self):
        self.assert_error("empty_line", " \n")

    def test_rejects_invalid_utf8(self):
        self.assert_error("invalid_utf8", b'{"rule":"\xff"}')

    def test_rejects_oversized_line_before_json_parsing(self):
        limits = FalcoEventLimits(max_line_bytes=64)

        self.assert_error(
            "line_too_large",
            encode_event(),
            limits=limits,
        )

    def test_rejects_non_object_root(self):
        self.assert_error("invalid_root_type", "[]")

    def test_rejects_missing_required_root_field(self):
        event = valid_event()
        del event["source"]

        self.assert_error("missing_root_field", json.dumps(event))

    def test_rejects_unknown_root_field(self):
        self.assert_error(
            "unknown_root_field",
            encode_event(unexpected="value"),
        )

    def test_rejects_duplicate_root_key(self):
        line = encode_event()
        duplicate = line[:-1] + ',"rule":"second rule"}'

        self.assert_error("duplicate_json_key", duplicate)

    def test_rejects_duplicate_output_field_key(self):
        line = encode_event(output_fields={})
        line = line.replace(
            '"output_fields":{}',
            '"output_fields":{"proc.name":"sh","proc.name":"bash"}',
        )

        self.assert_error("duplicate_json_key", line)

    def test_rejects_invalid_priority(self):
        self.assert_error(
            "invalid_priority",
            encode_event(priority="SEVERE"),
        )

    def test_rejects_timestamp_without_timezone(self):
        self.assert_error(
            "invalid_timestamp",
            encode_event(time="2026-08-05T00:44:05.478445995"),
        )

    def test_rejects_invalid_calendar_timestamp(self):
        self.assert_error(
            "invalid_timestamp",
            encode_event(time="2026-13-40T00:44:05Z"),
        )

    def test_rejects_identifier_control_characters(self):
        self.assert_error(
            "unsafe_identifier",
            encode_event(rule="Trusted rule\nforged"),
        )

    def test_rejects_surrounding_identifier_whitespace(self):
        self.assert_error(
            "unsafe_identifier",
            encode_event(hostname=" test-host"),
        )

    def test_rejects_too_many_tags(self):
        limits = FalcoEventLimits(max_tags=2)

        self.assert_error(
            "too_many_tags",
            encode_event(tags=["one", "two", "three"]),
            limits=limits,
        )

    def test_rejects_non_string_tag(self):
        self.assert_error(
            "invalid_tag",
            encode_event(tags=["host", 7]),
        )

    def test_rejects_too_many_output_fields(self):
        limits = FalcoEventLimits(max_output_fields=1)

        self.assert_error(
            "too_many_output_fields",
            encode_event(output_fields={"one": 1, "two": 2}),
            limits=limits,
        )

    def test_rejects_nested_output_field(self):
        self.assert_error(
            "nested_output_field",
            encode_event(output_fields={"proc.details": {"name": "sh"}}),
        )

    def test_rejects_out_of_range_integer(self):
        self.assert_error(
            "integer_out_of_range",
            encode_event(output_fields={"evt.time": 2**65}),
        )

    def test_rejects_non_finite_number(self):
        line = encode_event(output_fields={"ratio": 1.0})
        line = line.replace("1.0", "NaN")

        self.assert_error("invalid_json_number", line)

    def test_rejects_unpaired_unicode_surrogate(self):
        line = encode_event(output_fields={})
        line = line.replace(
            '"output_fields":{}',
            '"output_fields":{"proc.name":"\\ud800"}',
        )

        self.assert_error("invalid_text", line)


if __name__ == "__main__":
    unittest.main()
