import json
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

from modules.falco_event import FalcoEventLimits
from modules.falco_reader import (
    FalcoCursor,
    FalcoCursorStore,
    FalcoJSONLReader,
    FalcoReaderError,
    FalcoReaderLimits,
)


def event_line(rule="Test rule", **overrides):
    event = {
        "hostname": "test-host",
        "output": f"Detected {rule}",
        "priority": "Notice",
        "rule": rule,
        "source": "syscall",
        "tags": ["host", "test"],
        "time": "2026-08-12T00:00:00.000000001Z",
        "output_fields": {
            "proc.name": "sh",
            "user.name": "test",
        },
    }
    event.update(overrides)
    return (json.dumps(event, separators=(",", ":")) + "\n").encode("utf-8")


class FalcoReaderTestCase(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.log_path = self.root / "falco-events.jsonl"
        self.cursor_path = self.root / "state" / "cursor.json"
        self.owner_uid = os.geteuid()

    def write_log(self, *lines, mode=0o640):
        self.log_path.write_bytes(b"".join(lines))
        self.log_path.chmod(mode)

    def append_log(self, *lines):
        with self.log_path.open("ab") as handle:
            for line in lines:
                handle.write(line)
            handle.flush()
            os.fsync(handle.fileno())

    def reader(self, **kwargs):
        return FalcoJSONLReader(
            self.log_path,
            self.cursor_path,
            expected_owner_uid=self.owner_uid,
            **kwargs,
        )

    def assert_reader_error(self, expected_code, callback):
        with self.assertRaises(FalcoReaderError) as caught:
            callback()
        self.assertEqual(caught.exception.code, expected_code)


class FalcoReaderPositionTests(FalcoReaderTestCase):
    def test_first_run_defaults_to_end(self):
        self.write_log(event_line("old"))
        reader = self.reader()
        self.addCleanup(reader.close)

        first = reader.poll()
        self.append_log(event_line("new"))
        second = reader.poll()

        self.assertEqual(first.events, ())
        self.assertEqual([event.rule for event in second.events], ["new"])

    def test_first_run_can_begin_at_start(self):
        self.write_log(event_line("one"), event_line("two"))
        reader = self.reader(start_position="beginning")
        self.addCleanup(reader.close)

        batch = reader.poll()

        self.assertEqual(
            [event.rule for event in batch.events],
            ["one", "two"],
        )

    def test_restart_resumes_from_persistent_cursor(self):
        self.write_log(event_line("one"))
        first = self.reader(start_position="beginning")
        self.assertEqual([event.rule for event in first.poll().events], ["one"])
        first.close()
        self.append_log(event_line("two"))

        second = self.reader(start_position="beginning")
        self.addCleanup(second.close)
        batch = second.poll()

        self.assertEqual([event.rule for event in batch.events], ["two"])

    def test_incomplete_trailing_record_waits_for_newline(self):
        complete = event_line("partial")
        self.write_log(complete[:-1])
        reader = self.reader(start_position="beginning")
        self.addCleanup(reader.close)

        first = reader.poll()
        self.append_log(b"\n")
        second = reader.poll()

        self.assertEqual(first.events, ())
        self.assertEqual(first.records_consumed, 0)
        self.assertEqual([event.rule for event in second.events], ["partial"])


class FalcoReaderBoundTests(FalcoReaderTestCase):
    def test_records_per_poll_is_bounded(self):
        self.write_log(*(event_line(f"rule-{index}") for index in range(5)))
        limits = FalcoReaderLimits(
            max_records_per_poll=2,
            max_bytes_per_poll=1024 * 1024,
        )
        reader = self.reader(
            start_position="beginning",
            reader_limits=limits,
        )
        self.addCleanup(reader.close)

        first = reader.poll()
        second = reader.poll()
        third = reader.poll()

        self.assertEqual(len(first.events), 2)
        self.assertEqual(len(second.events), 2)
        self.assertEqual(len(third.events), 1)

    def test_invalid_event_is_counted_without_stopping_stream(self):
        self.write_log(
            b'{"not":"falco"}\n',
            event_line("valid"),
        )
        reader = self.reader(start_position="beginning")
        self.addCleanup(reader.close)

        batch = reader.poll()

        self.assertEqual([event.rule for event in batch.events], ["valid"])
        self.assertEqual(batch.rejected, (("missing_root_field", 1),))
        self.assertEqual(reader.stats().events_rejected, 1)

    def test_oversized_record_resynchronizes_to_next_line(self):
        event_limits = FalcoEventLimits(max_line_bytes=256)
        oversized = b"{" + (b"x" * 700) + b"}\n"
        self.write_log(oversized, event_line("after-oversize"))
        reader = self.reader(
            start_position="beginning",
            event_limits=event_limits,
            reader_limits=FalcoReaderLimits(
                max_records_per_poll=8,
                max_bytes_per_poll=4096,
            ),
        )
        self.addCleanup(reader.close)

        batch = reader.poll()

        self.assertEqual(
            [event.rule for event in batch.events],
            ["after-oversize"],
        )
        self.assertEqual(batch.rejected, (("line_too_large", 1),))

    def test_oversize_discard_state_survives_restart(self):
        event_limits = FalcoEventLimits(max_line_bytes=256)
        huge_prefix = b"{" + (b"x" * 700)
        self.write_log(huge_prefix)
        limits = FalcoReaderLimits(
            max_records_per_poll=8,
            max_bytes_per_poll=257,
        )
        first = self.reader(
            start_position="beginning",
            event_limits=event_limits,
            reader_limits=limits,
        )

        batch = first.poll()
        first.close()
        self.assertEqual(batch.rejected, (("line_too_large", 1),))
        self.append_log(b"}\n", event_line("after-restart"))

        second = self.reader(
            start_position="beginning",
            event_limits=event_limits,
            reader_limits=FalcoReaderLimits(
                max_records_per_poll=8,
                max_bytes_per_poll=4096,
            ),
        )
        self.addCleanup(second.close)
        resumed = second.poll()

        self.assertEqual(
            [event.rule for event in resumed.events],
            ["after-restart"],
        )

    def test_reader_limits_reject_too_small_byte_budget(self):
        self.write_log()

        with self.assertRaises(ValueError):
            self.reader(
                event_limits=FalcoEventLimits(max_line_bytes=1024),
                reader_limits=FalcoReaderLimits(max_bytes_per_poll=1024),
            )


class FalcoReaderRotationTests(FalcoReaderTestCase):
    def test_copytruncate_resets_same_inode_to_start(self):
        self.write_log(event_line("before"))
        reader = self.reader(start_position="beginning")
        self.addCleanup(reader.close)
        self.assertEqual([event.rule for event in reader.poll().events], ["before"])

        with self.log_path.open("wb") as handle:
            handle.write(event_line("after"))
            handle.flush()
            os.fsync(handle.fileno())

        batch = reader.poll()

        self.assertTrue(batch.truncation_detected)
        self.assertEqual([event.rule for event in batch.events], ["after"])

    def test_rotation_drains_open_old_file_then_reads_new_file(self):
        self.write_log(event_line("one"))
        limits = FalcoReaderLimits(
            max_records_per_poll=1,
            max_bytes_per_poll=1024 * 1024,
        )
        reader = self.reader(
            start_position="beginning",
            reader_limits=limits,
        )
        self.addCleanup(reader.close)
        self.assertEqual([event.rule for event in reader.poll().events], ["one"])
        self.append_log(event_line("old-tail"))

        rotated = self.root / "falco-events.jsonl.1"
        self.log_path.rename(rotated)
        self.write_log(event_line("new-file"))

        old_batch = reader.poll()
        new_batch = reader.poll()

        self.assertEqual([event.rule for event in old_batch.events], ["old-tail"])
        self.assertEqual([event.rule for event in new_batch.events], ["new-file"])
        self.assertTrue(new_batch.rotation_detected)

    def test_restart_after_rotation_reads_replacement_from_start(self):
        self.write_log(event_line("old"))
        first = self.reader(start_position="beginning")
        self.assertEqual([event.rule for event in first.poll().events], ["old"])
        first.close()

        self.log_path.rename(self.root / "falco-events.jsonl.1")
        self.write_log(event_line("new"))

        second = self.reader(start_position="end")
        self.addCleanup(second.close)
        batch = second.poll()

        self.assertTrue(batch.rotation_detected)
        self.assertEqual([event.rule for event in batch.events], ["new"])


class FalcoReaderSourceSafetyTests(FalcoReaderTestCase):
    def test_missing_source_is_reported(self):
        reader = self.reader()

        self.assert_reader_error("source_missing", reader.poll)

    def test_source_symlink_is_rejected(self):
        target = self.root / "target.jsonl"
        target.write_bytes(event_line())
        target.chmod(0o640)
        self.log_path.symlink_to(target)
        reader = self.reader(start_position="beginning")

        self.assert_reader_error("unsafe_path", reader.poll)

    def test_source_with_unexpected_owner_is_rejected(self):
        self.write_log(event_line())
        reader = FalcoJSONLReader(
            self.log_path,
            self.cursor_path,
            expected_owner_uid=self.owner_uid + 1,
            start_position="beginning",
        )

        self.assert_reader_error("unsafe_owner", reader.poll)

    def test_group_writable_source_is_rejected(self):
        self.write_log(event_line(), mode=0o660)
        reader = self.reader(start_position="beginning")

        self.assert_reader_error("unsafe_permissions", reader.poll)

    def test_directory_source_is_rejected(self):
        self.log_path.mkdir()
        reader = self.reader(start_position="beginning")

        self.assert_reader_error("unsafe_path", reader.poll)

    def test_group_writable_event_log_directory_is_rejected(self):
        self.write_log(event_line())
        self.root.chmod(0o770)
        self.addCleanup(self.root.chmod, 0o700)
        reader = self.reader(start_position="beginning")

        self.assert_reader_error("unsafe_permissions", reader.poll)

    def test_relative_event_log_path_is_rejected(self):
        with self.assertRaises(ValueError):
            FalcoJSONLReader(
                "relative.jsonl",
                self.cursor_path,
                expected_owner_uid=self.owner_uid,
            )


class FalcoCursorStoreTests(FalcoReaderTestCase):
    def test_cursor_is_atomic_private_and_round_trips(self):
        store = FalcoCursorStore(
            self.cursor_path,
            expected_owner_uid=self.owner_uid,
        )
        expected = FalcoCursor(
            device=10,
            inode=20,
            offset=30,
            discard_until_newline=True,
        )

        store.save(expected)
        loaded = store.load()

        self.assertEqual(loaded, expected)
        self.assertEqual(stat.S_IMODE(self.cursor_path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.cursor_path.parent.stat().st_mode), 0o700)
        temporary = list(self.cursor_path.parent.glob(".cursor.json.tmp-*"))
        self.assertEqual(temporary, [])

    def test_cursor_symlink_is_rejected(self):
        self.cursor_path.parent.mkdir(mode=0o700)
        target = self.root / "outside-cursor.json"
        target.write_text("{}", encoding="utf-8")
        target.chmod(0o600)
        self.cursor_path.symlink_to(target)
        store = FalcoCursorStore(
            self.cursor_path,
            expected_owner_uid=self.owner_uid,
        )

        self.assert_reader_error("unsafe_path", store.load)

    def test_group_writable_cursor_is_rejected(self):
        store = FalcoCursorStore(
            self.cursor_path,
            expected_owner_uid=self.owner_uid,
        )
        store.save(FalcoCursor(device=1, inode=2, offset=3))
        self.cursor_path.chmod(0o620)

        self.assert_reader_error("unsafe_permissions", store.load)

    def test_malformed_cursor_is_rejected(self):
        self.cursor_path.parent.mkdir(mode=0o700)
        self.cursor_path.write_text("{not-json}\n", encoding="utf-8")
        self.cursor_path.chmod(0o600)
        store = FalcoCursorStore(
            self.cursor_path,
            expected_owner_uid=self.owner_uid,
        )

        self.assert_reader_error("invalid_cursor", store.load)

    def test_duplicate_cursor_key_is_rejected(self):
        self.cursor_path.parent.mkdir(mode=0o700)
        self.cursor_path.write_text(
            '{"version":1,"device":1,"device":2,"inode":2,'
            '"offset":3,"discard_until_newline":false}\n',
            encoding="utf-8",
        )
        self.cursor_path.chmod(0o600)
        store = FalcoCursorStore(
            self.cursor_path,
            expected_owner_uid=self.owner_uid,
        )

        self.assert_reader_error("invalid_cursor", store.load)

    def test_cursor_state_directory_symlink_is_rejected(self):
        real_state = self.root / "real-state"
        real_state.mkdir(mode=0o700)
        self.cursor_path.parent.symlink_to(real_state, target_is_directory=True)
        store = FalcoCursorStore(
            self.cursor_path,
            expected_owner_uid=self.owner_uid,
        )

        self.assert_reader_error("unsafe_path", store.load)

    def test_group_writable_cursor_parent_is_rejected(self):
        self.root.chmod(0o770)
        self.addCleanup(self.root.chmod, 0o700)
        store = FalcoCursorStore(
            self.cursor_path,
            expected_owner_uid=self.owner_uid,
        )

        self.assert_reader_error("unsafe_permissions", store.load)

    def test_relative_cursor_path_is_rejected(self):
        with self.assertRaises(ValueError):
            FalcoCursorStore(
                "relative-cursor.json",
                expected_owner_uid=self.owner_uid,
            )

    def test_cursor_accepts_full_unsigned_device_and_inode_range(self):
        store = FalcoCursorStore(
            self.cursor_path,
            expected_owner_uid=self.owner_uid,
        )
        expected = FalcoCursor(
            device=(2**64) - 1,
            inode=(2**64) - 1,
            offset=0,
        )

        store.save(expected)

        self.assertEqual(store.load(), expected)


if __name__ == "__main__":
    unittest.main()
