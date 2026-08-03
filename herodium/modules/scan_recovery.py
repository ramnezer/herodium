import errno
import os
import threading
import time
from collections import OrderedDict


class ScanRecoveryController:
    """Bounded root-level catch-up scans for dropped filesystem events."""

    def __init__(
        self,
        config,
        logger,
        *,
        queue_capacity,
        scan_file,
        should_ignore,
        queue_size,
        is_running,
        watch_roots,
    ):
        self.logger = logger
        self.scan_file = scan_file
        self.should_ignore = should_ignore
        self.queue_size = queue_size
        self.is_running = is_running

        self.enabled = self._safe_bool(
            config.get("scan_recovery_enable", True), True
        )
        self.max_roots = self._bounded_int(
            config.get("scan_recovery_max_roots"), 8, 1, 128
        )
        self.low_watermark_percent = self._bounded_int(
            config.get("scan_recovery_queue_low_watermark_percent"),
            25,
            0,
            90,
        )
        self.max_files_per_pass = self._bounded_int(
            config.get("scan_recovery_max_files_per_pass"),
            2048,
            1,
            100000,
        )
        self.max_total_files_per_root = self._bounded_int(
            config.get("scan_recovery_max_total_files_per_root"),
            250000,
            1,
            1000000,
        )
        self.max_seconds_per_pass = self._bounded_int(
            config.get("scan_recovery_max_seconds_per_pass"),
            5,
            1,
            300,
        )
        self.max_depth = self._bounded_int(
            config.get("scan_recovery_max_depth"), 64, 1, 256
        )
        self.directory_warning_interval_seconds = self._bounded_int(
            config.get("scan_recovery_directory_warning_interval_seconds"),
            30,
            1,
            3600,
        )
        self.low_watermark = int(
            queue_capacity * self.low_watermark_percent / 100
        )

        self._state_lock = threading.Lock()
        self._run_lock = threading.Lock()
        self._roots = OrderedDict()
        self._watch_roots = set()
        self._removable_roots = set()
        self._active_root = None
        self._active_iterator = None
        self._active_files = 0
        self._active_transient_directory_errors = 0
        self._active_directory_errors = 0
        self._last_directory_warning = 0.0

        self._scans_started_total = 0
        self._files_scanned_total = 0
        self._roots_removed_total = 0
        self._roots_completed_total = 0
        self._roots_truncated_total = 0
        self._roots_rejected_total = 0
        self._transient_directory_errors_total = 0
        self._directory_errors_total = 0

        for root in watch_roots:
            self.add_watch_root(root)

    @staticmethod
    def _safe_bool(value, default=False):
        if isinstance(value, bool):
            return value
        if isinstance(value, int) and value in (0, 1):
            return bool(value)
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in ("1", "true", "yes", "on"):
                return True
            if normalized in ("0", "false", "no", "off"):
                return False
        return default

    @staticmethod
    def _bounded_int(value, default, minimum, maximum):
        if isinstance(value, bool):
            return default
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            return default
        return max(minimum, min(maximum, parsed))

    @staticmethod
    def _normalize_directory(path):
        if not isinstance(path, str) or not path.strip():
            return None
        normalized = os.path.normpath(path.strip())
        if not os.path.isabs(normalized):
            return None
        return normalized

    @staticmethod
    def _is_within(path, directory):
        normalized_path = ScanRecoveryController._normalize_directory(path)
        normalized_directory = ScanRecoveryController._normalize_directory(
            directory
        )
        if normalized_path is None or normalized_directory is None:
            return False
        return normalized_path == normalized_directory or normalized_path.startswith(
            normalized_directory + os.sep
        )

    def add_watch_root(self, root, *, removable=False):
        normalized = self._normalize_directory(root)
        if normalized is None:
            return False
        with self._state_lock:
            self._watch_roots.add(normalized)
            if removable:
                self._removable_roots.add(normalized)
            else:
                self._removable_roots.discard(normalized)
        return True

    def remove_watch_root(self, root, reason="removed"):
        normalized = self._normalize_directory(root)
        if normalized is None:
            return 0

        removed_roots = []
        with self._state_lock:
            self._watch_roots.discard(normalized)
            self._removable_roots.discard(normalized)
            for recovery_root in tuple(self._roots):
                if recovery_root == self._active_root:
                    continue
                if self._is_within(recovery_root, normalized):
                    self._roots.pop(recovery_root, None)
                    self._roots_removed_total += 1
                    removed_roots.append(recovery_root)

        for recovery_root in removed_roots:
            self.logger.info(
                "Scan recovery root removed: "
                f"root={recovery_root}, reason={reason}"
            )
        return len(removed_roots)

    def _find_root_locked(self, path, root_hint=None):
        normalized_path = self._normalize_directory(path)
        if normalized_path is None:
            return None

        normalized_hint = self._normalize_directory(root_hint)
        if (
            normalized_hint is not None
            and normalized_hint in self._watch_roots
            and self._is_within(normalized_path, normalized_hint)
        ):
            return normalized_hint

        matches = [
            root
            for root in self._watch_roots
            if self._is_within(normalized_path, root)
        ]
        if not matches:
            return None
        return max(matches, key=len)

    def schedule(self, path, root_hint=None):
        if not self.enabled:
            return None

        with self._state_lock:
            root = self._find_root_locked(path, root_hint)
            if root is None or root in self._roots:
                return None
            if len(self._roots) >= self.max_roots:
                self._roots_rejected_total += 1
                return None
            self._roots[root] = None
            return root

    def is_pending(self, root):
        normalized = self._normalize_directory(root)
        if normalized is None:
            return False
        with self._state_lock:
            return normalized in self._roots

    def stats(self):
        with self._state_lock:
            return {
                "recovery_roots_pending": len(self._roots),
                "recovery_scans_started": self._scans_started_total,
                "recovery_files_scanned": self._files_scanned_total,
                "recovery_roots_removed": self._roots_removed_total,
                "recovery_roots_completed": self._roots_completed_total,
                "recovery_roots_truncated": self._roots_truncated_total,
                "recovery_roots_rejected": self._roots_rejected_total,
                "recovery_transient_directory_errors": (
                    self._transient_directory_errors_total
                ),
                "recovery_directory_errors": self._directory_errors_total,
            }

    def _root_available(self, root):
        with self._state_lock:
            watched = any(
                self._is_within(root, watch_root)
                for watch_root in self._watch_roots
            )
            removable = root in self._removable_roots
        if not watched or not os.path.isdir(root):
            return False
        return not removable or os.path.ismount(root)

    def _walk_error(self, error):
        error_number = getattr(error, "errno", None)
        transient = error_number in {
            errno.ENOENT,
            errno.ENOTDIR,
            getattr(errno, "ESTALE", 116),
        }
        with self._state_lock:
            if transient:
                self._active_transient_directory_errors += 1
                self._transient_directory_errors_total += 1
            else:
                self._active_directory_errors += 1
                self._directory_errors_total += 1

        if transient:
            self.logger.debug(
                "Recovery scan path disappeared during traversal: %s",
                error,
            )
            return

        now = time.monotonic()
        if (
            now - self._last_directory_warning
            < self.directory_warning_interval_seconds
        ):
            return
        self._last_directory_warning = now
        self.logger.warning(f"Recovery scan directory error: {error}")

    def _iter_files(self, root):
        root_depth = root.rstrip(os.sep).count(os.sep)
        for current_root, directories, files in os.walk(
            root,
            topdown=True,
            onerror=self._walk_error,
            followlinks=False,
        ):
            if not self.is_running() or not self._root_available(root):
                return

            current_depth = current_root.rstrip(os.sep).count(os.sep) - root_depth
            filtered_directories = []
            if current_depth < self.max_depth:
                for name in sorted(directories):
                    candidate = os.path.join(current_root, name)
                    if os.path.islink(candidate):
                        continue
                    if not self.should_ignore(candidate):
                        filtered_directories.append(name)
            directories[:] = filtered_directories

            for name in sorted(files):
                candidate = os.path.join(current_root, name)
                if self.should_ignore(candidate):
                    continue
                try:
                    if os.path.islink(candidate) or not os.path.isfile(candidate):
                        continue
                except OSError as error:
                    self.logger.debug(
                        "Recovery scan skipped unavailable path "
                        f"{candidate}: {error}"
                    )
                    continue
                yield candidate

    def _reset_active_locked(self):
        self._active_root = None
        self._active_iterator = None
        self._active_files = 0
        self._active_transient_directory_errors = 0
        self._active_directory_errors = 0

    def _remove_active_unavailable(self, root, reason):
        removed = False
        with self._state_lock:
            if root in self._roots:
                self._roots.pop(root, None)
                self._roots_removed_total += 1
                removed = True
            if self._active_root == root:
                self._reset_active_locked()

        if removed:
            self.logger.info(
                f"Scan recovery root removed: root={root}, reason={reason}"
            )

    def _complete_active(self, root, *, truncated=False, events_dropped=0):
        with self._state_lock:
            root_files_scanned = self._active_files
            transient_directory_errors = (
                self._active_transient_directory_errors
            )
            directory_errors = self._active_directory_errors
            self._roots.pop(root, None)
            if truncated:
                self._roots_truncated_total += 1
            else:
                self._roots_completed_total += 1
            pending_roots = len(self._roots)
            total_files_scanned = self._files_scanned_total
            self._reset_active_locked()

        outcome = "truncated" if truncated else "completed"
        message = (
            f"Scan recovery {outcome}: root={root}, "
            f"files_scanned={root_files_scanned}, "
            f"recovery_files_scanned_total={total_files_scanned}, "
            f"events_dropped={events_dropped}, "
            f"recovery_roots_pending={pending_roots}"
        )
        if transient_directory_errors or directory_errors:
            message += (
                ", transient_directory_changes="
                f"{transient_directory_errors}, "
                f"directory_errors={directory_errors}"
            )
        if truncated:
            self.logger.warning(message)
        else:
            self.logger.info(message)

    def _select_root(self):
        with self._state_lock:
            if self._active_root is not None:
                return self._active_root, False
            if not self._roots:
                return None, False

            root = next(iter(self._roots))
            self._active_root = root
            self._active_iterator = self._iter_files(root)
            self._active_files = 0
            self._active_transient_directory_errors = 0
            self._active_directory_errors = 0
            self._scans_started_total += 1
            return root, True

    def run_once(self, *, events_dropped=0):
        if not self.enabled or not self.is_running():
            return False
        if self.queue_size() > self.low_watermark:
            return False
        if not self._run_lock.acquire(blocking=False):
            return False

        try:
            root, started = self._select_root()
            if root is None:
                return False
            if not self._root_available(root):
                self._remove_active_unavailable(root, "unavailable")
                return False

            if started:
                self.logger.info(
                    f"Scan recovery started: root={root}, "
                    f"queue_low_watermark={self.low_watermark}"
                )

            deadline = time.monotonic() + self.max_seconds_per_pass
            files_this_pass = 0
            while self.is_running():
                if self.queue_size() > self.low_watermark:
                    return True
                if files_this_pass >= self.max_files_per_pass:
                    return True
                if time.monotonic() >= deadline:
                    return True
                if not self._root_available(root):
                    self._remove_active_unavailable(root, "disconnected")
                    return True
                if self._active_files >= self.max_total_files_per_root:
                    self._complete_active(
                        root,
                        truncated=True,
                        events_dropped=events_dropped,
                    )
                    return True

                try:
                    path = next(self._active_iterator)
                except StopIteration:
                    if not self._root_available(root):
                        self._remove_active_unavailable(
                            root,
                            "disconnected",
                        )
                    else:
                        self._complete_active(
                            root,
                            events_dropped=events_dropped,
                        )
                    return True

                self.scan_file(path)
                files_this_pass += 1
                with self._state_lock:
                    self._active_files += 1
                    self._files_scanned_total += 1
            return True
        finally:
            self._run_lock.release()

    def stop(self):
        with self._state_lock:
            self._roots.clear()
            self._watch_roots.clear()
            self._removable_roots.clear()
            self._reset_active_locked()
