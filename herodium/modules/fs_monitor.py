import sys, time, logging, os, threading, psutil, queue
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from modules.av_scanner import ClamAVScanner
from modules.scan_recovery import ScanRecoveryController

class Handler(FileSystemEventHandler):
    def __init__(
        self,
        enqueue_func,
        logger,
        ignored_prefixes,
        ignore_user_cache=False,
        clamav_temp_directory=None,
    ):
        self.enqueue = enqueue_func
        self.logger = logger
        self.ignored_prefixes = ignored_prefixes
        self.ignore_user_cache = ignore_user_cache
        self.clamav_temp_directory = self._normalize_directory(
            clamav_temp_directory
        )

    @staticmethod
    def _normalize_directory(path):
        if not isinstance(path, str) or not path.strip():
            return None

        normalized = os.path.normpath(path.strip())
        if not os.path.isabs(normalized):
            return None
        return normalized

    @staticmethod
    def _is_within_directory(path, directory):
        if directory is None:
            return False

        normalized = os.path.normpath(path)
        return normalized == directory or normalized.startswith(
            directory + os.sep
        )

    def _should_ignore(self, path: str) -> bool:
        # Defensive checks
        if not path or not isinstance(path, str):
            return True

        # Ignore clamd's private extraction workspace. Scanning files created
        # by clamd itself creates a feedback loop: each INSTREAM scan can create
        # more temporary files, which Watchdog would enqueue for another scan.
        if self._is_within_directory(path, self.clamav_temp_directory):
            return True

        # Ignore system paths quickly (tuple-aware)
        if path.startswith(self.ignored_prefixes):
            return True

        # Optional: ignore user cache folders for performance
        if self.ignore_user_cache:
            # Root cache
            if path.startswith("/root/.cache/") or path == "/root/.cache":
                return True

            # Any user cache inside /home/*
            if path.startswith("/home/") and "/.cache/" in path:
                return True
            if path.startswith("/home/") and path.endswith("/.cache"):
                return True

        return False

    def _process(self, path):
        # Quick filtering of irrelevant paths
        if self._should_ignore(path):
            return

        if os.path.exists(path) and os.path.isfile(path):
            self.enqueue(path)

    def on_created(self, event):
        if not event.is_directory:
            self._process(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self._process(event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self._process(event.dest_path)

class Watcher:
    def __init__(self, config, logger):
        self.config = config
        self.logger, self.running = logger, True
        self.observer = Observer()
        self.scanner = ClamAVScanner(config, logger)

        dirs_cfg = (config.get("directories", {}) or {})
        clam_cfg = (config.get("clamav", {}) or {})
        self.clamav_temp_directory = Handler._normalize_directory(
            clam_cfg.get(
                "temporary_directory",
                "/var/lib/clamav/herodium-tmp",
            )
        )
        self.queue_max_size = self._bounded_int(
            dirs_cfg.get("scan_queue_max_size"), 1024, 1, 65536
        )
        self.queue_warning_interval_seconds = self._bounded_int(
            dirs_cfg.get("scan_queue_warning_interval_seconds"), 30, 1, 3600
        )
        self.scan_queue = queue.Queue(maxsize=self.queue_max_size)

        # Queue dedup state:
        # pending = paths that are currently queued or being scanned
        # dirty   = paths that changed again while pending
        self._pending = set()
        self._dirty = set()
        self._state_lock = threading.Lock()
        self._pending_limit = self.queue_max_size + 1

        # Queue counters are protected by _state_lock.
        self._queue_enqueued_total = 0
        self._queue_deduplicated_total = 0
        self._queue_dropped_total = 0
        self._queue_requeued_total = 0
        self._queue_scanned_total = 0
        self._queue_scan_errors_total = 0
        self._last_queue_warning = float("-inf")
        self._worker_thread = None

        # Instead of a simple set, we use a dictionary to store the Watch Object.
        # This allows us to specifically unschedule a watch when a drive is removed.
        # Format: { '/media/usb': <ObservedWatch Object> }
        self.watched_watches = {}

        # Default ignore list (safe + universal)
        default_ignores = (
            "/proc", "/sys", "/dev", "/run",
            "/var/log", "/var/lib/clamav",
            "/opt/herodium/quarantine",
            "/snap", "/root/.maltrail"
        )

        cfg_ignores = dirs_cfg.get("ignore_prefixes", [])
        if isinstance(cfg_ignores, list) and cfg_ignores:
            # Ensure strings + tuple for startswith(tuple)
            self.IGNORED_PREFIXES = tuple(str(x) for x in cfg_ignores)
        else:
            self.IGNORED_PREFIXES = default_ignores

        self.ignore_user_cache = self._safe_bool(
            dirs_cfg.get("ignore_user_cache", False), False
        )

        configured_watch_paths = dirs_cfg.get("watch_paths", [])
        if not isinstance(configured_watch_paths, list) or not configured_watch_paths:
            configured_watch_paths = ["/home", "/etc", "/tmp", "/var/www"]
        self.recovery = ScanRecoveryController(
            dirs_cfg,
            logger,
            queue_capacity=self.queue_max_size,
            scan_file=self._scan_path,
            should_ignore=self._recovery_path_ignored,
            queue_size=self.scan_queue.qsize,
            is_running=lambda: self.running,
            watch_roots=configured_watch_paths,
        )

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

    def _queue_stats_locked(self):
        return {
            "capacity": self.queue_max_size,
            "queued": self.scan_queue.qsize(),
            "pending": len(self._pending),
            "dirty": len(self._dirty),
            "enqueued_total": self._queue_enqueued_total,
            "deduplicated_total": self._queue_deduplicated_total,
            "dropped_total": self._queue_dropped_total,
            "requeued_total": self._queue_requeued_total,
            "scanned_total": self._queue_scanned_total,
            "scan_errors_total": self._queue_scan_errors_total,
        }

    def get_queue_stats(self):
        """Return a thread-safe snapshot of bounded queue state and counters."""
        with self._state_lock:
            stats = dict(self._queue_stats_locked())
            stats["events_dropped"] = self._queue_dropped_total
        stats.update(self.recovery.stats())
        return stats

    def _record_drop_locked(self, reason, path):
        self._queue_dropped_total += 1
        now = time.monotonic()
        if now - self._last_queue_warning < self.queue_warning_interval_seconds:
            return False

        self._last_queue_warning = now
        return True

    def _log_drop_outcome(
        self,
        reason,
        path,
        emit_warning,
        recovery_root_hint=None,
    ):
        recovery_root = self.recovery.schedule(path, recovery_root_hint)
        if recovery_root:
            self.logger.info(
                f"Scan recovery scheduled for root: {recovery_root}"
            )
        if not emit_warning:
            return

        stats = self.get_queue_stats()
        self.logger.warning(
            "Scan queue pressure: dropped event "
            f"reason={reason}, path={path!r}, "
            f"queued={stats['queued']}/{stats['capacity']}, "
            f"pending={stats['pending']}, dirty={stats['dirty']}, "
            f"dropped_total={stats['dropped_total']}, "
            f"recovery_roots_pending={stats['recovery_roots_pending']}, "
            f"recovery_roots_rejected={stats['recovery_roots_rejected']}"
        )

    def _enqueue_once(self, path: str, recovery_root_hint=None):
        """Deduplicate and enqueue without blocking or unbounded state."""
        if not isinstance(path, str) or not path or not self.running:
            return False

        drop_reason = None
        emit_warning = False
        enqueued = False
        with self._state_lock:
            if not self.running:
                return False

            if path in self._pending:
                self._dirty.add(path)
                self._queue_deduplicated_total += 1
                return False

            if len(self._pending) >= self._pending_limit:
                drop_reason = "pending_limit"
                emit_warning = self._record_drop_locked(drop_reason, path)
            else:
                self._pending.add(path)
                self._dirty.discard(path)
                try:
                    self.scan_queue.put_nowait(path)
                except queue.Full:
                    # Roll back state so a later event can retry.
                    self._pending.discard(path)
                    self._dirty.discard(path)
                    drop_reason = "queue_full"
                    emit_warning = self._record_drop_locked(drop_reason, path)
                else:
                    self._queue_enqueued_total += 1
                    enqueued = True

        if drop_reason:
            self._log_drop_outcome(
                drop_reason,
                path,
                emit_warning,
                recovery_root_hint,
            )
        return enqueued

    def _finish_path(self, path):
        """Complete one scan and requeue one dirty rescan without blocking."""
        drop_reason = None
        emit_warning = False
        with self._state_lock:
            self._queue_scanned_total += 1
            if self.running and path in self._dirty:
                self._dirty.discard(path)
                try:
                    self.scan_queue.put_nowait(path)
                except queue.Full:
                    self._pending.discard(path)
                    self._dirty.discard(path)
                    drop_reason = "dirty_requeue_full"
                    emit_warning = self._record_drop_locked(drop_reason, path)
                else:
                    self._queue_requeued_total += 1
            else:
                self._dirty.discard(path)
                self._pending.discard(path)

        if drop_reason:
            self._log_drop_outcome(
                drop_reason,
                path,
                emit_warning,
            )

    def _recovery_path_ignored(self, path):
        handler = getattr(self, "event_handler", None)
        if handler is not None:
            return handler._should_ignore(path)
        fallback = Handler(
            self._enqueue_once,
            self.logger,
            self.IGNORED_PREFIXES,
            self.ignore_user_cache,
            self.clamav_temp_directory,
        )
        return fallback._should_ignore(path)

    def _events_dropped(self):
        with self._state_lock:
            return self._queue_dropped_total

    def _scan_path(self, path):
        try:
            self.scanner.scan_file(path)
        except Exception as e:
            with self._state_lock:
                self._queue_scan_errors_total += 1
            self.logger.error(f"Scanner worker failed for {path}: {e}")

    def run(self):
        # Start the Worker thread (Single Scanner)
        if self._worker_thread is None or not self._worker_thread.is_alive():
            self._worker_thread = threading.Thread(
                target=self._worker_loop, daemon=True
            )
            self._worker_thread.start()

        self.event_handler = Handler(
            self._enqueue_once,
            self.logger,
            self.IGNORED_PREFIXES,
            self.ignore_user_cache,
            self.clamav_temp_directory,
        )

        try:
            self.observer.start()
            recovery_state = "enabled" if self.recovery.enabled else "disabled"
            self.logger.info(
                "File System Monitor started "
                f"(Queue Mode, capacity={self.queue_max_size}, "
                f"recovery={recovery_state}, "
                f"low_watermark={self.recovery.low_watermark})."
            )

            # Load critical paths (including HOME)
            threading.Thread(target=self._load_critical_paths, daemon=True).start()
            # Start USB Hunter
            threading.Thread(target=self._usb_hunter_loop, daemon=True).start()

        except Exception as e:
            self.logger.error(f"Observer failed: {e}")
            self.running = False
            return False

        return bool(
            self.observer.is_alive()
            and self._worker_thread is not None
            and self._worker_thread.is_alive()
        )

    def _worker_loop(self):
        """Consumes files from the queue and scans them one by one (dedup-safe)."""
        self.logger.info("Scanner Worker Started")
        while self.running:
            try:
                path = self.scan_queue.get(timeout=1)
            except queue.Empty:
                self.recovery.run_once(events_dropped=self._events_dropped())
                continue

            try:
                self._scan_path(path)
            finally:
                self._finish_path(path)
                self.scan_queue.task_done()
                self.recovery.run_once(events_dropped=self._events_dropped())

    def _load_critical_paths(self):
        # Prefer config-defined watch paths (from herodium.yaml)
        cfg_paths = self.config.get('directories', {}).get('watch_paths', [])
        if cfg_paths and isinstance(cfg_paths, list):
            critical_paths = cfg_paths
        else:
            # Safe fallback
            critical_paths = ["/home", "/etc", "/tmp", "/var/www"]

        self.logger.info(f"Attaching monitors to: {critical_paths}")
        for folder in critical_paths:
            if not self.running:
                break
            if os.path.exists(folder):
                try:
                    self.observer.schedule(self.event_handler, folder, recursive=True)
                    self.logger.info(f" -> Protected: {folder}")
                    time.sleep(0.1)
                except OSError as e:
                    if e.errno == 28:
                        self.logger.critical(
                            "Inotify limit reached! Run: "
                            "'echo fs.inotify.max_user_watches=524288 | sudo tee -a /etc/sysctl.conf && sudo sysctl -p'"
                        )
                        break

    def _usb_hunter_loop(self):
        """
        Smart loop for managing USB lifecycle.
        Detects connections and disconnections, updating the Observer accordingly.
        """
        self.logger.info("USB Hunter Active (Hot-Plug detection enabled)")

        while self.running:
            try:
                # 1. Get current state of mounted drives (Ground Truth)
                current_mounts = set()
                try:
                    # all=False filters out virtual filesystems, keeping physical ones
                    for p in psutil.disk_partitions(all=False):
                        if p.mountpoint.startswith(("/media", "/mnt")):
                            current_mounts.add(p.mountpoint)
                except (OSError, RuntimeError) as e:
                    self.logger.warning(f"Unable to enumerate removable drives: {e}")

                # 2. Detect changes (Diffing)
                active_watches = set(self.watched_watches.keys())

                # Drives removed (Watched but not in psutil)
                to_remove = active_watches - current_mounts

                # Drives added (In psutil but not watched)
                to_add = current_mounts - active_watches

                # 3. Handle removals (Crucial for allowing re-connection!)
                for path in to_remove:
                    self.logger.info(f"Drive Removed: {path}. Cleaning up watch.")
                    watch_obj = self.watched_watches[path]
                    try:
                        self.observer.unschedule(watch_obj)
                    except (KeyError, OSError, RuntimeError) as e:
                        # The drive can disappear before Watchdog removes the watch.
                        self.logger.debug(
                            f"Drive watch already unavailable for {path}: {e}"
                        )
                    del self.watched_watches[path]
                    self.recovery.remove_watch_root(path, "drive_removed")

                # 4. Handle new connections
                for path in to_add:
                    self.logger.info(f"New Drive Detected: {path}. Attaching Scanner.")
                    try:
                        # Register new watch, creating a new Handle with the OS
                        watch_obj = self.observer.schedule(self.event_handler, path, recursive=True)
                        self.watched_watches[path] = watch_obj
                        self.recovery.add_watch_root(path, removable=True)

                        # Initial scan of existing files on the drive
                        threading.Thread(target=self._queue_existing_files, args=(path,), daemon=True).start()
                    except Exception as e:
                        self.logger.error(f"Failed to watch USB {path}: {e}")

            except Exception as e:
                self.logger.error(f"USB Hunter Error: {e}")

            time.sleep(2)  # Check every 2 seconds

    def _queue_existing_files(self, path):
        for root, dirs, files in os.walk(path):
            if not self.running:
                break
            for f in files:
                enqueued = self._enqueue_once(
                    os.path.join(root, f),
                    recovery_root_hint=path,
                )
                if not enqueued:
                    stats = self.get_queue_stats()
                    queue_saturated = (
                        stats["queued"] >= stats["capacity"]
                        or stats["pending"] >= self._pending_limit
                    )
                    if self.recovery.is_pending(path):
                        self.logger.info(
                            f"Initial scan deferred to bounded recovery: {path}"
                        )
                        return
                    if queue_saturated:
                        self.logger.warning(
                            "Initial scan stopped at bounded queue pressure: "
                            f"root={path}, recovery_root_available=false"
                        )
                        return

    def _drain_queue(self):
        while True:
            try:
                self.scan_queue.get_nowait()
            except queue.Empty:
                break
            else:
                self.scan_queue.task_done()

    def stop(self):
        self.running = False
        if self.observer.is_alive():
            self.observer.stop()
            self.observer.join()

        if self._worker_thread is not None:
            self._worker_thread.join(timeout=2)

        if self._worker_thread is None or not self._worker_thread.is_alive():
            self._drain_queue()
            with self._state_lock:
                self._pending.clear()
                self._dirty.clear()
            self.recovery.stop()
        else:
            self.logger.warning("Scanner worker did not stop within 2 seconds.")
