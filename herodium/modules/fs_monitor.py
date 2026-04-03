import sys, time, logging, os, threading, psutil, queue
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from modules.av_scanner import ClamAVScanner

class Handler(FileSystemEventHandler):
    def __init__(self, enqueue_func, logger, ignored_prefixes, ignore_user_cache=False):
        self.enqueue = enqueue_func
        self.logger = logger
        self.ignored_prefixes = ignored_prefixes
        self.ignore_user_cache = ignore_user_cache

    def _should_ignore(self, path: str) -> bool:
        # Defensive checks
        if not path or not isinstance(path, str):
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
        self.scan_queue = queue.Queue()

        # Queue dedup state:
        # pending = paths that are currently queued or being scanned
        # dirty   = paths that changed again while pending
        self._pending = set()
        self._dirty = set()
        self._state_lock = threading.Lock()

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

        dirs_cfg = (config.get("directories", {}) or {})

        cfg_ignores = dirs_cfg.get("ignore_prefixes", [])
        if isinstance(cfg_ignores, list) and cfg_ignores:
            # Ensure strings + tuple for startswith(tuple)
            self.IGNORED_PREFIXES = tuple(str(x) for x in cfg_ignores)
        else:
            self.IGNORED_PREFIXES = default_ignores

        self.ignore_user_cache = bool(dirs_cfg.get("ignore_user_cache", False))

    def _enqueue_once(self, path: str):
        """
        Dedup + dirty-flag:
        - If path is already pending, mark dirty and do NOT enqueue again.
        - If not pending, enqueue and mark it as pending.
        """
        with self._state_lock:
            if path in self._pending:
                self._dirty.add(path)
                return
            self._pending.add(path)
            self._dirty.discard(path)

        self.scan_queue.put(path)

    def run(self):
        # Start the Worker thread (Single Scanner)
        threading.Thread(target=self._worker_loop, daemon=True).start()

        self.event_handler = Handler(
            self._enqueue_once,
            self.logger,
            self.IGNORED_PREFIXES,
            self.ignore_user_cache
        )

        try:
            self.observer.start()
            self.logger.info("File System Monitor started (Queue Mode).")

            # Load critical paths (including HOME)
            threading.Thread(target=self._load_critical_paths, daemon=True).start()
            # Start USB Hunter
            threading.Thread(target=self._usb_hunter_loop, daemon=True).start()

        except Exception as e:
            self.logger.error(f"Observer failed: {e}")

    def _worker_loop(self):
        """Consumes files from the queue and scans them one by one (dedup-safe)."""
        self.logger.info("Scanner Worker Started")
        while self.running:
            try:
                path = self.scan_queue.get(timeout=1)

                requeue = False
                try:
                    self.scanner.scan_file(path)
                finally:
                    # If file changed again while pending, rescan once more.
                    with self._state_lock:
                        if self.running and path in self._dirty:
                            self._dirty.discard(path)
                            requeue = True
                        else:
                            self._dirty.discard(path)
                            self._pending.discard(path)

                    if requeue:
                        # Keep path in pending set and re-enqueue once
                        self.scan_queue.put(path)

                    self.scan_queue.task_done()

            except queue.Empty:
                continue

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
                except:
                    pass

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
                    except Exception:
                        # Error here is normal as the drive no longer exists
                        pass
                    del self.watched_watches[path]

                # 4. Handle new connections
                for path in to_add:
                    self.logger.info(f"New Drive Detected: {path}. Attaching Scanner.")
                    try:
                        # Register new watch, creating a new Handle with the OS
                        watch_obj = self.observer.schedule(self.event_handler, path, recursive=True)
                        self.watched_watches[path] = watch_obj

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
                self._enqueue_once(os.path.join(root, f))

    def stop(self):
        self.running = False
        if self.observer.is_alive():
            self.observer.stop()
            self.observer.join()

