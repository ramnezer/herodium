import os

import psutil

from modules.av_scanner import ClamAVScanner, ScanStatus


class MemoryHunter:
    def __init__(self, config, logger):
        self.logger = logger
        self.scanner = ClamAVScanner(config, logger)

        cfg = (config.get('memory_scan', {}) or {})
        raw_whitelist = cfg.get('whitelist', []) or []
        self.kill_infected_process = self._safe_bool(
            cfg.get('kill_infected_process'),
            True
        )

        self.whitelist_names = set()
        self.whitelist_paths = set()

        for item in raw_whitelist:
            value = str(item).strip()
            if not value:
                continue

            if value.startswith('/'):
                self.whitelist_paths.add(os.path.realpath(value))
            else:
                self.whitelist_names.add(value)

        # Default safe whitelist entries
        self.whitelist_names.update({
            "chrome",
            "firefox",
            "code",
            "gnome-shell",
            "clamd",
            "systemd",
            "init",
            "systemd-journald",
        })

        self.whitelist_paths.update({
            os.path.realpath("/usr/bin/gnome-shell"),
            os.path.realpath("/usr/bin/Xorg"),
        })

        self.scanned_cache = {}

    def _safe_bool(self, value, default):
        """Return a safe boolean value from YAML/user configuration."""
        if isinstance(value, bool):
            return value
        if value is None:
            return default
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in ('1', 'true', 'yes', 'on'):
                return True
            if normalized in ('0', 'false', 'no', 'off'):
                return False
        return default

    def _is_whitelisted_process(self, name, exe_path):
        """
        Exact-match whitelist logic only.
        Avoid substring matching to prevent false negatives.
        """
        try:
            if name and name in self.whitelist_names:
                return True

            if exe_path:
                real_exe = os.path.realpath(exe_path)

                if real_exe in self.whitelist_paths:
                    return True

                if os.path.basename(real_exe) in self.whitelist_names:
                    return True

            return False
        except Exception:
            return False

    def flash_scan(self):
        """Smart memory scan: checks EXE binary and command-line file arguments."""
        scanned_count = 0
        retry_pending_count = 0
        current_pids = set()
        iteration_completed = True

        try:
            attrs = ['pid', 'name', 'exe', 'cmdline', 'create_time']
            for proc in psutil.process_iter(attrs):
                try:
                    pinfo = proc.info
                    pid = pinfo['pid']
                    exe_path = pinfo['exe']
                    cmdline = pinfo['cmdline']
                    start_time = pinfo['create_time']
                    name = pinfo['name']

                    current_pids.add(pid)

                    # 1. Initial filtering (whitelist)
                    if self._is_whitelisted_process(name, exe_path):
                        continue

                    # 2. Cache check
                    if pid in self.scanned_cache and self.scanned_cache[pid] == start_time:
                        continue

                    # 3. Collect related files for scanning
                    files_to_scan = set()

                    if exe_path and os.path.exists(exe_path):
                        files_to_scan.add(exe_path)

                    if cmdline:
                        for arg in cmdline[1:]:
                            if arg.startswith('/') and os.path.isfile(arg):
                                files_to_scan.add(arg)

                    # 4. Perform scan
                    infected = False
                    process_removed = False
                    retry_required = False
                    scanner_unavailable = False

                    for file_path in sorted(files_to_scan):
                        scan_result = self.scanner.scan_file(file_path)

                        if scan_result.retryable:
                            retry_required = True
                            scanner_unavailable = (
                                scan_result.status is ScanStatus.UNAVAILABLE
                            )
                            break

                        if scan_result.status is ScanStatus.INFECTED:
                            infected = True
                            if self._should_kill_infected_process():
                                self._kill_process(
                                    proc,
                                    file_path,
                                    pid=pid,
                                    name=name,
                                )
                                process_removed = True
                            else:
                                self.logger.warning(
                                    f"Infected process detected but left running by policy: "
                                    f"{name} (PID: {pid})"
                                )
                            break

                    if retry_required:
                        self.scanned_cache.pop(pid, None)
                        retry_pending_count += 1

                        if scanner_unavailable:
                            iteration_completed = False
                            break

                        continue

                    if not infected or not process_removed:
                        self.scanned_cache[pid] = start_time
                        scanned_count += 1

                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
        except Exception as e:
            iteration_completed = False
            self.logger.error(f"Memory Scan Loop Error: {e}")

        if iteration_completed:
            self._cleanup_cache(current_pids)

        if scanned_count > 0:
            self.logger.info(f"Memory Scan: checked {scanned_count} processes")

        if retry_pending_count > 0:
            self.logger.warning(
                f"Memory Scan: {retry_pending_count} process(es) pending retry"
            )

    def _should_kill_infected_process(self):
        """
        Decide whether Memory Hunter is allowed to terminate a process.
        Alert-only ClamAV policy must never kill processes.
        """
        try:
            if not self.kill_infected_process:
                return False

            action_policy = str(getattr(self.scanner, 'action_policy', '') or '').lower()
            if action_policy == 'alert':
                return False

            return True
        except Exception:
            return False

    def _kill_process(self, proc, reason_file, *, pid, name):
        """Terminate a process using identity captured before the AV scan.

        psutil caches Process objects globally and concurrent process_iter()
        calls can replace ``proc.info`` with a different attribute set. The AV
        scan can take long enough for that to happen, so the immutable PID and
        name captured by flash_scan() must be used here instead of consulting
        proc.info again.
        """
        try:
            display_name = name or "<unknown>"
            self.logger.critical(
                f"KILLING INFECTED PROCESS: {display_name} (PID: {pid})"
            )
            self.logger.critical(f"   -> Reason: Loaded infected file {reason_file}")

            proc.terminate()
            try:
                proc.wait(timeout=2)
            except psutil.TimeoutExpired:
                proc.kill()
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            self.logger.warning(f"Unable to terminate infected process: {e}")
        except Exception as e:
            self.logger.error(f"Unexpected process termination error: {e}")

    def _cleanup_cache(self, current_pids_set):
        expired_pids = [
            pid for pid in self.scanned_cache if pid not in current_pids_set
        ]
        for pid in expired_pids:
            del self.scanned_cache[pid]
