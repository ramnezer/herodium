import psutil
import logging
import time
import os
from modules.av_scanner import ClamAVScanner


class MemoryHunter:
    def __init__(self, config, logger):
        self.logger = logger
        self.scanner = ClamAVScanner(config, logger)

        cfg = (config.get('memory_scan', {}) or {})
        raw_whitelist = cfg.get('whitelist', []) or []

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
        current_pids = set()

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
                    for file_path in files_to_scan:
                        if self.scanner.scan_file(file_path):
                            self._kill_process(proc, file_path)
                            infected = True
                            break

                    if not infected:
                        self.scanned_cache[pid] = start_time
                        scanned_count += 1

                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
        except Exception as e:
            self.logger.error(f"Memory Scan Loop Error: {e}")

        self._cleanup_cache(current_pids)

        if scanned_count > 0:
            self.logger.info(f"Memory Scan: checked {scanned_count} processes")

    def _kill_process(self, proc, reason_file):
        try:
            pid = proc.info['pid']
            name = proc.info['name']
            self.logger.critical(f"KILLING INFECTED PROCESS: {name} (PID: {pid})")
            self.logger.critical(f"   -> Reason: Loaded infected file {reason_file}")

            proc.terminate()
            try:
                proc.wait(timeout=2)
            except psutil.TimeoutExpired:
                proc.kill()
        except Exception:
            pass

    def _cleanup_cache(self, current_pids_set):
        try:
            expired_pids = [pid for pid in self.scanned_cache if pid not in current_pids_set]
            for pid in expired_pids:
                del self.scanned_cache[pid]
        except Exception:
            pass
