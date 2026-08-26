import os
import stat

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

        self.whitelist_identities = {}

        for item in raw_whitelist:
            value = str(item).strip()
            if not value:
                continue
            self._register_whitelist_path(value)

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

    def _trusted_executable_identity(self, path):
        """Return a stable identity for a trusted root-owned executable."""
        try:
            metadata = os.stat(path, follow_symlinks=False)
        except OSError:
            return None

        if not stat.S_ISREG(metadata.st_mode):
            return None
        if metadata.st_uid != 0:
            return None
        if metadata.st_mode & 0o022:
            return None
        if not metadata.st_mode & 0o111:
            return None

        return (metadata.st_dev, metadata.st_ino)

    def _register_whitelist_path(self, value):
        """Register one absolute executable path using canonical file identity."""
        if not os.path.isabs(value):
            self.logger.warning(
                "Ignoring unsafe Memory Hunter whitelist entry %r: "
                "absolute executable path required",
                value,
            )
            return

        real_path = os.path.realpath(value)
        identity = self._trusted_executable_identity(real_path)
        if identity is None:
            if os.path.exists(real_path):
                self.logger.warning(
                    "Ignoring untrusted Memory Hunter whitelist path: %s",
                    real_path,
                )
            else:
                self.logger.debug(
                    "Memory Hunter whitelist path is unavailable: %s",
                    real_path,
                )
            return

        self.whitelist_identities[real_path] = identity

    def _is_whitelisted_process(self, pid, exe_path):
        """Whitelist only the exact trusted executable object for this process."""
        try:
            if not exe_path or not os.path.isabs(exe_path):
                return False

            real_exe = os.path.realpath(exe_path)
            expected_identity = self.whitelist_identities.get(real_exe)
            if expected_identity is None:
                return False

            current_identity = self._trusted_executable_identity(real_exe)
            if current_identity != expected_identity:
                return False

            process_metadata = os.stat(f"/proc/{pid}/exe")
            process_identity = (
                process_metadata.st_dev,
                process_metadata.st_ino,
            )
            return process_identity == expected_identity
        except (OSError, TypeError, ValueError):
            return False

    def _resolve_command_file_argument(self, arg, cwd):
        """Resolve a command-line file argument without guessing process context."""
        if not isinstance(arg, str) or not arg or "\x00" in arg:
            return None
        if arg.startswith("-"):
            return None

        try:
            if os.path.isabs(arg):
                candidate = arg
            else:
                if not cwd or not os.path.isabs(cwd):
                    return None
                candidate = os.path.join(cwd, arg)

            real_candidate = os.path.realpath(candidate)
            if os.path.isfile(real_candidate):
                return real_candidate
        except (OSError, TypeError, ValueError):
            return None

        return None

    def flash_scan(self):
        """Smart memory scan: checks EXE binary and command-line file arguments."""
        scanned_count = 0
        retry_pending_count = 0
        current_pids = set()
        iteration_completed = True

        try:
            attrs = ['pid', 'name', 'exe', 'cmdline', 'create_time', 'cwd']
            for proc in psutil.process_iter(attrs):
                try:
                    pinfo = proc.info
                    pid = pinfo['pid']
                    exe_path = pinfo['exe']
                    cmdline = pinfo['cmdline']
                    cwd = pinfo['cwd']
                    start_time = pinfo['create_time']
                    name = pinfo['name']

                    current_pids.add(pid)

                    # 1. Initial filtering (whitelist)
                    if self._is_whitelisted_process(pid, exe_path):
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
                            command_file = self._resolve_command_file_argument(
                                arg,
                                cwd,
                            )
                            if command_file is not None:
                                files_to_scan.add(command_file)

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
        # Keep the long-running monitor alive if an unexpected psutil/runtime
        # error escapes the per-process isolation boundary.
        except Exception as e:  # noqa: BLE001
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
            return action_policy != 'alert'
        # This authorization gate must fail closed for malformed scanner state.
        except Exception:  # noqa: BLE001
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
        # Process termination is best-effort; unexpected platform errors must
        # not terminate the Memory Hunter worker.
        except Exception as e:  # noqa: BLE001
            self.logger.error(f"Unexpected process termination error: {e}")

    def _cleanup_cache(self, current_pids_set):
        expired_pids = [
            pid for pid in self.scanned_cache if pid not in current_pids_set
        ]
        for pid in expired_pids:
            del self.scanned_cache[pid]
