import time
import threading
import subprocess
import psutil


class PerformanceManager:
    def __init__(self, config, logger, scanner):
        self.config = config or {}
        self.logger = logger
        self.stop_event = threading.Event()
        self.current_limit_value = None
        self.target_service = "clamav-daemon.service"
        self.daemon_name = "clamd"  # The actual process name

        self.cpu_count = psutil.cpu_count(logical=True) or 1

        # Cap as % of whole machine (0-100). Default: 30 to match your requirement.
        perf_cfg = (self.config.get("performance") or {})
        self.cap_machine_percent = int(perf_cfg.get("cpu_limit_percent", 30) or 30)

        # Original process priority state (captured once per clamd PID)
        self.priority_pid = None
        self.original_nice = None
        self.original_ionice = None

        self.logger.info(f"Performance Controller Active. Cores: {self.cpu_count}")

    def start(self):
        # Best-effort cleanup: remove any stale quota from previous runs/manual changes
        self._force_release_quota()
        self._clear_priority_state()
        threading.Thread(target=self._loop, daemon=True).start()

    def _force_release_quota(self):
        """Always try to clear CPUQuota even if we didn't set it in this run."""
        try:
            subprocess.run(
                ['systemctl', 'set-property', '--runtime', self.target_service, 'CPUQuota='],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False
            )
        except Exception:
            pass

        self.current_limit_value = None

    def stop(self):
        self.stop_event.set()
        self._remove_limit()

    def _clear_priority_state(self):
        """Forget saved baseline priority state."""
        self.priority_pid = None
        self.original_nice = None
        self.original_ionice = None

    def _scan_in_progress(self) -> bool:
        """Detect manual/scheduled scans by presence of clamdscan/clamscan."""
        try:
            for p in psutil.process_iter(['name']):
                n = (p.info.get('name') or '')
                if n in ('clamdscan', 'clamscan'):
                    return True
        except Exception:
            pass
        return False

    def _loop(self):
        # LIVE mode hysteresis + cooldown to prevent quota flapping
        APPLY_THRESHOLD = 60    # % of total machine (0-100)
        RELEASE_THRESHOLD = 40  # % of total machine (0-100)
        MIN_HOLD_SECONDS = 30   # minimum time between state changes

        last_change = 0.0

        while not self.stop_event.is_set():
            try:
                clamd_proc = self._get_clamd_process()
                if not clamd_proc:
                    time.sleep(3)
                    continue

                # Process cpu_percent can be >100 on multi-core.
                # Divide by cpu_count to get 0-100 "machine percent".
                try:
                    cpu_usage = clamd_proc.cpu_percent(interval=1.5) / self.cpu_count
                except Exception:
                    cpu_usage = 0

                thermal_limit = self._get_thermal_limit()

                now = time.time()
                can_change = (now - last_change) >= MIN_HOLD_SECONDS

                # 1) Thermal override (keeps your existing behavior)
                if thermal_limit < 100:
                    target_quota = 20  # machine percent
                    systemd_quota = int(target_quota * self.cpu_count)
                    if can_change and systemd_quota != self.current_limit_value:
                        self._apply_limit(systemd_quota, clamd_proc.pid)
                        last_change = now

                else:
                    # 2) Manual/Scheduled scan: HOLD fixed cap during the scan (no flapping)
                    if self._scan_in_progress():
                        systemd_quota = int(self.cap_machine_percent * self.cpu_count)
                        if systemd_quota != self.current_limit_value:
                            self._apply_limit(systemd_quota, clamd_proc.pid)
                        # Do NOT release while scan is running

                    # 3) LIVE behavior (your current logic) but cap is configurable (default 30)
                    else:
                        if self.current_limit_value is None:
                            if can_change and cpu_usage >= APPLY_THRESHOLD:
                                systemd_quota = int(self.cap_machine_percent * self.cpu_count)
                                self._apply_limit(systemd_quota, clamd_proc.pid)
                                last_change = now
                        else:
                            if can_change and cpu_usage <= RELEASE_THRESHOLD:
                                self._remove_limit()
                                last_change = now

            except Exception as e:
                self.logger.error(f"Performance Manager Error: {e}")

            time.sleep(3)

    def _get_clamd_process(self):
        """Find the real clamd daemon process only."""
        for proc in psutil.process_iter(['pid', 'name']):
            name = (proc.info.get('name') or '').strip()
            if name == self.daemon_name:
                return proc
        return None

    def _get_thermal_limit(self):
        """Return throttling factor (100 = no limit, lower = percentage)."""
        try:
            temps = psutil.sensors_temperatures()
            if not temps:
                return 100

            max_temp = 0
            for entry in temps.values():
                for sensor in entry:
                    if sensor.current > max_temp:
                        max_temp = sensor.current

            if max_temp > 90:
                return 10  # Critical
            if max_temp > 80:
                return 50  # Hot
            return 100
        except Exception:
            return 100

    def _capture_original_priority(self, proc):
        """Capture baseline nice/ionice once per PID before throttling."""
        if self.priority_pid == proc.pid:
            return

        try:
            self.original_nice = proc.nice()
        except Exception:
            self.original_nice = None

        try:
            io = proc.ionice()

            if hasattr(io, 'ioclass'):
                self.original_ionice = (io.ioclass, getattr(io, 'value', 0))
            elif isinstance(io, (tuple, list)) and len(io) >= 1:
                io_value = io[1] if len(io) > 1 else 0
                self.original_ionice = (io[0], io_value)
            else:
                self.original_ionice = None
        except Exception:
            self.original_ionice = None

        self.priority_pid = proc.pid

    def _restore_original_priority(self):
        """Restore original nice/ionice for the same PID if it still exists."""
        if self.priority_pid is None:
            return

        try:
            proc = psutil.Process(self.priority_pid)
        except Exception:
            self._clear_priority_state()
            return

        try:
            if self.original_nice is not None:
                proc.nice(self.original_nice)
        except Exception:
            pass

        try:
            if self.original_ionice is not None:
                io_class, io_value = self.original_ionice
                proc.ionice(ioclass=io_class, value=io_value)
        except Exception:
            pass

        self._clear_priority_state()

    def _apply_limit(self, limit, pid):
        try:
            proc = psutil.Process(pid)

            # Save original process priority only once for this PID
            self._capture_original_priority(proc)

            subprocess.run(
                ['systemctl', 'set-property', '--runtime', self.target_service, f'CPUQuota={limit}%'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False
            )

            try:
                proc.nice(19)
            except Exception:
                subprocess.run(
                    ['renice', '-n', '19', '-p', str(pid)],
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )

            try:
                proc.ionice(ioclass=psutil.IOPRIO_CLASS_IDLE)
            except Exception:
                subprocess.run(
                    ['ionice', '-c', '3', '-p', str(pid)],
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )

            self.current_limit_value = limit
            self.logger.info(f"Throttling ClamAV to {limit}% CPUQuota")
        except Exception:
            pass

    def _remove_limit(self):
        """Release CPUQuota and restore original process priority if possible."""
        had_limit = self.current_limit_value is not None

        if had_limit:
            try:
                subprocess.run(
                    ['systemctl', 'set-property', '--runtime', self.target_service, 'CPUQuota='],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False
                )
            except Exception:
                pass

        self.current_limit_value = None
        self._restore_original_priority()

        if had_limit:
            self.logger.info("ClamAV Throttling Released")
