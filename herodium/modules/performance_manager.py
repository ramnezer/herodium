from __future__ import annotations

import threading
import time

import psutil

from core.system_command import SystemCommandError, run_system_tool


class PerformanceManager:
    def __init__(self, config, logger, scanner):
        self.config = config or {}
        self.logger = logger
        self.stop_event = threading.Event()
        self._thread = None
        self.current_limit_value = None
        self.target_service = "clamav-daemon.service"
        self.daemon_name = "clamd"
        self.cpu_count = psutil.cpu_count(logical=True) or 1

        perf_config = self.config.get("performance", {}) or {}
        self.cap_machine_percent = self._bounded_int(
            perf_config.get("cpu_limit_percent"),
            default=30,
            minimum=1,
            maximum=100,
        )

        self.priority_pid = None
        self.original_nice = None
        self.original_ionice = None

        self.logger.info(
            f"Performance Controller Active. Cores: {self.cpu_count}"
        )

    @staticmethod
    def _bounded_int(value, *, default, minimum, maximum):
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            return default
        return max(minimum, min(maximum, parsed))

    def start(self):
        if self._thread is not None and self._thread.is_alive():
            return True

        cleanup_ok = self._force_release_quota()
        self._clear_priority_state()
        self.stop_event.clear()
        self._thread = threading.Thread(
            target=self._loop,
            daemon=True,
            name="herodium-performance-manager",
        )
        self._thread.start()
        return cleanup_ok and self._thread.is_alive()

    def _force_release_quota(self):
        """Clear a stale runtime CPUQuota before starting the controller."""
        try:
            result = run_system_tool(
                "systemctl",
                (
                    "set-property",
                    "--runtime",
                    self.target_service,
                    "CPUQuota=",
                ),
                quiet=True,
                timeout=30,
            )
        except SystemCommandError as exc:
            self.logger.warning(f"Unable to clear stale ClamAV CPUQuota: {exc}")
            return False

        if result.returncode != 0:
            self.logger.warning("Unable to clear stale ClamAV CPUQuota.")
            return False

        self.current_limit_value = None
        return True

    def stop(self):
        self.stop_event.set()
        released = self._remove_limit()
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=5)
        return released

    def _clear_priority_state(self):
        self.priority_pid = None
        self.original_nice = None
        self.original_ionice = None

    def _scan_in_progress(self) -> bool:
        """Detect manual or scheduled ClamAV scans."""
        try:
            for process in psutil.process_iter(["name"]):
                name = process.info.get("name") or ""
                if name in ("clamdscan", "clamscan"):
                    return True
        except psutil.Error as exc:
            self.logger.debug(f"Unable to inspect ClamAV scan processes: {exc}")
        return False

    def _loop(self):
        apply_threshold = 60
        release_threshold = 40
        minimum_hold_seconds = 30
        last_change = 0.0

        while not self.stop_event.is_set():
            try:
                clamd_process = self._get_clamd_process()
                if clamd_process is None:
                    self.stop_event.wait(3)
                    continue

                try:
                    cpu_usage = (
                        clamd_process.cpu_percent(interval=1.5) / self.cpu_count
                    )
                except psutil.Error as exc:
                    self.logger.debug(f"Unable to read clamd CPU usage: {exc}")
                    cpu_usage = 0.0

                thermal_limit = self._get_thermal_limit()
                now = time.monotonic()
                can_change = (now - last_change) >= minimum_hold_seconds

                if thermal_limit < 100:
                    target_quota = 20
                    systemd_quota = int(target_quota * self.cpu_count)
                    if can_change and systemd_quota != self.current_limit_value:
                        if self._apply_limit(systemd_quota, clamd_process.pid):
                            last_change = now
                elif self._scan_in_progress():
                    systemd_quota = int(
                        self.cap_machine_percent * self.cpu_count
                    )
                    if systemd_quota != self.current_limit_value:
                        self._apply_limit(systemd_quota, clamd_process.pid)
                elif self.current_limit_value is None:
                    if can_change and cpu_usage >= apply_threshold:
                        systemd_quota = int(
                            self.cap_machine_percent * self.cpu_count
                        )
                        if self._apply_limit(systemd_quota, clamd_process.pid):
                            last_change = now
                elif can_change and cpu_usage <= release_threshold:
                    if self._remove_limit():
                        last_change = now
            except psutil.Error as exc:
                self.logger.error(f"Performance Manager psutil error: {exc}")
            except (OSError, ValueError, TypeError) as exc:
                self.logger.error(f"Performance Manager error: {exc}")

            self.stop_event.wait(3)

    def _get_clamd_process(self):
        for process in psutil.process_iter(["pid", "name"]):
            name = (process.info.get("name") or "").strip()
            if name == self.daemon_name:
                return process
        return None

    def _get_thermal_limit(self):
        try:
            temperatures = psutil.sensors_temperatures()
        except (AttributeError, psutil.Error) as exc:
            self.logger.debug(f"Unable to read temperature sensors: {exc}")
            return 100

        if not temperatures:
            return 100

        max_temperature = max(
            (
                sensor.current
                for entries in temperatures.values()
                for sensor in entries
                if sensor.current is not None
            ),
            default=0,
        )
        if max_temperature > 90:
            return 10
        if max_temperature > 80:
            return 50
        return 100

    def _capture_original_priority(self, process):
        if self.priority_pid == process.pid:
            return

        try:
            self.original_nice = process.nice()
        except psutil.Error as exc:
            self.logger.debug(f"Unable to read clamd nice value: {exc}")
            self.original_nice = None

        try:
            io_priority = process.ionice()
            if hasattr(io_priority, "ioclass"):
                self.original_ionice = (
                    io_priority.ioclass,
                    getattr(io_priority, "value", 0),
                )
            elif isinstance(io_priority, (tuple, list)) and io_priority:
                io_value = io_priority[1] if len(io_priority) > 1 else 0
                self.original_ionice = (io_priority[0], io_value)
            else:
                self.original_ionice = None
        except psutil.Error as exc:
            self.logger.debug(f"Unable to read clamd ionice value: {exc}")
            self.original_ionice = None

        self.priority_pid = process.pid

    def _restore_original_priority(self):
        if self.priority_pid is None:
            return True

        try:
            process = psutil.Process(self.priority_pid)
        except psutil.Error:
            self._clear_priority_state()
            return True

        restored = True
        if self.original_nice is not None:
            try:
                process.nice(self.original_nice)
            except psutil.Error as exc:
                self.logger.warning(f"Unable to restore clamd nice value: {exc}")
                restored = False

        if self.original_ionice is not None:
            io_class, io_value = self.original_ionice
            try:
                process.ionice(ioclass=io_class, value=io_value)
            except psutil.Error as exc:
                self.logger.warning(f"Unable to restore clamd ionice value: {exc}")
                restored = False

        self._clear_priority_state()
        return restored

    def _apply_limit(self, limit, pid):
        try:
            process = psutil.Process(pid)
        except psutil.Error as exc:
            self.logger.warning(f"Unable to access clamd process {pid}: {exc}")
            return False

        self._capture_original_priority(process)

        try:
            quota_result = run_system_tool(
                "systemctl",
                (
                    "set-property",
                    "--runtime",
                    self.target_service,
                    f"CPUQuota={limit}%",
                ),
                quiet=True,
                timeout=30,
            )
        except SystemCommandError as exc:
            self.logger.error(f"Unable to apply ClamAV CPUQuota: {exc}")
            return False

        if quota_result.returncode != 0:
            self.logger.error("Unable to apply ClamAV CPUQuota.")
            return False

        try:
            process.nice(19)
        except psutil.Error as exc:
            self.logger.debug(f"psutil nice update failed, using renice: {exc}")
            self._run_priority_fallback("renice", ("-n", "19", "-p", pid))

        try:
            process.ionice(ioclass=psutil.IOPRIO_CLASS_IDLE)
        except psutil.Error as exc:
            self.logger.debug(f"psutil ionice update failed, using ionice: {exc}")
            self._run_priority_fallback("ionice", ("-c", "3", "-p", pid))

        self.current_limit_value = limit
        self.logger.info(f"Throttling ClamAV to {limit}% CPUQuota")
        return True

    def _run_priority_fallback(self, tool_name, arguments):
        try:
            result = run_system_tool(
                tool_name,
                arguments,
                quiet=True,
                timeout=15,
            )
        except SystemCommandError as exc:
            self.logger.warning(f"Unable to run {tool_name}: {exc}")
            return False
        if result.returncode != 0:
            self.logger.warning(f"{tool_name} failed for clamd process.")
            return False
        return True

    def _remove_limit(self):
        had_limit = self.current_limit_value is not None
        quota_released = True

        if had_limit:
            try:
                result = run_system_tool(
                    "systemctl",
                    (
                        "set-property",
                        "--runtime",
                        self.target_service,
                        "CPUQuota=",
                    ),
                    quiet=True,
                    timeout=30,
                )
            except SystemCommandError as exc:
                self.logger.error(f"Unable to release ClamAV CPUQuota: {exc}")
                quota_released = False
            else:
                quota_released = result.returncode == 0
                if not quota_released:
                    self.logger.error("Unable to release ClamAV CPUQuota.")

        priorities_restored = self._restore_original_priority()
        if quota_released:
            self.current_limit_value = None
            if had_limit:
                self.logger.info("ClamAV Throttling Released")

        return quota_released and priorities_restored
