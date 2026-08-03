from __future__ import annotations

import os
import re
import stat
import subprocess  # nosec B404 -- fixed local system tools only
import threading
import time
from pathlib import Path
from typing import Sequence

from modules.notifier import Notifier
from modules.rkhunter_manager import RkhunterManager


_SYSTEM_TOOL_CANDIDATES = {
    "clamdscan": (
        Path("/usr/bin/clamdscan"),
        Path("/usr/sbin/clamdscan"),
    ),
    "freshclam": (
        Path("/usr/bin/freshclam"),
        Path("/usr/sbin/freshclam"),
    ),
}


class TaskScheduler:
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger
        self.enabled = self._safe_bool(
            (config.get("scheduler", {}) or {}).get("enable"),
            True,
        )

        sched = config.get("scheduler", {}) or {}
        self.rkhunter_int = self._hours_to_seconds(
            sched.get("rkhunter_interval_hours", 6)
        )
        self.home_scan_int = self._hours_to_seconds(
            sched.get("home_scan_interval_hours", 24)
        )
        self.full_scan_int = self._hours_to_seconds(
            sched.get("full_scan_interval_hours", 168)
        )
        self.update_int = self._hours_to_seconds(
            sched.get("update_interval_hours", 24)
        )

        self.notifier = Notifier(config, logger)
        self.rkhunter = RkhunterManager(logger)

        now = time.time()
        self.last_rkhunter = now
        self.last_home = now
        self.last_full = now
        self.last_update = now

        self.stop_event = threading.Event()
        self._thread = None

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
    def _hours_to_seconds(hours):
        """Convert hours to seconds. Non-positive or invalid values disable the task."""
        try:
            parsed = int(hours)
        except (TypeError, ValueError):
            return None
        if parsed <= 0:
            return None
        return parsed * 3600

    def start(self):
        if not self.enabled:
            return False
        if self._thread is not None and self._thread.is_alive():
            return True

        self.stop_event.clear()
        self._thread = threading.Thread(
            target=self._loop,
            daemon=True,
            name="herodium-task-scheduler",
        )
        self._thread.start()
        self.logger.info("Task Scheduler started.")
        return self._thread.is_alive()

    def stop(self):
        self.stop_event.set()

    def _loop(self):
        while not self.stop_event.is_set():
            now = time.time()

            if self.rkhunter_int and now - self.last_rkhunter > self.rkhunter_int:
                self._run_rkhunter()
                self.last_rkhunter = now

            if self.home_scan_int and now - self.last_home > self.home_scan_int:
                self._run_scan("Home", "/home")
                self.last_home = now

            if self.full_scan_int and now - self.last_full > self.full_scan_int:
                self._run_scan("Full System", "/")
                self.last_full = now

            if self.update_int and now - self.last_update > self.update_int:
                self._run_updates()
                self.last_update = now

            self.stop_event.wait(60)

    def _run_scan(self, name, path):
        self.logger.info(f"Starting {name} Scan (ClamAV)...")

        clam_cfg = self.config.get("clamav", {}) or {}
        sched_cfg = self.config.get("scheduler", {}) or {}
        dirs_cfg = self.config.get("directories", {}) or {}

        action = str(
            sched_cfg.get("threat_action")
            or clam_cfg.get("threat_action")
            or "quarantine"
        ).lower()
        qdir = str(
            dirs_cfg.get("quarantine_dir")
            or "/opt/herodium/quarantine"
        )

        arguments = ["--fdpass", "--multiscan"]
        safe_exclude_dirs = (
            "/proc",
            "/sys",
            "/dev",
            "/run",
            "/var/lib/clamav",
            qdir,
            "/var/log/herodium",
            "/root/.maltrail",
        )
        for excluded_dir in safe_exclude_dirs:
            normalized_dir = str(excluded_dir).rstrip("/")
            if normalized_dir:
                arguments.append(
                    f"--exclude-dir=^{re.escape(normalized_dir)}($|/)"
                )

        if action == "delete":
            arguments.append("--remove=yes")
        elif action == "quarantine":
            try:
                os.makedirs(qdir, exist_ok=True)
                arguments.append(f"--move={qdir}")
            except OSError as exc:
                self.logger.error(
                    f"Unable to prepare quarantine directory {qdir}: {exc}. "
                    "Scheduled scan will run in alert-only mode."
                )
                action = "alert"

        arguments.append(path)
        result = self._run_system_tool(
            "clamdscan",
            arguments,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if result is None:
            self.logger.error(f"{name} Scan failed: clamdscan is unavailable.")
            return False

        if result.returncode == 0:
            self.logger.info(f"{name} Scan completed (clean).")
            return True
        if result.returncode == 1:
            self.logger.warning(
                f"{name} Scan completed (THREATS FOUND). Action={action}"
            )
            self.notifier.send_notification(
                "CLAMAV DETECTION",
                f"{name} scan found threats.\nAction: {action}",
                level="critical",
            )
            return True

        self.logger.error(
            f"{name} Scan ended with error code {result.returncode}."
        )
        return False

    def _run_rkhunter(self):
        self.logger.info("Starting Rkhunter scan...")
        result = self.rkhunter.check()

        if result.lock_busy:
            return False
        if result.returncode not in (0, 1):
            self.logger.error(
                f"Rkhunter scan failed with exit code {result.returncode}: "
                f"{result.output or 'no diagnostic output'}"
            )
            return False
        if result.output:
            self.logger.warning(f"Rkhunter Warnings:\n{result.output}")
            self.notifier.send_notification(
                "ROOTKIT WARNING",
                "Rkhunter found suspicious anomalies.\nCheck logs immediately!",
                level="critical",
            )
            return True

        self.logger.info("Rkhunter scan clean.")
        return True

    def _run_updates(self):
        self.logger.info("Running signature and Rkhunter data updates...")

        freshclam = self._run_system_tool(
            "freshclam",
            (),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if freshclam is None:
            self.logger.error("FreshClam update failed: executable unavailable.")
        elif freshclam.returncode != 0:
            self.logger.warning(
                f"FreshClam update exited with code {freshclam.returncode}."
            )

        if not self.rkhunter.available():
            self.logger.info("Rkhunter update skipped: executable unavailable.")
            return freshclam is not None and freshclam.returncode == 0

        update = self.rkhunter.update_data()
        if update.lock_busy:
            return False
        if update.returncode in (0, 2):
            self.logger.info("Rkhunter data update completed.")
            return freshclam is not None and freshclam.returncode == 0

        self.logger.error(
            f"Rkhunter data update failed with exit code {update.returncode}: "
            f"{update.output or 'no diagnostic output'}"
        )
        return False

    def _run_system_tool(
        self,
        name: str,
        arguments: Sequence[str],
        **kwargs,
    ):
        try:
            executable = self._resolve_system_tool(name)
        except (FileNotFoundError, PermissionError, OSError) as exc:
            self.logger.error(f"System tool resolution failed for {name}: {exc}")
            return None

        command = [str(executable), *map(str, arguments)]
        try:
            return subprocess.run(  # nosec B603 -- fixed verified executable, no shell
                command,
                shell=False,
                check=False,
                timeout=7200,
                **kwargs,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            self.logger.error(f"System tool {name} failed: {exc}")
            return None

    @staticmethod
    def _resolve_system_tool(name: str) -> Path:
        candidates = _SYSTEM_TOOL_CANDIDATES.get(name)
        if not candidates:
            raise ValueError(f"unsupported system tool: {name}")

        errors = []
        for candidate in candidates:
            try:
                resolved = candidate.resolve(strict=True)
                metadata = resolved.stat()
            except OSError as exc:
                errors.append(f"{candidate}: {exc}")
                continue

            if not stat.S_ISREG(metadata.st_mode):
                errors.append(f"{candidate}: not a regular file")
                continue
            if metadata.st_uid != 0:
                errors.append(f"{candidate}: not root-owned")
                continue
            if metadata.st_mode & 0o022:
                errors.append(f"{candidate}: group/other writable")
                continue
            if not os.access(resolved, os.X_OK):
                errors.append(f"{candidate}: not executable")
                continue
            return resolved

        detail = "; ".join(errors) or "no candidate paths configured"
        raise FileNotFoundError(f"trusted {name} executable unavailable: {detail}")
