from __future__ import annotations

import pwd
from pathlib import Path

from core.system_command import (
    SystemCommandError,
    resolve_system_tool,
    run_system_tool,
    system_tool_available,
)


class Notifier:
    def __init__(self, config, logger, scope="general"):
        self.config = config or {}
        self.logger = logger
        self.scope = scope
        self.enabled = self._resolve_enabled_state()

    @staticmethod
    def _safe_bool(value, default=True):
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

    def _resolve_enabled_state(self):
        """Resolve notification enablement by scope with safe booleans."""
        notifications_config = self.config.get("notifications", {}) or {}
        maltrail_config = self.config.get("maltrail", {}) or {}

        if self.scope == "maltrail":
            if "desktop_notifications" in maltrail_config:
                return self._safe_bool(
                    maltrail_config.get("desktop_notifications"), True
                )
            if "enable" in notifications_config:
                return self._safe_bool(notifications_config.get("enable"), True)
            return True

        if "enable" in notifications_config:
            return self._safe_bool(notifications_config.get("enable"), True)
        return True

    def send_notification(self, title, message, level="normal"):
        """Send a desktop notification to active non-system user sessions."""
        if not self.enabled:
            return False

        base_run_dir = Path("/run/user")
        try:
            entries = tuple(base_run_dir.iterdir())
        except OSError as exc:
            self.logger.error(f"Notification loop error: {exc}")
            return False

        delivered = False
        for entry in entries:
            if not entry.name.isdigit():
                continue

            uid = int(entry.name)
            if uid < 1000:
                continue

            try:
                user_name = pwd.getpwuid(uid).pw_name
            except KeyError:
                continue

            dbus_path = entry / "bus"
            if not dbus_path.exists():
                continue

            if self._dispatch(
                user_name,
                uid,
                dbus_path,
                str(title),
                str(message),
                str(level),
            ):
                delivered = True

        return delivered

    def _dispatch(self, user, uid, dbus_path, title, message, level):
        """Dispatch a notification to one desktop session."""
        urgency = level if level in {"low", "normal", "critical"} else "normal"
        try:
            env_path = resolve_system_tool("env")
            notify_path = resolve_system_tool("notify-send")

            env_arguments = [
                str(env_path),
                f"DBUS_SESSION_BUS_ADDRESS=unix:path={dbus_path}",
                f"XDG_RUNTIME_DIR=/run/user/{uid}",
                "DISPLAY=:0",
                str(notify_path),
                title,
                message,
                "-t",
                "10000",
                "-u",
                urgency,
                "-i",
                "security-high",
            ]

            if system_tool_available("sudo"):
                tool = "sudo"
                arguments = ["-u", user, *env_arguments]
            elif system_tool_available("runuser"):
                tool = "runuser"
                arguments = ["-u", user, "--", *env_arguments]
            else:
                self.logger.warning(
                    "Notification skipped: neither sudo nor runuser is available."
                )
                return False

            result = run_system_tool(
                tool,
                arguments,
                quiet=True,
                timeout=15,
            )
            if result.returncode != 0:
                self.logger.warning(
                    f"Desktop notification command failed for user {user}."
                )
                return False
            return True
        except (SystemCommandError, OSError, TimeoutError) as exc:
            self.logger.error(f"Failed to notify user {user}: {exc}")
            return False
