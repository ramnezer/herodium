from __future__ import annotations

import glob
import time

from core.system_command import (
    SystemCommandError,
    run_system_tool,
    system_tool_available,
)


class IPSManager:
    def __init__(self, config, logger):
        self.config = config or {}
        self.logger = logger
        ips_config = self.config.get("ips", {}) or {}
        self.enabled = self._safe_bool(ips_config.get("enable"), False)
        self.bantime = self._safe_int(ips_config.get("bantime"), 3600, 1)
        self.maxretry = self._safe_int(ips_config.get("maxretry"), 3, 1)
        self.findtime = self._safe_int(ips_config.get("findtime"), 60, 1)

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
    def _safe_int(value, default, minimum):
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            return default
        return max(minimum, parsed)

    def start(self):
        if not self.enabled:
            self.logger.info("IPS (Fail2Ban) is DISABLED in config.")
            return True

        self.logger.info("Initializing Network IPS (Fail2Ban)...")

        if not system_tool_available("fail2ban-client"):
            self.logger.warning(
                "Fail2Ban is enabled in config but not installed. "
                "Install it from the Herodium installer."
            )
            return False

        if not self._has_existing_herodium_jail():
            self.logger.warning(
                "No Herodium Fail2Ban jail config found in "
                "/etc/fail2ban/jail.d/. The installer should create it."
            )

        return self._ensure_running()

    def _has_existing_herodium_jail(self) -> bool:
        try:
            return bool(glob.glob("/etc/fail2ban/jail.d/herodium*.conf"))
        except OSError as exc:
            self.logger.warning(f"Unable to inspect Fail2Ban jail configuration: {exc}")
            return False

    def _ensure_running(self):
        """Ensure the preconfigured Fail2Ban service is running."""
        try:
            enable_result = run_system_tool(
                "systemctl",
                ("enable", "fail2ban"),
                quiet=True,
                timeout=30,
            )
            if enable_result.returncode != 0:
                self.logger.error("Could not enable Fail2Ban service.")
                return False

            restart_result = run_system_tool(
                "systemctl",
                ("restart", "fail2ban"),
                quiet=True,
                timeout=30,
            )
            if restart_result.returncode != 0:
                self.logger.error("Could not restart Fail2Ban service.")
                return False

            for _ in range(5):
                time.sleep(1)
                ping_result = run_system_tool(
                    "fail2ban-client",
                    ("ping",),
                    capture=True,
                    timeout=10,
                )
                if (
                    ping_result.returncode == 0
                    and "server replied: pong" in ping_result.stdout.lower()
                ):
                    self.logger.info(
                        "IPS Active: SSH Brute-Force Protection Enabled."
                    )
                    return True

            self.logger.warning(
                "IPS Service started but timed out waiting for socket."
            )
            return False
        except (SystemCommandError, OSError, TimeoutError) as exc:
            self.logger.error(f"Error managing Fail2Ban service: {exc}")
            return False

    def stop(self):
        """Fail2Ban remains managed by systemd when Herodium exits."""
        return True
