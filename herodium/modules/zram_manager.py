from __future__ import annotations

from pathlib import Path

from core.system_command import (
    SystemCommandError,
    run_system_tool,
    system_tool_available,
)


class ZramManager:
    def __init__(self, config, logger):
        self.config = config or {}
        self.logger = logger
        performance_config = self.config.get("performance", {}) or {}
        self.enabled = self._safe_bool(
            performance_config.get("enable_zram"), False
        )
        self.service_name = None

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

    def enable(self):
        if not self.enabled:
            self.logger.info("ZRAM optimization is DISABLED in config.")
            return True

        if self._is_active():
            self.logger.info("ZRAM is already active (System Accelerated).")
            return True

        self._detect_existing_service()
        if not self.service_name:
            self.logger.warning(
                "ZRAM is enabled in config but no supported ZRAM service was "
                "found. Install and configure it from the Herodium installer."
            )
            return False

        if (
            self.service_name == "zramswap"
            and not Path("/etc/default/zramswap").is_file()
        ):
            self.logger.warning(
                "/etc/default/zramswap is missing. "
                "The installer should create it before runtime."
            )
            return False

        self.logger.info("Activating ZRAM memory compression...")
        return self._configure_zram()

    def _is_active(self):
        """Check whether a zram block device is configured as swap."""
        if system_tool_available("zramctl"):
            try:
                result = run_system_tool(
                    "zramctl", (), capture=True, timeout=10
                )
            except SystemCommandError as exc:
                self.logger.debug(f"Unable to query zramctl: {exc}")
            else:
                if result.returncode == 0 and "zram" in result.stdout:
                    return True

        try:
            swaps = run_system_tool(
                "swapon",
                ("--show", "--noheadings", "--raw", "--output", "NAME"),
                capture=True,
                timeout=10,
            )
        except SystemCommandError as exc:
            self.logger.debug(f"Unable to query active swap devices: {exc}")
            return False

        return swaps.returncode == 0 and any(
            line.strip().startswith("/dev/zram")
            for line in swaps.stdout.splitlines()
        )

    def _detect_existing_service(self):
        """Detect one supported systemd ZRAM service."""
        unit_directories = (
            Path("/etc/systemd/system"),
            Path("/run/systemd/system"),
            Path("/usr/lib/systemd/system"),
            Path("/lib/systemd/system"),
        )
        for service_name in ("zram-config", "zramswap"):
            unit_name = f"{service_name}.service"
            if any((directory / unit_name).exists() for directory in unit_directories):
                self.service_name = service_name
                return
        self.service_name = None

    def _configure_zram(self):
        if self.service_name not in {"zram-config", "zramswap"}:
            self.logger.error("Refusing to start an unsupported ZRAM service.")
            return False

        try:
            enable_result = run_system_tool(
                "systemctl",
                ("enable", self.service_name),
                quiet=True,
                timeout=30,
            )
            if enable_result.returncode != 0:
                self.logger.error(f"Could not enable {self.service_name}.")
                return False

            restart_result = run_system_tool(
                "systemctl",
                ("restart", self.service_name),
                quiet=True,
                timeout=30,
            )
            if restart_result.returncode != 0:
                self.logger.error(f"Could not restart {self.service_name}.")
                return False
        except SystemCommandError as exc:
            self.logger.error(f"Could not start {self.service_name}: {exc}")
            return False

        if self._is_active():
            self.logger.info(
                f"ZRAM activated successfully using {self.service_name}."
            )
            return True

        self.logger.warning(
            f"Service {self.service_name} started but ZRAM was not detected yet."
        )
        return False
