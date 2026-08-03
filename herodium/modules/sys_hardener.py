from __future__ import annotations

import re

from core.system_command import SystemCommandError, run_system_tool


_SYSCTL_KEY_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+$")


class SystemHardener:
    def __init__(self, config, logger):
        self.logger = logger
        self.config = config or {}
        hardening_config = self.config.get("hardening", {}) or {}
        self.enabled = self._safe_bool(hardening_config.get("enable"), False)
        rules = hardening_config.get("rules", {}) or {}
        self.rules = rules if isinstance(rules, dict) else {}

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

    def apply_security_rules(self):
        if not self.enabled:
            self.logger.info("System Hardening is DISABLED in config.")
            return True

        self.logger.info("Applying System Hardening rules (Kernel Tuning)...")
        applied_count = 0
        failed_count = 0

        for key, value in self.rules.items():
            if self._set_sysctl(key, value):
                applied_count += 1
            else:
                failed_count += 1

        self.logger.info(
            f"Hardening Complete: {applied_count} applied, "
            f"{failed_count} failed."
        )
        return failed_count == 0

    def _set_sysctl(self, key, value):
        key_text = str(key).strip()
        value_text = str(value).strip()
        if not _SYSCTL_KEY_PATTERN.fullmatch(key_text):
            self.logger.warning(f"Rejected invalid sysctl key: {key!r}")
            return False
        if (
            not value_text
            or len(value_text) > 256
            or "\x00" in value_text
            or "\n" in value_text
            or "\r" in value_text
        ):
            self.logger.warning(f"Rejected invalid sysctl value for {key_text}.")
            return False

        try:
            result = run_system_tool(
                "sysctl",
                ("-w", f"{key_text}={value_text}"),
                capture=True,
                timeout=15,
            )
        except SystemCommandError as exc:
            self.logger.error(f"Error applying {key_text}: {exc}")
            return False

        if result.returncode == 0:
            self.logger.debug(f"Applied: {key_text} = {value_text}")
            return True

        error_text = result.stderr.strip() or "unknown sysctl error"
        self.logger.warning(f"Failed to apply {key_text}: {error_text}")
        return False
