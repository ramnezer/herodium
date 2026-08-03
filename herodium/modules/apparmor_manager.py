import os
import subprocess  # nosec B404 -- fixed local administration tools only
from pathlib import Path
from typing import Final

from modules.apparmor_state import AppArmorStateError, AppArmorStateStore


_SYSTEM_TOOL_CANDIDATES: Final[dict[str, tuple[str, ...]]] = {
    "aa-complain": ("/usr/sbin/aa-complain", "/sbin/aa-complain"),
    "aa-enforce": ("/usr/sbin/aa-enforce", "/sbin/aa-enforce"),
    "auditctl": ("/usr/sbin/auditctl", "/sbin/auditctl"),
    "systemctl": ("/usr/bin/systemctl", "/bin/systemctl"),
    "timeshift": ("/usr/bin/timeshift", "/bin/timeshift"),
}


class AppArmorManager:
    def __init__(self, config, logger, state_store=None):
        self.config = config
        self.logger = logger
        self.level = int(config.get("apparmor", {}).get("level", 1) or 1)
        self.should_backup = bool(
            config.get("apparmor", {}).get("create_backup", True)
        )
        self.backup_name = config.get("apparmor", {}).get(
            "backup_name",
            "herodium_pre_apparmor",
        )

        self.state_store = state_store or AppArmorStateStore()
        self.force_complain_dir = Path("/etc/apparmor.d/force-complain")

    def apply_policy(self):
        """Apply AppArmor policy while preserving the pre-Herodium baseline."""
        try:
            self.state_store.prepare()
            last_level = self.state_store.read_level()
        except AppArmorStateError as exc:
            self.logger.error(f"AppArmor persistent state is unavailable: {exc}")
            return False

        if self.level == last_level:
            self.logger.info(
                f"AppArmor already configured at Level {self.level}. "
                "Skipping heavy setup."
            )
            return True

        if not self._runtime_requirements_ok():
            self.logger.warning(
                "AppArmor requirements are missing. Skipping policy apply."
            )
            return False

        self.logger.info(
            f"Applying NEW AppArmor Level: {self.level} (Was: {last_level})"
        )

        if self.level > 1 and last_level <= 1:
            try:
                if not self.state_store.baseline_exists():
                    self.state_store.save_baseline(self.force_complain_dir)
                    self.logger.info("Saved AppArmor baseline mode state.")
            except AppArmorStateError as exc:
                self.logger.warning(
                    f"Failed to save AppArmor baseline mode state: {exc}"
                )
                return False

        if self.level > 1 and self.should_backup:
            if not self._create_timeshift_snapshot():
                self.logger.warning(
                    "Timeshift backup failed or timed out. "
                    "Skipping AppArmor policy change."
                )
                return False

        applied_level = self.level
        if self.level == 1:
            applied = self._mode_default()
        elif self.level == 2:
            applied = self._mode_light()
        elif self.level == 3:
            applied = self._mode_medium()
        elif self.level == 4:
            applied = self._mode_full()
        else:
            self.logger.warning("Invalid AppArmor level. Defaulting to 1.")
            applied_level = 1
            applied = self._mode_default()

        if not applied:
            self.logger.error(
                f"AppArmor Level {applied_level} was not applied successfully."
            )
            return False

        try:
            self.state_store.write_level(applied_level)
        except AppArmorStateError as exc:
            self.logger.error(
                f"AppArmor policy changed but state persistence failed: {exc}"
            )
            return False

        return True

    def _runtime_requirements_ok(self):
        if self._resolve_system_tool("systemctl") is None:
            self.logger.error("systemctl not found at an approved path.")
            return False

        if self.level <= 1:
            return True

        if self.level == 2 and self._resolve_system_tool("aa-complain") is None:
            self.logger.warning(
                "aa-complain not found. Install apparmor-utils from the installer."
            )
            return False

        if self.level in (3, 4) and self._resolve_system_tool("aa-enforce") is None:
            self.logger.warning(
                "aa-enforce not found. Install apparmor-utils from the installer."
            )
            return False

        if self.level == 4 and self._resolve_system_tool("auditctl") is None:
            self.logger.warning(
                "auditctl not found. Level 4 is incomplete without auditd."
            )
            return False

        if not os.path.isdir("/etc/apparmor.d"):
            self.logger.warning("/etc/apparmor.d not found.")
            return False

        return True

    def _create_timeshift_snapshot(self):
        if self._resolve_system_tool("timeshift") is None:
            self.logger.warning(
                "Timeshift not found. Skipping AppArmor policy change because "
                "backup was requested."
            )
            return False

        self.logger.info("Creating Timeshift snapshot before AppArmor change...")
        try:
            result = self._run_system_tool(
                "timeshift",
                "--create",
                "--comments",
                self.backup_name,
                "--tags",
                "D",
                "--yes",
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=7200,
            )
        except subprocess.TimeoutExpired:
            self.logger.warning("Timeshift snapshot timed out.")
            return False
        except (OSError, ValueError) as exc:
            self.logger.warning(f"Failed to create Timeshift snapshot: {exc}")
            return False

        if result.returncode == 0:
            self.logger.info("Timeshift snapshot completed successfully.")
            return True

        self.logger.warning(
            f"Timeshift snapshot failed with exit code {result.returncode}."
        )
        return False

    def _profile_paths(self):
        base = Path("/etc/apparmor.d")
        try:
            return sorted(
                str(path)
                for path in base.iterdir()
                if path.is_file() and not path.is_symlink()
            )
        except OSError as exc:
            self.logger.warning(f"Unable to enumerate AppArmor profiles: {exc}")
            return []

    def _reload_apparmor(self):
        try:
            result = self._run_system_tool(
                "systemctl",
                "reload-or-restart",
                "apparmor",
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        except (OSError, ValueError) as exc:
            self.logger.warning(f"Unable to reload AppArmor: {exc}")
            return False

        if result.returncode != 0:
            self.logger.warning(
                f"AppArmor reload failed with exit code {result.returncode}."
            )
            return False
        return True

    def _mode_default(self):
        try:
            restored = self.state_store.restore_baseline(
                self.force_complain_dir
            )
        except AppArmorStateError as exc:
            self.logger.warning(f"Failed to restore AppArmor baseline state: {exc}")
            return False

        if restored:
            self.logger.info("Restored AppArmor baseline mode state.")
            if not self._reload_apparmor():
                return False
        else:
            self.logger.info(
                "No Herodium AppArmor baseline found; leaving force-complain "
                "state unchanged."
            )

        self.logger.info(
            "AppArmor Level 1 selected; auditd service state left unchanged."
        )
        return True

    def _mode_light(self):
        profiles = self._profile_paths()
        if not profiles:
            self.logger.warning("No AppArmor profiles found to set in complain mode.")
            return False

        self.logger.info("AppArmor: Setting COMPLAIN mode...")
        return self._run_profile_tool("aa-complain", profiles)

    def _mode_medium(self):
        profiles = self._profile_paths()
        if not profiles:
            self.logger.warning("No AppArmor profiles found to set in enforce mode.")
            return False

        self.logger.info("AppArmor: Setting ENFORCE mode (Standard)...")
        return self._run_profile_tool("aa-enforce", profiles)

    def _mode_full(self):
        profiles = self._profile_paths()
        if not profiles:
            self.logger.warning("No AppArmor profiles found to set in enforce mode.")
            return False

        self.logger.warning("AppArmor: FULL LOCKDOWN.")
        if not self._run_profile_tool("aa-enforce", profiles):
            return False

        try:
            result = self._run_system_tool(
                "systemctl",
                "enable",
                "--now",
                "auditd",
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        except (OSError, ValueError) as exc:
            self.logger.warning(f"Unable to enable auditd: {exc}")
            return False

        if result.returncode != 0:
            self.logger.warning(
                f"auditd enablement failed with exit code {result.returncode}."
            )
            return False
        return True

    def _run_profile_tool(self, tool, profiles):
        try:
            result = self._run_system_tool(
                tool,
                *profiles,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        except (OSError, ValueError) as exc:
            self.logger.warning(f"Unable to run {tool}: {exc}")
            return False

        if result.returncode != 0:
            self.logger.warning(
                f"{tool} failed with exit code {result.returncode}."
            )
            return False
        return True

    @staticmethod
    def _resolve_system_tool(tool):
        candidates = _SYSTEM_TOOL_CANDIDATES.get(tool)
        if candidates is None:
            return None

        for candidate in candidates:
            path = Path(candidate)
            try:
                if path.is_file() and os.access(path, os.X_OK):
                    return str(path.resolve(strict=True))
            except OSError:
                continue
        return None

    def _run_system_tool(self, tool, *arguments, **kwargs):
        executable = self._resolve_system_tool(tool)
        if executable is None:
            raise ValueError(f"System tool is unavailable or unapproved: {tool}")
        command = [executable, *(str(argument) for argument in arguments)]
        return subprocess.run(  # nosec B603 -- fixed allowlist and shell disabled
            command,
            shell=False,
            **kwargs,
        )
