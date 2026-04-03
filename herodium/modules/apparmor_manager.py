import subprocess
import logging
import os
import shutil
import time

class AppArmorManager:
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger
        self.level = int(config.get('apparmor', {}).get('level', 1) or 1)
        self.should_backup = bool(config.get('apparmor', {}).get('create_backup', True))
        self.backup_name = config.get('apparmor', {}).get('backup_name', "herodium_pre_apparmor")

        self.state_file = "/opt/herodium/apparmor_state"
        self.state_dir = "/opt/herodium/apparmor_state_data"
        self.force_complain_dir = "/etc/apparmor.d/force-complain"
        self.baseline_force_complain = os.path.join(self.state_dir, "baseline_force-complain")

    def apply_policy(self):
        """Apply AppArmor policy with baseline preservation and blocking backup."""
        last_level = self._read_last_state()

        if self.level == last_level:
            self.logger.info(f"AppArmor already configured at Level {self.level}. Skipping heavy setup.")
            return

        if not self._runtime_requirements_ok():
            self.logger.warning("AppArmor requirements are missing. Skipping policy apply.")
            return

        self.logger.info(f"Applying NEW AppArmor Level: {self.level} (Was: {last_level})")

        # Save baseline only once: the first time we move away from default/level 1.
        if self.level > 1 and last_level <= 1:
            if not self._baseline_exists():
                if not self._save_baseline_mode_state():
                    self.logger.warning("Failed to save AppArmor baseline mode state. Skipping policy change.")
                    return

        # If backup was requested, wait for it to finish before changing policy.
        if self.level > 1 and self.should_backup:
            if not self._create_timeshift_snapshot():
                self.logger.warning("Timeshift backup failed or timed out. Skipping AppArmor policy change.")
                return

        if self.level == 1:
            self._mode_default()
        elif self.level == 2:
            self._mode_light()
        elif self.level == 3:
            self._mode_medium()
        elif self.level == 4:
            self._mode_full()
        else:
            self.logger.warning("Invalid AppArmor level. Defaulting to 1.")
            self._mode_default()

        self._write_current_state()

    def _runtime_requirements_ok(self):
        if not shutil.which("systemctl"):
            self.logger.error("systemctl not found.")
            return False

        if self.level <= 1:
            return True

        if self.level == 2 and not shutil.which("aa-complain"):
            self.logger.warning("aa-complain not found. Install apparmor-utils from the installer.")
            return False

        if self.level in (3, 4) and not shutil.which("aa-enforce"):
            self.logger.warning("aa-enforce not found. Install apparmor-utils from the installer.")
            return False

        if self.level == 4 and not shutil.which("auditctl"):
            self.logger.warning("auditctl not found. Level 4 is incomplete without auditd.")
            return False

        if not os.path.isdir("/etc/apparmor.d"):
            self.logger.warning("/etc/apparmor.d not found.")
            return False

        return True

    def _read_last_state(self):
        if not os.path.exists(self.state_file):
            return -1
        try:
            with open(self.state_file, 'r') as f:
                return int(f.read().strip())
        except Exception:
            return -1

    def _write_current_state(self):
        try:
            os.makedirs(os.path.dirname(self.state_file), exist_ok=True)
            with open(self.state_file, 'w') as f:
                f.write(str(self.level))
        except Exception:
            pass

    def _baseline_exists(self):
        return os.path.isdir(self.baseline_force_complain)

    def _save_baseline_mode_state(self):
        """
        Save the original AppArmor complain-mode markers only once,
        so Level 1 can restore the pre-Herodium state later.
        """
        try:
            os.makedirs(self.state_dir, exist_ok=True)

            if os.path.exists(self.baseline_force_complain):
                shutil.rmtree(self.baseline_force_complain, ignore_errors=True)

            if os.path.isdir(self.force_complain_dir):
                shutil.copytree(self.force_complain_dir, self.baseline_force_complain, symlinks=True)
            else:
                os.makedirs(self.baseline_force_complain, exist_ok=True)

            self.logger.info("Saved AppArmor baseline mode state.")
            return True
        except Exception as e:
            self.logger.warning(f"Failed to save AppArmor baseline state: {e}")
            return False

    def _restore_baseline_mode_state(self):
        """
        Restore the original complain-mode markers and reload AppArmor.
        If baseline is missing, fall back to generic defaults.
        """
        try:
            if os.path.isdir(self.force_complain_dir):
                shutil.rmtree(self.force_complain_dir, ignore_errors=True)

            if os.path.isdir(self.baseline_force_complain):
                shutil.copytree(self.baseline_force_complain, self.force_complain_dir, symlinks=True)
                self.logger.info("Restored AppArmor baseline mode state.")
            else:
                os.makedirs(self.force_complain_dir, exist_ok=True)
                self.logger.warning("Baseline AppArmor state was missing. Restored generic defaults instead.")

            self._reload_apparmor()
        except Exception as e:
            self.logger.warning(f"Failed to restore AppArmor baseline state: {e}")

    def _create_timeshift_snapshot(self):
        """
        Run Timeshift synchronously so policy changes start only after backup completion.
        """
        if not shutil.which('timeshift'):
            self.logger.warning("Timeshift not found. Continuing AppArmor change without backup.")
            return True

        self.logger.info("Creating Timeshift snapshot before AppArmor change...")
        try:
            cmd = ['timeshift', '--create', '--comments', self.backup_name, '--tags', 'D', '--yes']
            result = subprocess.run(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=7200
            )

            if result.returncode == 0:
                self.logger.info("Timeshift snapshot completed successfully.")
                return True

            self.logger.warning(f"Timeshift snapshot failed with exit code {result.returncode}.")
            return False
        except subprocess.TimeoutExpired:
            self.logger.warning("Timeshift snapshot timed out.")
            return False
        except Exception as e:
            self.logger.warning(f"Failed to create Timeshift snapshot: {e}")
            return False

    def _profile_paths(self):
        base = "/etc/apparmor.d"
        try:
            return [
                os.path.join(base, name)
                for name in os.listdir(base)
                if os.path.isfile(os.path.join(base, name))
            ]
        except Exception:
            return []

    def _reload_apparmor(self):
        subprocess.run(
            ['systemctl', 'reload-or-restart', 'apparmor'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False
        )

    def _mode_default(self):
        self._restore_baseline_mode_state()

        # Best-effort rollback of Level 4 audit component
        subprocess.run(
            ['systemctl', 'disable', '--now', 'auditd'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False
        )

    def _mode_light(self):
        profiles = self._profile_paths()
        if not profiles:
            self.logger.warning("No AppArmor profiles found to set in complain mode.")
            return

        self.logger.info("AppArmor: Setting COMPLAIN mode...")
        subprocess.run(
            ['aa-complain'] + profiles,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False
        )

    def _mode_medium(self):
        profiles = self._profile_paths()
        if not profiles:
            self.logger.warning("No AppArmor profiles found to set in enforce mode.")
            return

        self.logger.info("AppArmor: Setting ENFORCE mode (Standard)...")
        subprocess.run(
            ['aa-enforce'] + profiles,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False
        )

    def _mode_full(self):
        profiles = self._profile_paths()
        if not profiles:
            self.logger.warning("No AppArmor profiles found to set in enforce mode.")
            return

        self.logger.warning("AppArmor: FULL LOCKDOWN.")
        subprocess.run(
            ['aa-enforce'] + profiles,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False
        )
        subprocess.run(
            ['systemctl', 'enable', '--now', 'auditd'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False
        )
