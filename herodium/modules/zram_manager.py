import subprocess
import logging
import os
import shutil

class ZramManager:
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger
        self.enabled = config.get('performance', {}).get('enable_zram', False)
        self.service_name = None

    def enable(self):
        if not self.enabled:
            self.logger.info("ZRAM optimization is DISABLED in config.")
            return

        if self._is_active():
            self.logger.info("ZRAM is already active (System Accelerated).")
            return

        self._detect_existing_service()

        if not self.service_name:
            self.logger.warning(
                "ZRAM is enabled in config but no supported ZRAM service was found. "
                "Install and configure it from the Herodium installer."
            )
            return

        if self.service_name == "zramswap" and not os.path.exists("/etc/default/zramswap"):
            self.logger.warning(
                "/etc/default/zramswap is missing. "
                "The installer should create it before runtime."
            )
            return

        self.logger.info("Activating ZRAM memory compression...")
        self._configure_zram()

    def _is_active(self):
        """Check if a zram swap exists."""
        try:
            if shutil.which('zramctl'):
                output = subprocess.check_output(['zramctl'], stderr=subprocess.DEVNULL, text=True)
                if "zram" in output:
                    return True

            swaps = subprocess.check_output(['swapon', '--show'], stderr=subprocess.DEVNULL, text=True)
            return "/dev/zram" in swaps
        except Exception:
            return False

    def _detect_existing_service(self):
        """Detect which ZRAM service exists on the system."""
        if os.path.exists("/lib/systemd/system/zram-config.service"):
            self.service_name = "zram-config"
        elif os.path.exists("/lib/systemd/system/zramswap.service"):
            self.service_name = "zramswap"

    def _configure_zram(self):
        """Enable the already-installed service only."""
        try:
            subprocess.run(
                ['systemctl', 'enable', self.service_name],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False
            )
            subprocess.run(
                ['systemctl', 'restart', self.service_name],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False
            )

            if self._is_active():
                self.logger.info(f"ZRAM activated successfully using {self.service_name}.")
            else:
                self.logger.warning(f"Service {self.service_name} started but ZRAM was not detected yet.")
        except Exception as e:
            self.logger.error(f"Could not start {self.service_name}: {e}")
