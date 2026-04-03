import subprocess
import shutil
import os
import logging
import time 
import glob

class IPSManager:
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger
        self.enabled = self.config.get('ips', {}).get('enable', True)

        self.bantime = self.config.get('ips', {}).get('bantime', 3600)
        self.maxretry = self.config.get('ips', {}).get('maxretry', 3)

        try:
            self.findtime = int(self.config.get('ips', {}).get('findtime', 60) or 60)
        except Exception:
            self.findtime = 60

    def start(self):
        if not self.enabled:
            self.logger.info("IPS (Fail2Ban) is DISABLED in config.")
            return

        self.logger.info("Initializing Network IPS (Fail2Ban)...")

        if not shutil.which('fail2ban-client'):
            self.logger.warning(
                "Fail2Ban is enabled in config but not installed. "
                "Install it from the Herodium installer."
            )
            return

        if not self._has_existing_herodium_jail():
            self.logger.warning(
                "No Herodium Fail2Ban jail config found in /etc/fail2ban/jail.d/. "
                "The installer should create it."
            )

        self._ensure_running()

    def _has_existing_herodium_jail(self) -> bool:
        try:
            matches = glob.glob("/etc/fail2ban/jail.d/herodium*.conf")
            return len(matches) > 0
        except Exception:
            return False

    def _ensure_running(self):
        """Ensure the service is running without installing or writing configs."""
        try:
            subprocess.run(
                ['systemctl', 'enable', 'fail2ban'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False
            )
            subprocess.run(
                ['systemctl', 'restart', 'fail2ban'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False
            )

            for _ in range(5):
                time.sleep(1)
                res = subprocess.run(
                    ['fail2ban-client', 'ping'],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                if "Server replied: pong" in res.stdout:
                    self.logger.info("IPS Active: SSH Brute-Force Protection Enabled.")
                    return

            self.logger.warning("IPS Service started but timed out waiting for socket.")

        except Exception as e:
            self.logger.error(f"Error managing Fail2Ban service: {e}")

    def stop(self):
        pass
