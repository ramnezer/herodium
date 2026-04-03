import logging
import subprocess
import sys

# ==============================================================================
# Herodium System Hardener
# Applies Kernel-level security tweaks (sysctl) to prevent common network attacks.
# ==============================================================================

class SystemHardener:
    def __init__(self, config, logger):
        self.logger = logger
        self.config = config
        self.enabled = config.get('hardening', {}).get('enable', False)
        self.rules = config.get('hardening', {}).get('rules', {})

    def apply_security_rules(self):
        """
        Iterates over defined sysctl rules and applies them.
        """
        if not self.enabled:
            self.logger.info("System Hardening is DISABLED in config.")
            return

        self.logger.info("Applying System Hardening rules (Kernel Tuning)...")
        
        applied_count = 0
        failed_count = 0

        for key, value in self.rules.items():
            if self._set_sysctl(key, value):
                applied_count += 1
            else:
                failed_count += 1

        self.logger.info(f"Hardening Complete: {applied_count} applied, {failed_count} failed.")

    def _set_sysctl(self, key, value):
        """
        Executes 'sysctl -w key=value' securely.
        """
        try:
            # We use subprocess to run the system command
            cmd = ['sysctl', '-w', f'{key}={value}']
            
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                check=False # Don't crash on error
            )

            if result.returncode == 0:
                self.logger.debug(f"Applied: {key} = {value}")
                return True
            else:
                self.logger.warning(f"Failed to apply {key}: {result.stderr.strip()}")
                return False

        except FileNotFoundError:
            self.logger.error("Critical: 'sysctl' command not found. Is this Linux?")
            return False
        except Exception as e:
            self.logger.error(f"Error applying {key}: {e}")
            return False
