import os
import shutil
import time
import logging
import pyclamd
import threading
from modules.notifier import Notifier

class ClamAVScanner:
    def __init__(self, config, logger):
        # Defensive config handling: avoid KeyError if YAML is missing keys
        self.config = config or {}
        self.logger = logger

        dirs_cfg = (self.config.get('directories') or {})
        clam_cfg = (self.config.get('clamav') or {})

        # Safe defaults (keep behaviour when YAML is valid, prevent crashes if not)
        self.quarantine_dir = str(dirs_cfg.get('quarantine_dir') or "/opt/herodium/quarantine")
        self.socket_path = str(clam_cfg.get('socket_path') or "/var/run/clamav/clamd.ctl")
        self.max_file_size_mb = self._safe_int(clam_cfg.get('max_file_size_mb'), 25)
        # Stream scanning uses INSTREAM, which is limited by clamd's StreamMaxLength.
        # We clamp the effective limit to avoid false failures on large files.
        self.stream_max_length_mb = self._safe_int(clam_cfg.get('stream_max_length_mb'), 25)
        self.effective_max_file_size_mb = min(self.max_file_size_mb, self.stream_max_length_mb)
        # Read User Preference (default: quarantine)
        self.action_policy = str(clam_cfg.get('threat_action') or 'quarantine').lower()

        self.lock = threading.Lock()
        self.cd = None
        self._connect()
        self.notifier = Notifier(self.config, logger)

    def _safe_int(self, value, default):
        """Return int(value) if valid (>0), otherwise default."""
        try:
            v = int(value)
            return v if v > 0 else default
        except Exception:
            return default

    def _connect(self):
        try:
            self.cd = pyclamd.ClamdUnixSocket(self.socket_path)
            if self.cd.ping() == 'PONG':
                self.logger.info("Connected to ClamAV Daemon.")
        except Exception as e:
            self.logger.error(f"ClamAV Connection Failed: {e}")
            self.cd = None

    def scan_file(self, file_path):
        if not os.path.exists(file_path):
            return False

        try:
            size = os.path.getsize(file_path)
            if size == 0 or size > self.effective_max_file_size_mb * 1024 * 1024:
                return False
        except Exception:
            return False

        with self.lock:
            if not self.cd:
                self._connect()
                if not self.cd:
                    return False

            try:
                with open(file_path, 'rb') as f:
                    file_content = f.read()

                result = self.cd.scan_stream(file_content)

                if result and 'stream' in result:
                    virus_info = result['stream']
                    if isinstance(virus_info, (list, tuple)) and len(virus_info) >= 2:
                        virus_name = virus_info[1]
                    else:
                        virus_name = str(virus_info)

                    if "FOUND" in str(virus_info) and "ERROR" not in str(virus_name):
                        self.logger.critical(f"VIRUS DETECTED: {file_path} -> {virus_name}")

                        # Execute Policy ---
                        self._handle_threat(file_path, virus_name)
                        return True

            except FileNotFoundError:
                pass
            except Exception as e:
                if "Broken pipe" not in str(e):
                    self.logger.error(f"Scan error on {file_path}: {e}")
                self.cd = None

        return False

    def _handle_threat(self, file_path, virus_name):
        """Executes the action chosen by the user in the installer."""
        if self.action_policy == 'delete':
            self._delete_file(file_path, virus_name)
        elif self.action_policy == 'quarantine':
            self._quarantine(file_path, virus_name)
        else:
            # Alert only
            self.logger.warning(f"Alert Only: Malicious file left in place: {file_path}")
            self.notifier.send_notification(
                "THREAT DETECTED",
                f"File: {os.path.basename(file_path)}\nAction: None (Alert Only)",
                level='critical'
            )

    def _delete_file(self, file_path, virus_name):
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
                self.logger.info(f"DELETED infected file: {file_path}")
                self.notifier.send_notification(
                    "VIRUS DELETED",
                    f"File: {os.path.basename(file_path)}\nThreat: {virus_name}"
                )
            else:
                self.logger.info(f"File vanished before deletion (Already removed): {file_path}")

        except OSError as e:
            # If file not found (Errno 2), it's a success (already gone)
            if e.errno == 2:
                self.logger.info(f"File vanished before deletion (Already removed): {file_path}")
            else:
                self.logger.error(f"Failed to delete {file_path}: {e}")
        except Exception as e:
            self.logger.error(f"Unexpected error deleting {file_path}: {e}")

    def _quarantine(self, file_path, virus_name):
        try:
            os.makedirs(self.quarantine_dir, exist_ok=True)

            file_name = os.path.basename(file_path)
            new_name = f"{file_name}_{int(time.time())}.infected"
            dest = os.path.join(self.quarantine_dir, new_name)

            shutil.move(file_path, dest)
            os.chmod(dest, 0o000)

            self.logger.info(f"Quarantined to: {dest}")
            self.notifier.send_notification(
                "VIRUS REMOVED",
                f"File: {file_name}\nThreat: {virus_name}"
            )

        except FileNotFoundError:
            # The file may vanish quickly (e.g., /tmp temp files). This is normal.
            self.logger.info(f"Quarantine skipped (file vanished): {file_path}")
            return
        except OSError as e:
            if getattr(e, 'errno', None) == 2:
                self.logger.info(f"Quarantine skipped (file vanished): {file_path}")
                return
            self.logger.error(f"Quarantine failed: {e}")
        except Exception as e:
            self.logger.error(f"Quarantine failed: {e}")
