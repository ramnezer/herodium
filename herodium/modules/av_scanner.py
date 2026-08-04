import os
import stat
import tempfile
import threading
import time
from dataclasses import dataclass
from enum import Enum
from typing import Optional

import pyclamd

from modules.notifier import Notifier


class ScanStatus(Enum):
    CLEAN = "clean"
    INFECTED = "infected"
    SKIPPED = "skipped"
    UNAVAILABLE = "unavailable"
    ERROR = "error"


class ScanReason(Enum):
    FILE_NOT_FOUND = "file_not_found"
    EMPTY_FILE = "empty_file"
    FILE_TOO_LARGE = "file_too_large"
    STAT_FAILED = "stat_failed"
    CLAMAV_UNAVAILABLE = "clamav_unavailable"
    READ_FAILED = "read_failed"
    SCAN_FAILED = "scan_failed"
    INVALID_RESPONSE = "invalid_response"


@dataclass(frozen=True)
class ScanResult:
    status: ScanStatus
    path: str
    reason: Optional[ScanReason] = None
    threat_name: Optional[str] = None
    detail: Optional[str] = None

    @property
    def completed(self):
        return self.status in (ScanStatus.CLEAN, ScanStatus.INFECTED)

    @property
    def retryable(self):
        return self.status in (ScanStatus.UNAVAILABLE, ScanStatus.ERROR)

    def __bool__(self):
        raise TypeError(
            "ScanResult has no implicit truth value; inspect result.status explicitly"
        )


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

    @staticmethod
    def _ping_succeeded(response):
        """Validate pyClamd and protocol-level PING responses."""
        if response is True:
            return True
        if isinstance(response, bytes):
            return response.strip().upper() == b'PONG'
        if isinstance(response, str):
            return response.strip().upper() == 'PONG'
        return False

    def _connect(self):
        self.cd = None
        try:
            client = pyclamd.ClamdUnixSocket(self.socket_path)
            ping_response = client.ping()
            if not self._ping_succeeded(ping_response):
                self.logger.error(
                    "ClamAV Connection Failed: invalid ping response "
                    f"{ping_response!r}"
                )
                return False
            self.cd = client
            self.logger.info("Connected to ClamAV Daemon.")
            return True
        except Exception as e:
            self.logger.error(f"ClamAV Connection Failed: {e}")
            return False

    def health_check(self):
        """Return True only when the configured clamd endpoint answers PING."""
        with self.lock:
            if self.cd is not None:
                try:
                    ping_response = self.cd.ping()
                except Exception as exc:
                    self.logger.error(f"ClamAV health check failed: {exc}")
                    self.cd = None
                else:
                    if self._ping_succeeded(ping_response):
                        return True
                    self.logger.error(
                        "ClamAV health check failed: invalid ping response "
                        f"{ping_response!r}"
                    )
                    self.cd = None

            return self._connect()

    def scan_file(self, file_path):
        path = os.fspath(file_path)

        try:
            size = os.path.getsize(path)
        except FileNotFoundError:
            return ScanResult(
                ScanStatus.SKIPPED, path, ScanReason.FILE_NOT_FOUND
            )
        except OSError as e:
            self.logger.error(f"Unable to inspect file before scanning {path}: {e}")
            return ScanResult(
                ScanStatus.ERROR, path, ScanReason.STAT_FAILED, detail=str(e)
            )

        if size == 0:
            return ScanResult(ScanStatus.SKIPPED, path, ScanReason.EMPTY_FILE)

        max_bytes = self.effective_max_file_size_mb * 1024 * 1024
        if size > max_bytes:
            return ScanResult(
                ScanStatus.SKIPPED,
                path,
                ScanReason.FILE_TOO_LARGE,
                detail=f"size={size}, limit={max_bytes}",
            )

        with self.lock:
            if not self.cd and not self._connect():
                return ScanResult(
                    ScanStatus.UNAVAILABLE, path, ScanReason.CLAMAV_UNAVAILABLE
                )

            try:
                with open(path, 'rb') as f:
                    file_content = f.read()
            except FileNotFoundError:
                return ScanResult(
                    ScanStatus.SKIPPED, path, ScanReason.FILE_NOT_FOUND
                )
            except OSError as e:
                self.logger.error(f"Unable to read file for scanning {path}: {e}")
                return ScanResult(
                    ScanStatus.ERROR, path, ScanReason.READ_FAILED, detail=str(e)
                )

            try:
                response = self.cd.scan_stream(file_content)
            except Exception as e:
                self.logger.error(f"ClamAV scan failed for {path}: {e}")
                self.cd = None
                return ScanResult(
                    ScanStatus.UNAVAILABLE,
                    path,
                    ScanReason.SCAN_FAILED,
                    detail=str(e),
                )

        return self._interpret_scan_response(path, response)

    def _interpret_scan_response(self, path, response):
        if response is None:
            return ScanResult(ScanStatus.CLEAN, path)

        if not isinstance(response, dict) or 'stream' not in response:
            self.logger.error(f"Invalid ClamAV response for {path}: {response!r}")
            return ScanResult(
                ScanStatus.ERROR,
                path,
                ScanReason.INVALID_RESPONSE,
                detail=repr(response),
            )

        stream_result = response['stream']
        if isinstance(stream_result, (list, tuple)):
            verdict = str(stream_result[0]).upper() if stream_result else ''
            detail = str(stream_result[1]) if len(stream_result) >= 2 else ''
        else:
            verdict = str(stream_result).upper()
            detail = str(stream_result)

        if verdict == 'OK':
            return ScanResult(ScanStatus.CLEAN, path)

        if verdict == 'FOUND':
            virus_name = detail or 'Unknown ClamAV signature'
            self.logger.critical(f"VIRUS DETECTED: {path} -> {virus_name}")
            self._handle_threat(path, virus_name)
            return ScanResult(
                ScanStatus.INFECTED, path, threat_name=virus_name
            )

        reason = (
            ScanReason.SCAN_FAILED
            if verdict == 'ERROR'
            else ScanReason.INVALID_RESPONSE
        )
        self.logger.error(f"ClamAV scan response error for {path}: {stream_result!r}")
        return ScanResult(
            ScanStatus.ERROR, path, reason, detail=detail or repr(stream_result)
        )

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
        dest = None
        dest_complete = False
        source_fd = None
        dest_fd = None

        try:
            try:
                initial_stat = os.lstat(file_path)
            except FileNotFoundError:
                self.logger.info(f"Quarantine skipped (file vanished): {file_path}")
                return

            if not stat.S_ISREG(initial_stat.st_mode):
                self.logger.error(
                    "Quarantine refused non-regular source path: "
                    f"{file_path}"
                )
                return

            if os.path.lexists(self.quarantine_dir):
                quarantine_stat = os.lstat(self.quarantine_dir)
                if not stat.S_ISDIR(quarantine_stat.st_mode):
                    raise OSError(
                        "quarantine path exists but is not a real directory: "
                        f"{self.quarantine_dir}"
                    )
            else:
                os.makedirs(self.quarantine_dir, mode=0o700, exist_ok=False)

            # The service runs as root. Normalize the directory on every use so
            # older installations cannot preserve permissive ownership or modes.
            os.chown(self.quarantine_dir, 0, 0)
            os.chmod(self.quarantine_dir, 0o700)

            source_flags = os.O_RDONLY
            source_flags |= getattr(os, "O_CLOEXEC", 0)
            source_flags |= getattr(os, "O_NOFOLLOW", 0)
            source_fd = os.open(file_path, source_flags)
            opened_stat = os.fstat(source_fd)

            if not stat.S_ISREG(opened_stat.st_mode):
                raise OSError(f"quarantine source is not a regular file: {file_path}")
            if (
                opened_stat.st_dev != initial_stat.st_dev
                or opened_stat.st_ino != initial_stat.st_ino
            ):
                raise OSError(f"quarantine source changed before capture: {file_path}")

            file_name = os.path.basename(file_path)
            prefix = f"{file_name}_{time.time_ns()}_{os.getpid()}_"
            dest_fd, dest = tempfile.mkstemp(
                prefix=prefix,
                suffix=".infected",
                dir=self.quarantine_dir,
            )

            while True:
                chunk = os.read(source_fd, 1024 * 1024)
                if not chunk:
                    break
                view = memoryview(chunk)
                while view:
                    written = os.write(dest_fd, view)
                    if written <= 0:
                        raise OSError("short write while creating quarantine copy")
                    view = view[written:]

            os.fchown(dest_fd, 0, 0)
            os.fchmod(dest_fd, 0o600)
            os.fsync(dest_fd)
            dest_complete = True

            os.close(dest_fd)
            dest_fd = None
            os.close(source_fd)
            source_fd = None

            try:
                current_stat = os.lstat(file_path)
            except FileNotFoundError:
                current_stat = None

            if current_stat is not None:
                if (
                    current_stat.st_dev != opened_stat.st_dev
                    or current_stat.st_ino != opened_stat.st_ino
                    or not stat.S_ISREG(current_stat.st_mode)
                ):
                    self.logger.error(
                        "Quarantine secured a private copy, but the source path "
                        f"changed before removal: {file_path}"
                    )
                    return
                os.unlink(file_path)

            self.logger.info(f"Quarantined to: {dest}")
            self.notifier.send_notification(
                "VIRUS REMOVED",
                f"File: {file_name}\nThreat: {virus_name}"
            )

        except FileNotFoundError:
            # The file may vanish quickly (e.g., /tmp temp files). This is normal.
            self.logger.info(f"Quarantine skipped (file vanished): {file_path}")
        except OSError as e:
            if getattr(e, 'errno', None) == 2:
                self.logger.info(f"Quarantine skipped (file vanished): {file_path}")
            else:
                self.logger.error(f"Quarantine failed: {e}")
        except Exception as e:
            self.logger.error(f"Quarantine failed: {e}")
        finally:
            if source_fd is not None:
                try:
                    os.close(source_fd)
                except OSError:
                    pass
            if dest_fd is not None:
                try:
                    os.close(dest_fd)
                except OSError:
                    pass
            if dest and not dest_complete:
                try:
                    os.unlink(dest)
                except FileNotFoundError:
                    pass
                except OSError as e:
                    self.logger.error(
                        f"Failed to remove incomplete quarantine copy {dest}: {e}"
                    )
