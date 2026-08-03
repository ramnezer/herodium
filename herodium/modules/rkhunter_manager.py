from __future__ import annotations

import fcntl
import os
import stat
import subprocess  # nosec B404 -- fixed local administration tool only
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Sequence


DEFAULT_RKHUNTER_CANDIDATES = (
    Path("/usr/bin/rkhunter"),
    Path("/usr/sbin/rkhunter"),
)
DEFAULT_LOCK_PATH = Path("/run/lock/herodium-rkhunter.lock")


@dataclass(frozen=True)
class RkhunterCommandResult:
    operation: str
    returncode: int
    stdout: str = ""
    stderr: str = ""
    lock_busy: bool = False

    @property
    def output(self) -> str:
        return "\n".join(
            part.strip()
            for part in (self.stdout, self.stderr)
            if part and part.strip()
        )


class RkhunterManager:
    def __init__(
        self,
        logger,
        *,
        executable_candidates: Sequence[Path] = DEFAULT_RKHUNTER_CANDIDATES,
        lock_path: Path = DEFAULT_LOCK_PATH,
        trusted_owner_uid: int = 0,
    ):
        self.logger = logger
        self.executable_candidates = tuple(
            Path(path) for path in executable_candidates
        )
        self.lock_path = Path(lock_path)
        self.trusted_owner_uid = int(trusted_owner_uid)

    def available(self) -> bool:
        try:
            self._resolve_executable()
        except (FileNotFoundError, PermissionError, OSError):
            return False
        return True

    def check(self) -> RkhunterCommandResult:
        return self._run_locked(
            "check",
            ("--check", "--sk", "--rwo", "--nocolors"),
        )

    def update_data(self) -> RkhunterCommandResult:
        return self._run_locked(
            "update",
            ("--update", "--nocolors"),
        )

    def update_properties(self) -> RkhunterCommandResult:
        return self._run_locked(
            "propupd",
            ("--propupd", "--nocolors"),
        )

    def review_then_update_properties(
        self,
    ) -> tuple[RkhunterCommandResult, RkhunterCommandResult | None]:
        try:
            with self._operation_lock(blocking=False):
                review = self._run_unlocked(
                    "check",
                    ("--check", "--sk", "--rwo", "--nocolors"),
                )
                if review.returncode not in (0, 1):
                    return review, None
                update = self._run_unlocked(
                    "propupd",
                    ("--propupd", "--nocolors"),
                )
                return review, update
        except BlockingIOError:
            busy = self._busy_result("check")
            return busy, None
        except (FileNotFoundError, PermissionError, OSError) as exc:
            failure = self._failure_result("check", exc)
            return failure, None

    def _run_locked(
        self,
        operation: str,
        arguments: Sequence[str],
    ) -> RkhunterCommandResult:
        try:
            with self._operation_lock(blocking=False):
                return self._run_unlocked(operation, arguments)
        except BlockingIOError:
            return self._busy_result(operation)
        except (FileNotFoundError, PermissionError, OSError) as exc:
            return self._failure_result(operation, exc)

    def _run_unlocked(
        self,
        operation: str,
        arguments: Sequence[str],
    ) -> RkhunterCommandResult:
        executable = self._resolve_executable()
        command = [str(executable), *map(str, arguments)]

        try:
            completed = subprocess.run(  # nosec B603 -- fixed verified executable, no shell
                command,
                shell=False,
                check=False,
                capture_output=True,
                text=True,
                timeout=7200,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return self._failure_result(operation, exc)

        return RkhunterCommandResult(
            operation=operation,
            returncode=int(completed.returncode),
            stdout=completed.stdout or "",
            stderr=completed.stderr or "",
        )

    def _resolve_executable(self) -> Path:
        errors: list[str] = []
        for candidate in self.executable_candidates:
            try:
                resolved = candidate.resolve(strict=True)
                metadata = resolved.stat()
            except OSError as exc:
                errors.append(f"{candidate}: {exc}")
                continue

            if not stat.S_ISREG(metadata.st_mode):
                errors.append(f"{candidate}: not a regular file")
                continue
            if metadata.st_uid != self.trusted_owner_uid:
                errors.append(
                    f"{candidate}: owner uid {metadata.st_uid} is not trusted"
                )
                continue
            if metadata.st_mode & 0o022:
                errors.append(f"{candidate}: group/other writable")
                continue
            if not os.access(resolved, os.X_OK):
                errors.append(f"{candidate}: not executable")
                continue
            return resolved

        detail = "; ".join(errors) or "no candidate paths configured"
        raise FileNotFoundError(f"trusted rkhunter executable unavailable: {detail}")

    @contextmanager
    def _operation_lock(self, *, blocking: bool) -> Iterator[None]:
        self.lock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW

        descriptor = os.open(self.lock_path, flags, 0o600)
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise OSError("rkhunter lock path is not a regular file")
            os.fchmod(descriptor, 0o600)

            operation = fcntl.LOCK_EX
            if not blocking:
                operation |= fcntl.LOCK_NB
            fcntl.flock(descriptor, operation)
            yield
        finally:
            os.close(descriptor)

    def _busy_result(self, operation: str) -> RkhunterCommandResult:
        message = "another rkhunter operation is already active"
        self.logger.warning(f"Rkhunter {operation} skipped: {message}")
        return RkhunterCommandResult(
            operation=operation,
            returncode=75,
            stderr=message,
            lock_busy=True,
        )

    def _failure_result(
        self,
        operation: str,
        error: BaseException,
    ) -> RkhunterCommandResult:
        message = str(error)
        self.logger.error(f"Rkhunter {operation} failed: {message}")
        return RkhunterCommandResult(
            operation=operation,
            returncode=127,
            stderr=message,
        )
