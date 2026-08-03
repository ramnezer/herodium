from __future__ import annotations

import stat
import subprocess  # nosec B404 -- centralized fixed-tool execution only
from pathlib import Path
from typing import Final, Iterable


_TOOL_CANDIDATES: Final[dict[str, tuple[str, ...]]] = {
    "env": ("/usr/bin/env", "/bin/env"),
    "fail2ban-client": (
        "/usr/bin/fail2ban-client",
        "/usr/sbin/fail2ban-client",
    ),
    "ionice": ("/usr/bin/ionice", "/bin/ionice"),
    "notify-send": ("/usr/bin/notify-send",),
    "renice": ("/usr/bin/renice", "/bin/renice"),
    "runuser": ("/usr/sbin/runuser", "/usr/bin/runuser"),
    "sudo": ("/usr/bin/sudo",),
    "swapon": ("/usr/sbin/swapon", "/sbin/swapon"),
    "sysctl": ("/usr/sbin/sysctl", "/sbin/sysctl"),
    "systemctl": ("/usr/bin/systemctl", "/bin/systemctl"),
    "zramctl": ("/usr/sbin/zramctl", "/usr/bin/zramctl"),
}


class SystemCommandError(RuntimeError):
    """Base error for fixed local system-tool execution."""


class SystemToolUnavailableError(SystemCommandError):
    """Raised when an approved executable is not installed."""


class UntrustedSystemToolError(SystemCommandError):
    """Raised when an approved path resolves to an unsafe executable."""


def resolve_system_tool(tool_name: str) -> Path:
    """Resolve one allowlisted, root-owned, non-writable system executable."""
    candidates = _TOOL_CANDIDATES.get(tool_name)
    if candidates is None:
        raise SystemToolUnavailableError(
            f"system tool is not allowlisted: {tool_name}"
        )

    rejected: list[str] = []
    for raw_candidate in candidates:
        candidate = Path(raw_candidate)
        try:
            resolved = candidate.resolve(strict=True)
            metadata = resolved.stat()
        except OSError:
            continue

        if not stat.S_ISREG(metadata.st_mode):
            rejected.append(f"{resolved}: not a regular file")
            continue
        if metadata.st_uid != 0:
            rejected.append(f"{resolved}: not owned by root")
            continue
        if metadata.st_mode & 0o022:
            rejected.append(f"{resolved}: group/world writable")
            continue
        return resolved

    if rejected:
        raise UntrustedSystemToolError(
            f"no trusted executable for {tool_name}: " + "; ".join(rejected)
        )
    raise SystemToolUnavailableError(
        f"approved executable is unavailable: {tool_name}"
    )


def system_tool_available(tool_name: str) -> bool:
    """Return whether a trusted executable is available for an allowlisted tool."""
    try:
        resolve_system_tool(tool_name)
    except SystemCommandError:
        return False
    return True


def run_system_tool(
    tool_name: str,
    arguments: Iterable[object] = (),
    *,
    capture: bool = False,
    quiet: bool = False,
    timeout: float | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run a fixed local administration tool without invoking a shell."""
    if capture and quiet:
        raise ValueError("capture and quiet are mutually exclusive")

    executable = resolve_system_tool(tool_name)
    command = [str(executable), *(str(argument) for argument in arguments)]
    kwargs: dict[str, object] = {
        "check": False,
        "shell": False,
        "text": True,
    }
    if capture:
        kwargs["capture_output"] = True
    elif quiet:
        kwargs["stdout"] = subprocess.DEVNULL
        kwargs["stderr"] = subprocess.DEVNULL
    if timeout is not None:
        kwargs["timeout"] = timeout

    try:
        return subprocess.run(  # nosec B603 -- fixed allowlist and shell disabled
            command,
            **kwargs,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SystemCommandError(
            f"system tool execution failed: {tool_name}: {exc}"
        ) from exc
