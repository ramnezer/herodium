from __future__ import annotations

from collections.abc import MutableMapping
from typing import Any

HARDENED_MEMORY_HUNTER_DEFAULT_WHITELIST = (
    "/usr/lib/systemd/systemd",
    "/usr/lib/systemd/systemd-journald",
    "/usr/sbin/clamd",
    "/usr/bin/gnome-shell",
    "/usr/lib/xorg/Xorg",
)

_LEGACY_MEMORY_HUNTER_DEFAULT_WHITELISTS = (
    frozenset(
        {
            "chrome",
            "firefox",
            "code",
            "gnome-shell",
            "systemd",
        }
    ),
    frozenset(
        {
            "chrome",
            "firefox",
            "code",
            "gnome-shell",
            "clamd",
            "systemd",
            "init",
            "systemd-journald",
        }
    ),
)


def migrate_memory_hunter_whitelist(config: MutableMapping[str, Any]) -> bool:
    """Migrate only known legacy default Memory Hunter whitelists.

    Custom or mixed whitelists are intentionally left unchanged. The runtime
    rejects unsafe name-only entries fail-closed, so the installer must not
    guess paths for operator-managed configuration.
    """

    memory_scan = config.get("memory_scan")
    if not isinstance(memory_scan, MutableMapping):
        return False

    whitelist = memory_scan.get("whitelist")
    if not isinstance(whitelist, list) or not whitelist:
        return False
    if not all(isinstance(item, str) for item in whitelist):
        return False

    legacy_entries = frozenset(whitelist)
    if len(legacy_entries) != len(whitelist):
        return False
    if legacy_entries not in _LEGACY_MEMORY_HUNTER_DEFAULT_WHITELISTS:
        return False

    memory_scan["whitelist"] = list(HARDENED_MEMORY_HUNTER_DEFAULT_WHITELIST)
    return True
