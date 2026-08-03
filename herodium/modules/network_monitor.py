import csv
import ipaddress
import os
import re
import socket
import subprocess  # nosec B404 -- required for fixed, local system tools
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import urlsplit

from modules.notifier import Notifier


_MALTRAIL_FIELD_COUNT = 11
_BLOCKABLE_TRAIL_TYPES = frozenset({"DNS", "HTTP", "IP", "IPORT", "URL"})
_DOMAIN_LABEL_PATTERN = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)
_SYSTEM_TOOL_CANDIDATES = {
    "ip": ("/usr/sbin/ip", "/sbin/ip"),
    "ipset": ("/usr/sbin/ipset", "/sbin/ipset"),
    "iptables": ("/usr/sbin/iptables", "/sbin/iptables"),
    "ip6tables": ("/usr/sbin/ip6tables", "/sbin/ip6tables"),
}


@dataclass(frozen=True)
class MaltrailEvent:
    timestamp: str
    sensor: str
    src_ip: str
    src_port: str
    dst_ip: str
    dst_port: str
    proto: str
    trail_type: str
    trail: str
    trail_info: str
    reference: str


class NetworkMonitor:
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger
        maltrail_cfg = (config.get('maltrail', {}) or {})
        self.log_dir = "/var/log/maltrail"
        self.log_path = str(maltrail_cfg.get('log_path') or '')

        # Enable flag (installer choice)
        self.enabled = maltrail_cfg.get('enable', False)

        # Read the user preference properly
        self.blocking_enabled = config.get('maltrail', {}).get('block_traffic', False)

        self.ipset_v4 = "herodium_blacklist"
        self.ipset_v6 = "herodium_blacklist_v6"
        self._system_tools = self._resolve_system_tools()

        # Anti-Trolling Initialization
        self.static_whitelist = set()
        conf_whitelist = config.get('maltrail', {}).get('whitelist', [])
        for ip in conf_whitelist:
            try:
                self.static_whitelist.add(ipaddress.ip_address(ip))
            except ValueError:
                self.logger.warning("Ignoring invalid Maltrail whitelist IP: %r", ip)

        self.static_whitelist.add(ipaddress.ip_address("127.0.0.1"))
        self.static_whitelist.add(ipaddress.ip_address("::1"))

        self.dynamic_whitelist = set()
        self.running = False

        # Initialize the universal notifier
        self.notifier = Notifier(config, logger, scope="maltrail")

        # Coalesce repeated Maltrail alerts (for example repeated DNS NXDOMAIN
        # events) so a single IOC cannot flood the desktop or operator logs.
        self.alert_cooldown_seconds = self._bounded_int(
            maltrail_cfg.get("alert_cooldown_seconds"),
            default=300,
            minimum=0,
            maximum=86400,
        )
        self.alert_cache_max_entries = self._bounded_int(
            maltrail_cfg.get("alert_cache_max_entries"),
            default=1024,
            minimum=16,
            maximum=65536,
        )
        self._alert_lock = threading.Lock()
        self._alert_state = OrderedDict()

        # Cache DNS results (including NXDOMAIN) so a flood of identical
        # Maltrail DNS events cannot hold the single log-consumer thread in
        # repeated resolver calls and delay a later blockable IP event.
        self.dns_resolution_cache_seconds = self._bounded_int(
            maltrail_cfg.get("dns_resolution_cache_seconds"),
            default=300,
            minimum=0,
            maximum=86400,
        )
        self.dns_resolution_cache_max_entries = self._bounded_int(
            maltrail_cfg.get("dns_resolution_cache_max_entries"),
            default=1024,
            minimum=16,
            maximum=65536,
        )
        self._dns_cache_lock = threading.Lock()
        self._dns_resolution_cache = OrderedDict()

        # Optional scheduled cleanup of ipset blacklists (hours). 0 disables.
        try:
            self.clean_interval_hours = int(
                (self.config.get("maltrail", {}) or {}).get(
                    "clean_interval_hours",
                    0,
                )
                or 0
            )
        except (TypeError, ValueError):
            self.logger.warning(
                "Invalid maltrail.clean_interval_hours value; cleanup disabled."
            )
            self.clean_interval_hours = 0

    @staticmethod
    def _bounded_int(value, *, default, minimum, maximum):
        if isinstance(value, bool):
            return default
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            return default
        return max(minimum, min(maximum, parsed))

    @staticmethod
    def _alert_now():
        return time.monotonic()

    @staticmethod
    def _dns_now():
        return time.monotonic()

    def _allow_alert(self, key):
        """Return (emit, suppressed_count) for one bounded alert key.

        The cooldown is sliding: continuous duplicates extend the quiet window
        instead of producing another desktop alert every N seconds.
        """
        now = self._alert_now()
        with self._alert_lock:
            previous = self._alert_state.pop(key, None)
            if previous is not None:
                last_seen, suppressed = previous
                if now - last_seen < self.alert_cooldown_seconds:
                    self._alert_state[key] = (now, suppressed + 1)
                    return False, 0
            else:
                suppressed = 0

            self._alert_state[key] = (now, 0)
            while len(self._alert_state) > self.alert_cache_max_entries:
                self._alert_state.popitem(last=False)
            return True, suppressed

    def _emit_alert(self, key, log_message, title, message, level="critical"):
        emit, suppressed = self._allow_alert(key)
        if not emit:
            self.logger.debug("Suppressed duplicate Maltrail alert: %r", key)
            return False

        if suppressed:
            log_message = (
                f"{log_message} (suppressed_duplicates={suppressed})"
            )
            message = (
                f"{message} ({suppressed} duplicate alert(s) suppressed)"
            )

        self.logger.warning(log_message)
        self.notifier.send_notification(
            title,
            message,
            level=level,
        )
        return True

    @staticmethod
    def _resolve_system_tools():
        resolved = {}
        for tool_name, candidates in _SYSTEM_TOOL_CANDIDATES.items():
            resolved[tool_name] = next(
                (
                    candidate
                    for candidate in candidates
                    if os.path.isfile(candidate) and os.access(candidate, os.X_OK)
                ),
                None,
            )
        return resolved

    def _run_system_tool(self, tool_name, arguments, **kwargs):
        tool_path = self._system_tools.get(tool_name)
        if tool_path is None:
            raise FileNotFoundError(
                f"Required system tool is unavailable: {tool_name}"
            )

        command = [tool_path, *(str(argument) for argument in arguments)]
        return subprocess.run(command, shell=False, **kwargs)  # nosec B603

    def start_monitoring(self):
        if not self.enabled:
            self.logger.info("Maltrail Network Monitor is DISABLED in config.")
            return False

        self.running = True
        self._refresh_critical_infrastructure()
        startup_healthy = True

        try:
            if self.blocking_enabled:
                # Blocking mode is explicitly enabled by the installer/config.
                # Only in this mode Herodium creates ipsets and firewall rules.
                for arguments in (
                    ["create", self.ipset_v4, "hash:ip", "family", "inet", "-exist"],
                    ["create", self.ipset_v6, "hash:ip", "family", "inet6", "-exist"],
                ):
                    result = self._run_system_tool(
                        "ipset",
                        arguments,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        check=False,
                    )
                    startup_healthy = startup_healthy and result.returncode == 0

                has_ip6tables = self._system_tools.get("ip6tables") is not None

                for chain in ("INPUT", "OUTPUT"):
                    startup_healthy = (
                        self._ensure_fw_rule(
                            "iptables", chain, self.ipset_v4, "src"
                        )
                        and startup_healthy
                    )
                    startup_healthy = (
                        self._ensure_fw_rule(
                            "iptables", chain, self.ipset_v4, "dst"
                        )
                        and startup_healthy
                    )

                    if has_ip6tables:
                        startup_healthy = (
                            self._ensure_fw_rule(
                                "ip6tables", chain, self.ipset_v6, "src"
                            )
                            and startup_healthy
                        )
                        startup_healthy = (
                            self._ensure_fw_rule(
                                "ip6tables", chain, self.ipset_v6, "dst"
                            )
                            and startup_healthy
                        )

                if not has_ip6tables:
                    startup_healthy = False
                    self.logger.warning(
                        "ip6tables not found; IPv6 blocking will not be enforced."
                    )

                protected_count = len(self.static_whitelist) + len(
                    self.dynamic_whitelist
                )
                self.logger.info(
                    "Network Monitor Active (BLOCKING MODE). Protected IPs: %d",
                    protected_count,
                )
            else:
                self.logger.info(
                    "Network Monitor Active (ALERT ONLY). "
                    "No ipset or firewall changes applied."
                )

            updater = threading.Thread(
                target=self._infrastructure_updater,
                daemon=True,
                name="herodium-maltrail-infrastructure",
            )
            tailer = threading.Thread(
                target=self._tail_loop,
                daemon=True,
                name="herodium-maltrail-tail",
            )
            updater.start()
            tailer.start()

            threads = [updater, tailer]
            if self.blocking_enabled and self.clean_interval_hours > 0:
                self.logger.info(
                    "IPSet cleanup enabled: every %s hour(s)",
                    self.clean_interval_hours,
                )
                cleaner = threading.Thread(
                    target=self._clean_ipset_loop,
                    daemon=True,
                    name="herodium-maltrail-cleaner",
                )
                cleaner.start()
                threads.append(cleaner)

            return startup_healthy and all(thread.is_alive() for thread in threads)
        except (OSError, RuntimeError, ValueError) as exc:
            self.running = False
            self.logger.error(f"Network Monitor startup failed: {exc}")
            return False

    def _ensure_fw_rule(self, tool_name, chain, set_name, direction):
        """Check and add one fixed iptables/ip6tables set-matching rule."""
        try:
            check_result = self._run_system_tool(
                tool_name,
                [
                    "-C",
                    chain,
                    "-m",
                    "set",
                    "--match-set",
                    set_name,
                    direction,
                    "-j",
                    "DROP",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )

            if check_result.returncode == 0:
                return True

            insert_result = self._run_system_tool(
                tool_name,
                [
                    "-I",
                    chain,
                    "1",
                    "-m",
                    "set",
                    "--match-set",
                    set_name,
                    direction,
                    "-j",
                    "DROP",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            return insert_result.returncode == 0
        except OSError as exc:
            self.logger.error(
                "Failed to update %s for %s/%s: %s",
                tool_name,
                chain,
                direction,
                exc,
            )
            return False

    def _refresh_critical_infrastructure(self):
        new_dynamic = set()
        try:
            import psutil

            for snics in psutil.net_if_addrs().values():
                for snic in snics:
                    try:
                        new_dynamic.add(ipaddress.ip_address(snic.address))
                    except ValueError:
                        self.logger.debug(
                            "Ignoring non-IP interface address: %r",
                            snic.address,
                        )

            result = self._run_system_tool(
                "ip",
                ["route", "show", "default"],
                capture_output=True,
                text=True,
                check=False,
            )
            match = re.search(r"default via ([0-9.]+)", result.stdout)
            if match:
                try:
                    new_dynamic.add(ipaddress.ip_address(match.group(1)))
                except ValueError:
                    self.logger.warning(
                        "Ignoring invalid default gateway address: %r",
                        match.group(1),
                    )

            resolv_path = "/etc/resolv.conf"
            if os.path.exists(resolv_path):
                with open(resolv_path, "r", encoding="utf-8") as handle:
                    for line in handle:
                        if not line.startswith("nameserver"):
                            continue
                        parts = line.split()
                        if len(parts) < 2:
                            continue
                        try:
                            new_dynamic.add(ipaddress.ip_address(parts[1]))
                        except ValueError:
                            self.logger.warning(
                                "Ignoring invalid resolver address: %r",
                                parts[1],
                            )

            self.dynamic_whitelist = new_dynamic
        except (OSError, RuntimeError) as exc:
            self.logger.error(
                "Failed to refresh network infrastructure whitelist: %s",
                exc,
            )

    def _infrastructure_updater(self):
        while self.running:
            time.sleep(60)
            self._refresh_critical_infrastructure()

    def _tail_loop(self):
        current_file = None
        f = None
        while self.running:
            try:
                today = datetime.now().strftime('%Y-%m-%d')

                if self.log_path and os.path.isfile(self.log_path):
                    log_path = self.log_path
                else:
                    log_path = f"{self.log_dir}/{today}.log"

                if log_path != current_file:
                    if f:
                        f.close()
                    if os.path.exists(log_path):
                        f = open(log_path, 'r')
                        f.seek(0, 2)
                        current_file = log_path
                        self.logger.info(f"Tracking log file: {log_path}")
                    else:
                        time.sleep(2)
                        continue

                line = f.readline()
                if line:
                    self._process_line(line)
                else:
                    time.sleep(0.1)
            except Exception as exc:
                self.logger.error("Maltrail log tail error: %s", exc)
                time.sleep(1)

    @staticmethod
    def _parse_maltrail_line(line):
        """Parse one Maltrail event line using Maltrail's quoted space format."""
        if not isinstance(line, str):
            return None

        raw_line = line.rstrip("\r\n")
        if not raw_line:
            return None

        try:
            fields = next(
                csv.reader(
                    [raw_line],
                    delimiter=" ",
                    quotechar='"',
                    doublequote=True,
                    skipinitialspace=True,
                    strict=True,
                )
            )
        except (csv.Error, StopIteration):
            return None

        if len(fields) != _MALTRAIL_FIELD_COUNT:
            return None

        try:
            datetime.strptime(fields[0], "%Y-%m-%d %H:%M:%S.%f")
        except ValueError:
            return None

        return MaltrailEvent(*fields)

    @staticmethod
    def _normalize_domain(value):
        """Return a normalized DNS hostname, or None for an unsafe value."""
        candidate = value.strip().rstrip(".").lower()
        if not candidate or "." not in candidate or len(candidate) > 253:
            return None

        try:
            candidate = candidate.encode("idna").decode("ascii")
        except UnicodeError:
            return None

        labels = candidate.split(".")
        if any(not _DOMAIN_LABEL_PATTERN.fullmatch(label) for label in labels):
            return None

        return candidate

    @staticmethod
    def _remove_maltrail_markers(value):
        """Remove Maltrail's parentheses used to mark matched trail fragments."""
        return (
            value.replace(r"\(", "(")
            .replace(r"\)", ")")
            .replace("(", "")
            .replace(")", "")
            .strip()
        )

    @classmethod
    def _extract_ip_from_trail(cls, trail):
        cleaned = cls._remove_maltrail_markers(trail)
        first_token = cleaned.split(None, 1)[0] if cleaned else ""
        if not first_token:
            return None

        try:
            direct_ip = str(ipaddress.ip_address(first_token))
        except ValueError:
            direct_ip = None

        if direct_ip is not None:
            return direct_ip

        try:
            host = urlsplit(f"//{first_token}").hostname
        except ValueError:
            return None

        if not host:
            return None

        try:
            return str(ipaddress.ip_address(host.split("%", 1)[0]))
        except ValueError:
            return None

    @classmethod
    def _extract_host_from_trail(cls, trail_type, trail):
        normalized_type = trail_type.strip().upper()
        if normalized_type not in _BLOCKABLE_TRAIL_TYPES:
            return None

        if normalized_type in {"IP", "IPORT"}:
            ip_value = cls._extract_ip_from_trail(trail)
            return ("ip", ip_value) if ip_value else None

        cleaned = cls._remove_maltrail_markers(trail)
        if not cleaned:
            return None

        if normalized_type == "DNS":
            domain = cls._normalize_domain(cleaned)
            return ("domain", domain) if domain else None

        try:
            parsed = urlsplit(cleaned if "://" in cleaned else f"//{cleaned}")
        except ValueError:
            return None

        host = parsed.hostname
        if not host:
            return None

        host = host.split("%", 1)[0]
        try:
            return ("ip", str(ipaddress.ip_address(host)))
        except ValueError:
            domain = cls._normalize_domain(host)
            return ("domain", domain) if domain else None

    def _process_line(self, line):
        event = self._parse_maltrail_line(line)
        if event is None:
            self.logger.debug("Ignored malformed Maltrail log entry.")
            return

        target = self._extract_host_from_trail(event.trail_type, event.trail)
        if target is None:
            self._alert_without_blocking(event)
            return

        target_kind, target_value = target
        if target_kind == "ip":
            self._block(target_value)
        elif not self._resolve_and_block(target_value):
            self._alert_without_blocking(event)

    def _alert_without_blocking(self, event):
        normalized_type = event.trail_type.strip().upper()
        trail_display = event.trail[:200]
        alert_key = (
            "not-blocked",
            normalized_type,
            event.trail.strip().casefold(),
        )
        self._emit_alert(
            alert_key,
            (
                "MALTRAIL DETECTION (NOT BLOCKED): "
                f"type={normalized_type} trail={trail_display} "
                f"info={event.trail_info[:200]}"
            ),
            "Maltrail Detection",
            f"Detected {normalized_type}: {trail_display} (Not Blocked)",
        )

    def _get_cached_dns_addresses(self, domain):
        if self.dns_resolution_cache_seconds <= 0:
            return None

        now = self._dns_now()
        with self._dns_cache_lock:
            cached = self._dns_resolution_cache.pop(domain, None)
            if cached is None:
                return None

            expires_at, addresses = cached
            if now >= expires_at:
                return None

            self._dns_resolution_cache[domain] = (expires_at, addresses)
            return addresses

    def _cache_dns_addresses(self, domain, addresses):
        if self.dns_resolution_cache_seconds <= 0:
            return

        expires_at = self._dns_now() + self.dns_resolution_cache_seconds
        with self._dns_cache_lock:
            self._dns_resolution_cache.pop(domain, None)
            self._dns_resolution_cache[domain] = (expires_at, addresses)
            while (
                len(self._dns_resolution_cache)
                > self.dns_resolution_cache_max_entries
            ):
                self._dns_resolution_cache.popitem(last=False)

    def _resolve_and_block(self, domain):
        normalized_domain = self._normalize_domain(domain)
        if normalized_domain is None:
            self.logger.debug("Ignored invalid Maltrail domain trail: %r", domain)
            return False

        resolved_addresses = self._get_cached_dns_addresses(normalized_domain)
        if resolved_addresses is None:
            try:
                results = socket.getaddrinfo(normalized_domain, None)
            except socket.gaierror as exc:
                self.logger.debug(
                    "Could not resolve Maltrail domain %s: %s",
                    normalized_domain,
                    exc,
                )
                resolved_addresses = ()
                self._cache_dns_addresses(
                    normalized_domain,
                    resolved_addresses,
                )
            except OSError as exc:
                self.logger.error(
                    "Resolver failure for Maltrail domain %s: %s",
                    normalized_domain,
                    exc,
                )
                return False
            else:
                unique_addresses = set()
                for result in results:
                    sockaddr = result[4]
                    if not sockaddr:
                        continue

                    raw_address = str(sockaddr[0]).split("%", 1)[0]
                    try:
                        unique_addresses.add(
                            ipaddress.ip_address(raw_address)
                        )
                    except ValueError:
                        self.logger.debug(
                            "Resolver returned an invalid address for %s: %r",
                            normalized_domain,
                            raw_address,
                        )

                resolved_addresses = tuple(
                    sorted(
                        unique_addresses,
                        key=lambda item: (item.version, int(item)),
                    )
                )
                self._cache_dns_addresses(
                    normalized_domain,
                    resolved_addresses,
                )

        for address in resolved_addresses:
            self._block(str(address))

        return bool(resolved_addresses)

    def _block(self, ip):
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            self.logger.error("Refused invalid Maltrail IP target: %r", ip)
            return

        if ip_obj in self.static_whitelist or ip_obj in self.dynamic_whitelist:
            return

        if ip_obj.is_private or ip_obj.is_loopback or str(ip_obj) == "0.0.0.0":
            return

        if not self.blocking_enabled:
            self._emit_alert(
                ("alert-only-ip", str(ip_obj)),
                f"DETECTED MALICIOUS IP (Alert Only): {ip_obj}",
                "Herodium Alert",
                f"Detected: {ip_obj} (Not Blocked)",
            )
            return

        set_name = self.ipset_v4 if ip_obj.version == 4 else self.ipset_v6
        try:
            result = self._run_system_tool(
                "ipset",
                ["add", set_name, str(ip_obj)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
        except OSError as exc:
            self.logger.error("Failed to execute ipset for %s: %s", ip_obj, exc)
            return

        if result.returncode == 0:
            # A successful ipset add is the authoritative state transition:
            # the address was absent and has now entered the blacklist. Do not
            # pass this event through the time-based alert cooldown. Duplicate
            # detections while the address remains a member already return a
            # non-zero status from ipset, while a later external/scheduled flush
            # allows a fresh add and therefore deserves a fresh notification.
            self.logger.warning("BLOCKED MALICIOUS IP: %s", ip_obj)
            self.notifier.send_notification(
                "Maltrail Detection",
                f"Blocked Threat: {ip_obj}",
                level="critical",
            )

    def _clean_ipset_loop(self):
        """Periodically flush Herodium ipset blacklists to reduce false positives."""
        interval_h = self.clean_interval_hours
        if not interval_h or interval_h <= 0:
            return

        # Sleep in small steps so stop_monitoring() can exit quickly
        sleep_step = 5
        interval_s = int(interval_h * 3600)

        while self.running:
            remaining = interval_s
            while self.running and remaining > 0:
                time.sleep(sleep_step if remaining > sleep_step else remaining)
                remaining -= sleep_step

            if not self.running:
                break

            try:
                self._run_system_tool(
                    "ipset",
                    ["flush", self.ipset_v4],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
                self._run_system_tool(
                    "ipset",
                    ["flush", self.ipset_v6],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
                self.logger.info("IPSet blacklist flushed (scheduled cleanup)")
            except OSError as exc:
                self.logger.error("IPSet cleanup failed: %s", exc)

    def stop_monitoring(self):
        self.running = False
