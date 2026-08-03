from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Iterable, Tuple


class SystemHealth(Enum):
    PROTECTED = "PROTECTED"
    DEGRADED = "DEGRADED"
    FAILED = "FAILED"


class ComponentState(Enum):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    FAILED = "FAILED"
    DISABLED_BY_POLICY = "DISABLED_BY_POLICY"


@dataclass(frozen=True)
class ComponentHealth:
    name: str
    state: ComponentState
    required: bool = False
    detail: str = ""


@dataclass(frozen=True)
class HealthReport:
    components: Tuple[ComponentHealth, ...]

    @classmethod
    def from_components(cls, components: Iterable[ComponentHealth]):
        return cls(tuple(components))

    @property
    def state(self):
        if any(
            component.required and component.state is ComponentState.FAILED
            for component in self.components
        ):
            return SystemHealth.FAILED

        if any(
            component.state in (ComponentState.DEGRADED, ComponentState.FAILED)
            for component in self.components
        ):
            return SystemHealth.DEGRADED

        return SystemHealth.PROTECTED

    @property
    def failed_required(self):
        return tuple(
            component
            for component in self.components
            if component.required and component.state is ComponentState.FAILED
        )

    @property
    def impaired(self):
        return tuple(
            component
            for component in self.components
            if component.state in (ComponentState.DEGRADED, ComponentState.FAILED)
        )

    def component(self, name):
        for component in self.components:
            if component.name == name:
                return component
        raise KeyError(name)


class StartupHealthManager:
    """Collect and publish deterministic startup health for Herodium."""

    def __init__(
        self,
        *,
        config,
        logger,
        scanner,
        zram_manager,
        apparmor_manager,
        ips_manager,
        hardener,
        scheduler,
        network_monitor,
        performance_manager,
        filesystem_monitor,
        start_memory_hunter,
    ):
        self.config = config
        self.logger = logger
        self.scanner = scanner
        self.zram_manager = zram_manager
        self.apparmor_manager = apparmor_manager
        self.ips_manager = ips_manager
        self.hardener = hardener
        self.scheduler = scheduler
        self.network_monitor = network_monitor
        self.performance_manager = performance_manager
        self.filesystem_monitor = filesystem_monitor
        self.start_memory_hunter = start_memory_hunter

    @staticmethod
    def _safe_bool(value, default=False):
        if isinstance(value, bool):
            return value
        if isinstance(value, int) and value in (0, 1):
            return bool(value)
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in ("1", "true", "yes", "on"):
                return True
            if normalized in ("0", "false", "no", "off"):
                return False
        return default

    def _config_bool(self, section, key, default=False):
        section_config = self.config.get(section, {}) or {}
        return self._safe_bool(section_config.get(key), default)

    def _run_operation(self, label, operation):
        try:
            result = operation()
        except Exception as exc:
            self.logger.error(f"{label} startup failed: {exc}")
            return False
        return result is not False

    @staticmethod
    def _ips_socket_active():
        return any(
            path.is_socket()
            for path in (
                Path("/run/fail2ban/fail2ban.sock"),
                Path("/var/run/fail2ban/fail2ban.sock"),
            )
        )

    def _hardening_matches_policy(self):
        rules = self.config.get("hardening", {}).get("rules", {}) or {}
        if not isinstance(rules, dict):
            return False

        for key, expected in rules.items():
            proc_path = Path("/proc/sys") / str(key).replace(".", "/")
            try:
                actual = proc_path.read_text(encoding="utf-8").strip()
            except OSError:
                return False
            if actual != str(expected).strip():
                return False
        return True

    def collect(self, *, live_monitor_enabled, maltrail_enabled):
        components = []

        clamav_healthy = self.scanner.health_check()
        components.append(
            ComponentHealth(
                "clamav",
                ComponentState.HEALTHY
                if clamav_healthy
                else ComponentState.FAILED,
                required=True,
                detail=(
                    "clamd endpoint answered PING"
                    if clamav_healthy
                    else "clamd endpoint is unavailable"
                ),
            )
        )
        if not clamav_healthy:
            return HealthReport.from_components(components)

        self._collect_zram(components)
        self._collect_apparmor(components)
        self._collect_ips(components)
        self._collect_hardening(components)
        self._collect_scheduler(components)
        self._collect_maltrail(components, maltrail_enabled)
        self._collect_performance_manager(components)
        self._collect_live_monitor(components, live_monitor_enabled)
        return HealthReport.from_components(components)

    def _collect_zram(self, components):
        if not self._config_bool("performance", "enable_zram", False):
            components.append(
                ComponentHealth(
                    "zram",
                    ComponentState.DISABLED_BY_POLICY,
                    detail="disabled in configuration",
                )
            )
            return

        started = self._run_operation("ZRAM", self.zram_manager.enable)
        healthy = started and self.zram_manager._is_active()
        components.append(
            ComponentHealth(
                "zram",
                ComponentState.HEALTHY
                if healthy
                else ComponentState.DEGRADED,
                detail=(
                    "zram swap is active"
                    if healthy
                    else "zram was requested but is not active"
                ),
            )
        )

    def _collect_apparmor(self, components):
        healthy = self._run_operation(
            "AppArmor", self.apparmor_manager.apply_policy
        )
        components.append(
            ComponentHealth(
                "apparmor",
                ComponentState.HEALTHY
                if healthy
                else ComponentState.DEGRADED,
                detail=(
                    "configured policy was verified"
                    if healthy
                    else "configured policy could not be verified"
                ),
            )
        )

    def _collect_ips(self, components):
        if not self._config_bool("ips", "enable", False):
            components.append(
                ComponentHealth(
                    "ips",
                    ComponentState.DISABLED_BY_POLICY,
                    detail="disabled in configuration",
                )
            )
            return

        started = self._run_operation("IPS", self.ips_manager.start)
        healthy = started and self._ips_socket_active()
        components.append(
            ComponentHealth(
                "ips",
                ComponentState.HEALTHY
                if healthy
                else ComponentState.DEGRADED,
                detail=(
                    "Fail2Ban socket is active"
                    if healthy
                    else "Fail2Ban was requested but its socket is unavailable"
                ),
            )
        )

    def _collect_hardening(self, components):
        if not self._config_bool("hardening", "enable", False):
            components.append(
                ComponentHealth(
                    "hardening",
                    ComponentState.DISABLED_BY_POLICY,
                    detail="disabled in configuration",
                )
            )
            return

        started = self._run_operation(
            "System hardening", self.hardener.apply_security_rules
        )
        healthy = started and self._hardening_matches_policy()
        components.append(
            ComponentHealth(
                "hardening",
                ComponentState.HEALTHY
                if healthy
                else ComponentState.DEGRADED,
                detail=(
                    "configured kernel rules are active"
                    if healthy
                    else "one or more configured kernel rules are inactive"
                ),
            )
        )

    def _collect_scheduler(self, components):
        if not self._config_bool("scheduler", "enable", True):
            components.append(
                ComponentHealth(
                    "scheduler",
                    ComponentState.DISABLED_BY_POLICY,
                    detail="disabled in configuration",
                )
            )
            return

        started = self._run_operation("Task Scheduler", self.scheduler.start)
        components.append(
            ComponentHealth(
                "scheduler",
                ComponentState.HEALTHY
                if started
                else ComponentState.DEGRADED,
                detail=(
                    "scheduler startup completed"
                    if started
                    else "scheduler startup failed"
                ),
            )
        )

    def _collect_maltrail(self, components, enabled):
        if not enabled:
            self.logger.info(
                "Network Monitor (Maltrail) is DISABLED in config."
            )
            components.append(
                ComponentHealth(
                    "maltrail",
                    ComponentState.DISABLED_BY_POLICY,
                    detail="disabled in configuration",
                )
            )
            return

        healthy = self._run_operation(
            "Network Monitor", self.network_monitor.start_monitoring
        )
        components.append(
            ComponentHealth(
                "maltrail",
                ComponentState.HEALTHY
                if healthy
                else ComponentState.DEGRADED,
                detail=(
                    "configured monitor threads and enforcement started"
                    if healthy
                    else "configured network monitoring is incomplete"
                ),
            )
        )

    def _collect_performance_manager(self, components):
        started = self._run_operation(
            "Performance Manager", self.performance_manager.start
        )
        components.append(
            ComponentHealth(
                "performance_manager",
                ComponentState.HEALTHY
                if started
                else ComponentState.DEGRADED,
                detail=(
                    "controller startup completed"
                    if started
                    else "controller startup failed"
                ),
            )
        )

    def _collect_live_monitor(self, components, enabled):
        if not enabled:
            self.logger.info(
                "Live Monitor is DISABLED in config. "
                "FS/USB/Memory scanning will not run."
            )
            for name in ("filesystem_monitor", "memory_hunter"):
                components.append(
                    ComponentHealth(
                        name,
                        ComponentState.DISABLED_BY_POLICY,
                        detail="disabled by live_monitor policy",
                    )
                )
            return

        filesystem_healthy = self._run_operation(
            "File System Monitor", self.filesystem_monitor.run
        )
        components.append(
            ComponentHealth(
                "filesystem_monitor",
                ComponentState.HEALTHY
                if filesystem_healthy
                else ComponentState.FAILED,
                required=True,
                detail=(
                    "observer and scanner worker are active"
                    if filesystem_healthy
                    else "observer or scanner worker failed to start"
                ),
            )
        )

        memory_healthy = (
            self.start_memory_hunter() if filesystem_healthy else False
        )
        components.append(
            ComponentHealth(
                "memory_hunter",
                ComponentState.HEALTHY
                if memory_healthy
                else ComponentState.FAILED,
                required=True,
                detail=(
                    "memory scanner thread is active"
                    if memory_healthy
                    else "memory scanner thread failed to start"
                ),
            )
        )

    def emit(self, report, notifier):
        for component in report.components:
            message = (
                "Health component: "
                f"name={component.name}, state={component.state.value}, "
                f"required={str(component.required).lower()}, "
                f"detail={component.detail}"
            )
            if component.state is ComponentState.FAILED:
                self.logger.error(message)
            elif component.state is ComponentState.DEGRADED:
                self.logger.warning(message)
            else:
                self.logger.info(message)

        if report.state is SystemHealth.PROTECTED:
            self.logger.info("System is PROTECTED. Monitoring active...")
            notifier.send_notification(
                "Herodium Security",
                "System is Active and Protected.",
                level="normal",
            )
            return

        impaired_names = ", ".join(
            component.name for component in report.impaired
        )
        if report.state is SystemHealth.DEGRADED:
            self.logger.warning(
                "System is DEGRADED. Impaired components: %s",
                impaired_names,
            )
            notifier.send_notification(
                "Herodium Security",
                f"System is DEGRADED. Check: {impaired_names}",
                level="critical",
            )
            return

        failed_names = ", ".join(
            component.name for component in report.failed_required
        )
        self.logger.critical(
            "System is FAILED. Required protection unavailable: %s",
            failed_names,
        )
        notifier.send_notification(
            "Herodium Security",
            f"System is FAILED. Required: {failed_names}",
            level="critical",
        )
