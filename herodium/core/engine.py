import logging
import signal
import sys
import threading
import time
from pathlib import Path

import yaml

# Python Path
sys.path.append(str(Path(__file__).resolve().parent.parent))

from modules.apparmor_manager import AppArmorManager
from modules.av_scanner import ClamAVScanner
from modules.falco_dispatcher import FalcoEventDispatcher
from modules.falco_monitor import FalcoMonitor
from modules.fs_monitor import Watcher
from modules.ips_manager import IPSManager
from modules.memory_hunter import MemoryHunter
from modules.network_monitor import NetworkMonitor
from modules.notifier import Notifier
from modules.performance_manager import PerformanceManager
from modules.scheduler import TaskScheduler
from modules.sys_hardener import SystemHardener
from modules.zram_manager import ZramManager

from core.health import (
    ComponentHealth,
    ComponentState,
    HealthReport,
    StartupHealthManager,
    SystemHealth,
)

# Configuration Paths
BASE_DIR = Path("/opt/herodium")
CONFIG_PATH = BASE_DIR / "config" / "herodium.yaml"
LOG_DIR = BASE_DIR / "logs"


class HerodiumEngine:
    def __init__(self):
        self.running = True
        self._memory_hunter_thread = None
        self.health_report = HealthReport.from_components(())
        self._setup_logging()
        self.config = self._load_config()
        self.logger.info("Initializing Herodium Engine...")

        self.live_monitor_enabled = self._config_bool(
            "live_monitor", "enable", True
        )
        self.maltrail_enabled = self._config_bool(
            "maltrail", "enable", False
        )
        self.falco_enabled = self._config_bool("falco", "enable", False)

        self.notifier = Notifier(self.config, self.logger)
        self.notifier.send_notification(
            "Herodium Security",
            "System Initializing... Please wait.",
            level="normal",
        )

        self.scanner = ClamAVScanner(self.config, self.logger)
        self.perf_manager = PerformanceManager(
            self.config, self.logger, self.scanner
        )
        self.monitor = Watcher(self.config, self.logger)
        self.scheduler = TaskScheduler(self.config, self.logger)
        self.network_monitor = NetworkMonitor(self.config, self.logger)
        self.memory_hunter = MemoryHunter(self.config, self.logger)
        self.hardener = SystemHardener(self.config, self.logger)
        self.ips_manager = IPSManager(self.config, self.logger)
        self.apparmor_manager = AppArmorManager(self.config, self.logger)
        self.zram_manager = ZramManager(self.config, self.logger)
        self.falco_monitor = self._create_falco_monitor()
        self.falco_dispatcher = self._create_falco_dispatcher()

        self.health_manager = StartupHealthManager(
            config=self.config,
            logger=self.logger,
            scanner=self.scanner,
            zram_manager=self.zram_manager,
            apparmor_manager=self.apparmor_manager,
            ips_manager=self.ips_manager,
            hardener=self.hardener,
            scheduler=self.scheduler,
            network_monitor=self.network_monitor,
            performance_manager=self.perf_manager,
            filesystem_monitor=self.monitor,
            start_memory_hunter=self._start_memory_hunter,
            falco_monitor=self.falco_monitor,
        )

        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

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
        section_config = self.config.get(section, {})
        if not isinstance(section_config, dict):
            return default
        return self._safe_bool(section_config.get(key), default)

    def _create_falco_monitor(self):
        if not self.falco_enabled:
            return None

        section = self.config.get("falco", {})
        try:
            monitor = FalcoMonitor.from_config(self.logger, section)
            FalcoEventDispatcher.validate_config(
                section,
                queue_capacity=monitor.queue_max_size,
            )
            return monitor
        except (TypeError, ValueError) as exc:
            self.logger.error("Falco configuration rejected: %s", exc)
            return None

    def _create_falco_dispatcher(self):
        if not self.falco_enabled or self.falco_monitor is None:
            return None

        section = self.config.get("falco", {})
        try:
            return FalcoEventDispatcher.from_config(
                self.logger,
                self.notifier,
                self.falco_monitor,
                section,
            )
        except (TypeError, ValueError) as exc:
            self.logger.error("Falco dispatch configuration rejected: %s", exc)
            return None

    def _setup_logging(self):
        if not LOG_DIR.exists():
            LOG_DIR.mkdir(parents=True, exist_ok=True)
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - [HERODIUM] - %(levelname)s - %(message)s",
            handlers=[
                logging.FileHandler(LOG_DIR / "herodium.log"),
                logging.StreamHandler(sys.stdout),
            ],
        )
        self.logger = logging.getLogger()

    def _load_config(self):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as config_file:
                loaded_config = yaml.safe_load(config_file) or {}

            if not isinstance(loaded_config, dict):
                self.logger.error(
                    "Config load failed: root YAML object must be a mapping."
                )
                return {}

            return loaded_config
        except (OSError, yaml.YAMLError) as exc:
            self.logger.error(f"Config load failed: {exc}")
            return {}

    def _signal_handler(self, sig, frame):
        self.logger.info("Shutdown signal received...")
        self.stop()
        raise SystemExit(0)

    def _memory_hunter_loop(self):
        cfg = self.config.get("memory_scan", {}) or {}
        raw = cfg.get("interval_seconds", 5)

        try:
            interval = int(raw)
        except (TypeError, ValueError):
            interval = 5

        interval = max(1, interval)
        self.logger.info(
            f"Memory Hunter activated (Interval: {interval}s)"
        )
        while self.running:
            try:
                self.memory_hunter.flash_scan()
            # Keep the long-running worker alive across backend-specific failures.
            except Exception as exc:  # noqa: BLE001
                self.logger.error(f"Memory Hunter error: {exc}")
            time.sleep(interval)

    def _start_memory_hunter(self):
        thread = threading.Thread(
            target=self._memory_hunter_loop,
            daemon=True,
            name="herodium-memory-hunter",
        )
        thread.start()
        self._memory_hunter_thread = thread
        return thread.is_alive()

    def start(self):
        self.logger.info("Starting all protection modules...")
        self.health_report = self.health_manager.collect(
            live_monitor_enabled=self.live_monitor_enabled,
            maltrail_enabled=self.maltrail_enabled,
            falco_enabled=self.falco_enabled,
        )
        self.health_manager.emit(self.health_report, self.notifier)

        if self.health_report.state is SystemHealth.FAILED:
            self.stop()
            return 1

        try:
            while self.running:
                self._service_falco_runtime()
                time.sleep(1)
        # Keep top-level engine failure handling deterministic.
        except Exception as exc:  # noqa: BLE001
            self.logger.error(f"Engine main loop error: {exc}")
            self.stop()
            return 1

        return 0

    def _service_falco_runtime(self):
        if (
            not self.falco_enabled
            or self.falco_monitor is None
            or self.falco_dispatcher is None
        ):
            return 0

        dispatch_failed = False
        try:
            dispatched = self.falco_dispatcher.service_once()
        # Falco is optional and must not terminate the main protection engine.
        except Exception as exc:  # noqa: BLE001
            dispatch_failed = True
            dispatched = 0
            self.logger.error(
                "Falco runtime dispatch failed: %s",
                type(exc).__name__,
            )

        if dispatch_failed:
            current = ComponentHealth(
                "falco",
                ComponentState.DEGRADED,
                detail="Falco event dispatch failed",
            )
        else:
            current = self.health_manager.falco_runtime_component(True)

        try:
            previous = self.health_report.component("falco")
        except KeyError:
            previous = current

        self.health_report = self.health_report.with_component(current)
        if previous.state is not current.state:
            self.health_manager.emit_component_transition(
                previous,
                current,
                self.health_report,
                self.notifier,
            )
        return dispatched

    def stop(self):
        self.running = False
        if hasattr(self.monitor, "stop"):
            self.monitor.stop()
        if self.falco_monitor is not None:
            falco_stopped = self.falco_monitor.stop()
            if not falco_stopped:
                self.logger.warning("Falco monitor did not stop cleanly.")
        if hasattr(self.network_monitor, "stop_monitoring"):
            self.network_monitor.stop_monitoring()
        if hasattr(self.perf_manager, "stop"):
            self.perf_manager.stop()
        if hasattr(self.scheduler, "stop"):
            self.scheduler.stop()
        self.logger.info("Engine stopped.")


if __name__ == "__main__":
    engine = HerodiumEngine()
    raise SystemExit(engine.start())
