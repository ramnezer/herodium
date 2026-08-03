import logging
import signal
import sys
import threading
import time
from pathlib import Path

import yaml

# Python Path
sys.path.append(str(Path(__file__).resolve().parent.parent))

from core.health import HealthReport, StartupHealthManager, SystemHealth  # noqa: E402
from modules.apparmor_manager import AppArmorManager  # noqa: E402
from modules.av_scanner import ClamAVScanner  # noqa: E402
from modules.fs_monitor import Watcher  # noqa: E402
from modules.ips_manager import IPSManager  # noqa: E402
from modules.memory_hunter import MemoryHunter  # noqa: E402
from modules.network_monitor import NetworkMonitor  # noqa: E402
from modules.notifier import Notifier  # noqa: E402
from modules.performance_manager import PerformanceManager  # noqa: E402
from modules.scheduler import TaskScheduler  # noqa: E402
from modules.sys_hardener import SystemHardener  # noqa: E402
from modules.zram_manager import ZramManager  # noqa: E402

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
        section_config = self.config.get(section, {}) or {}
        return self._safe_bool(section_config.get(key), default)

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
            except Exception as exc:
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
        )
        self.health_manager.emit(self.health_report, self.notifier)

        if self.health_report.state is SystemHealth.FAILED:
            self.stop()
            return 1

        try:
            while self.running:
                time.sleep(1)
        except Exception as exc:
            self.logger.error(f"Engine main loop error: {exc}")
            self.stop()
            return 1

        return 0

    def stop(self):
        self.running = False
        if hasattr(self.monitor, "stop"):
            self.monitor.stop()
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
