import time
import logging
import threading
import signal
import sys
import yaml
from pathlib import Path

# Python Path
sys.path.append(str(Path(__file__).resolve().parent.parent))

from modules.av_scanner import ClamAVScanner
from modules.fs_monitor import Watcher
from modules.scheduler import TaskScheduler
from modules.network_monitor import NetworkMonitor
from modules.memory_hunter import MemoryHunter
from modules.performance_manager import PerformanceManager
from modules.apparmor_manager import AppArmorManager
from modules.zram_manager import ZramManager
from modules.sys_hardener import SystemHardener
from modules.ips_manager import IPSManager
from modules.notifier import Notifier

# Configuration Paths
BASE_DIR = Path("/opt/herodium")
CONFIG_PATH = BASE_DIR / "config" / "herodium.yaml"
LOG_DIR = BASE_DIR / "logs"

class HerodiumEngine:
    def __init__(self):
        self.running = True
        self._setup_logging()
        self.config = self._load_config()
        self.logger.info("Initializing Herodium Engine...")

        # Respect user configuration flags (installer choices)
        self.live_monitor_enabled = self.config.get('live_monitor', {}).get('enable', True)
        self.maltrail_enabled = self.config.get('maltrail', {}).get('enable', False)

        
        # User Notification
        self.notifier = Notifier(self.config, self.logger)
        self.notifier.send_notification("Herodium Security", "System Initializing... Please wait.", level='normal')

        # 1. Initialize Components
        self.scanner = ClamAVScanner(self.config, self.logger)
        self.perf_manager = PerformanceManager(self.config, self.logger, self.scanner)
        self.monitor = Watcher(self.config, self.logger)
        self.scheduler = TaskScheduler(self.config, self.logger)
        self.network_monitor = NetworkMonitor(self.config, self.logger)
        self.memory_hunter = MemoryHunter(self.config, self.logger)
        self.hardener = SystemHardener(self.config, self.logger)
        self.ips_manager = IPSManager(self.config, self.logger)
        
        self.apparmor_manager = AppArmorManager(self.config, self.logger)
        self.zram_manager = ZramManager(self.config, self.logger)

        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _setup_logging(self):
        if not LOG_DIR.exists(): LOG_DIR.mkdir(parents=True, exist_ok=True)
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - [HERODIUM] - %(levelname)s - %(message)s',
            handlers=[logging.FileHandler(LOG_DIR / "herodium.log"), logging.StreamHandler(sys.stdout)]
        )
        self.logger = logging.getLogger()

    def _load_config(self):
        try:
            with open(CONFIG_PATH, 'r') as f: return yaml.safe_load(f)
        except Exception as e:
            self.logger.error(f"Config load failed: {e}")
            return {}

    def _signal_handler(self, sig, frame):
        self.logger.info("Shutdown signal received...")
        self.stop()
        sys.exit(0)

    def _memory_hunter_loop(self):
        #
        cfg = (self.config.get("memory_scan") or {})
        raw = cfg.get("interval_seconds", 5)

        try:
            interval = int(raw)
        except Exception:
            interval = 5

        if interval < 1:
            interval = 1

        self.logger.info(f"Memory Hunter activated (Interval: {interval}s)")
        while self.running:
            try:
                self.memory_hunter.flash_scan()
            except Exception as e:
                self.logger.error(f"Memory Hunter error: {e}")
            time.sleep(interval)


    def start(self):
        self.logger.info("Starting all protection modules...")
        
        self.zram_manager.enable()
        self.apparmor_manager.apply_policy()
        self.ips_manager.start()
        self.hardener.apply_security_rules()
        self.scheduler.start()
        if self.maltrail_enabled:
            self.network_monitor.start_monitoring()
        else:
            self.logger.info("Network Monitor (Maltrail) is DISABLED in config.")
        self.perf_manager.start()
        # Live monitor controls FS watcher + USB hunter + memory hunter loop
        if self.live_monitor_enabled:
            threading.Thread(target=self._memory_hunter_loop, daemon=True).start()
        else:
            self.logger.info("Live Monitor is DISABLED in config. FS/USB/Memory scanning will not run.")
        self.logger.info("System is PROTECTED. Monitoring active...")
        # Success Notification
        self.notifier.send_notification("Herodium Security", "System is Active and Protected.", level='normal')
        
        try:
            if self.live_monitor_enabled:
                self.monitor.run()
            while self.running: time.sleep(1)
        except Exception as e:
            self.logger.error(f"Engine main loop error: {e}")
            self.stop()

    def stop(self):
        self.running = False
        if hasattr(self.monitor, 'stop'): self.monitor.stop()
        if hasattr(self.network_monitor, 'stop_monitoring'): self.network_monitor.stop_monitoring()
        if hasattr(self.perf_manager, 'stop'): self.perf_manager.stop()
        self.logger.info("Engine stopped.")

if __name__ == "__main__":
    engine = HerodiumEngine()
    engine.start()
