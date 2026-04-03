import time
import threading
import subprocess
import logging
import os
from modules.notifier import Notifier

class TaskScheduler:
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger
        self.enabled = config.get('scheduler', {}).get('enable', True)
        
        # Intervals
        # 0 or negative => DISABLED for that task (respects installer choices)
        sched = config.get('scheduler', {}) or {}
        self.rkhunter_int = self._hours_to_seconds(sched.get('rkhunter_interval_hours', 6))
        self.home_scan_int = self._hours_to_seconds(sched.get('home_scan_interval_hours', 24))
        self.full_scan_int = self._hours_to_seconds(sched.get('full_scan_interval_hours', 168))
        self.update_int = self._hours_to_seconds(sched.get('update_interval_hours', 24))
        # Init Notifier
        self.notifier = Notifier(config, logger)

        # Timers
        now = time.time()
        self.last_rkhunter = now
        self.last_home = now 
        self.last_full = now
        self.last_update = now
        
        self.stop_event = threading.Event()
    def _hours_to_seconds(self, hours):
        """Convert hours to seconds. 0/None/invalid => disabled (returns None)."""
        try:
            h = int(hours)
        except Exception:
            return None
        if h <= 0:
            return None
        return h * 3600


    def start(self):
        if not self.enabled: return
        self.logger.info("Task Scheduler started.")
        threading.Thread(target=self._loop, daemon=True).start()

    def stop(self):
        self.stop_event.set()

    def _loop(self):
        while not self.stop_event.is_set():
            now = time.time()
            
            # Rkhunter
            if self.rkhunter_int and (now - self.last_rkhunter > self.rkhunter_int):
                self._run_rkhunter()
                self.last_rkhunter = now

            # Home Scan
            if self.home_scan_int and (now - self.last_home > self.home_scan_int):
                self._run_scan("Home", "/home")
                self.last_home = now

            # Full Scan
            if self.full_scan_int and (now - self.last_full > self.full_scan_int):
                self._run_scan("Full System", "/")
                self.last_full = now
                
            # Updates
            if self.update_int and (now - self.last_update > self.update_int):
                self._run_updates()
                self.last_update = now

            time.sleep(60)

    def _run_scan(self, name, path):
        self.logger.info(f"Starting {name} Scan (ClamAV)...")

        clam_cfg = (self.config.get('clamav') or {})
        sched_cfg = (self.config.get('scheduler') or {})
        dirs_cfg = (self.config.get('directories') or {})

        # Scheduled policy (preferred), fallback to global clamav policy, then default
        action = str(
            sched_cfg.get('threat_action')
            or clam_cfg.get('threat_action')
            or 'quarantine'
        ).lower()

        qdir = str(dirs_cfg.get('quarantine_dir') or '/opt/herodium/quarantine')

        cmd = ['clamdscan', '--fdpass', '--multiscan']

        # Apply user policy for scheduled scans (minimal, safe change)
        if action == 'delete':
            cmd.append('--remove=yes')
        elif action == 'quarantine':
            try:
                os.makedirs(qdir, exist_ok=True)
                cmd.append(f'--move={qdir}')
            except Exception:
                # If quarantine dir fails, fall back to alert-only
                action = 'alert'

        cmd.append(path)

        try:
            res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            if res.returncode == 0:
                self.logger.info(f"{name} Scan completed (clean).")
                return

            if res.returncode == 1:
                self.logger.warning(f"{name} Scan completed (THREATS FOUND). Action={action}")
                self.notifier.send_notification(
                    "CLAMAV DETECTION",
                    f"{name} scan found threats.\nAction: {action}",
                    level='critical'
                )
                return

            self.logger.error(f"{name} Scan ended with error code {res.returncode}.")
        except Exception as e:
            self.logger.error(f"{name} Scan failed: {e}")

    def _run_rkhunter(self):
        self.logger.info("Starting Rkhunter scan...")
        try:
            # Report Warnings Only
            res = subprocess.run(['rkhunter', '--check', '--sk', '--rwo'], capture_output=True, text=True)
            
            if res.stdout and len(res.stdout.strip()) > 0:
                self.logger.warning(f"Rkhunter Warnings:\n{res.stdout}")
                # Notify User
                self.notifier.send_notification("ROOTKIT WARNING", "Rkhunter found suspicious anomalies.\nCheck logs immediately!", level='critical')
            else:
                self.logger.info("Rkhunter scan clean.")
        except: pass

    def _run_updates(self):
        self.logger.info("Running updates...")
        try:
            subprocess.run(['freshclam'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(['rkhunter', '--update'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(['rkhunter', '--propupd'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except: pass
