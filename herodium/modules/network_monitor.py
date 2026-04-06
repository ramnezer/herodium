import time
import os
import logging
import shutil
import subprocess
import threading
import ipaddress
import socket
import re
from datetime import datetime
from modules.notifier import Notifier  

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

        # Anti-Trolling Initialization
        self.static_whitelist = set()
        conf_whitelist = config.get('maltrail', {}).get('whitelist', [])
        for ip in conf_whitelist:
            try:
                self.static_whitelist.add(ipaddress.ip_address(ip))
            except:
                pass

        self.static_whitelist.add(ipaddress.ip_address("127.0.0.1"))
        self.static_whitelist.add(ipaddress.ip_address("::1"))

        self.dynamic_whitelist = set()
        self.running = False

        # Initialize the universal notifier
        self.notifier = Notifier(config, logger, scope="maltrail")

        # Optional scheduled cleanup of ipset blacklists (hours). 0 disables.
        try:
            self.clean_interval_hours = int((self.config.get('maltrail', {}) or {}).get('clean_interval_hours', 0) or 0)
        except Exception:
            self.clean_interval_hours = 0

    def start_monitoring(self):
        if not self.enabled:
            self.logger.info("Maltrail Network Monitor is DISABLED in config.")
            return

        self.running = True
        self._refresh_critical_infrastructure()

        # Initialize IP Sets regardless of mode (needed for detection logic)
        subprocess.run(['ipset', 'create', self.ipset_v4, 'hash:ip', 'family', 'inet', '-exist'], check=False)
        subprocess.run(['ipset', 'create', self.ipset_v6, 'hash:ip', 'family', 'inet6', '-exist'], check=False)

        # Apply firewall rules ONLY if blocking is enabled
        if self.blocking_enabled:
            has_ip6tables = shutil.which('ip6tables') is not None

            for chain in ["INPUT", "OUTPUT"]:
                # IPv4 rules
                self._ensure_fw_rule('iptables', chain, self.ipset_v4, "src")
                self._ensure_fw_rule('iptables', chain, self.ipset_v4, "dst")

                # IPv6 rules (only if ip6tables exists)
                if has_ip6tables:
                    self._ensure_fw_rule('ip6tables', chain, self.ipset_v6, "src")
                    self._ensure_fw_rule('ip6tables', chain, self.ipset_v6, "dst")

            if not has_ip6tables:
                self.logger.warning("ip6tables not found; IPv6 blocking will not be enforced.")

            self.logger.info(
                f"Network Monitor Active (BLOCKING MODE). Protected IPs: {len(self.static_whitelist) + len(self.dynamic_whitelist)}"
            )
        else:
            self.logger.info("Network Monitor Active (ALERT ONLY). No blocking rules applied.")

        threading.Thread(target=self._infrastructure_updater, daemon=True).start()
        threading.Thread(target=self._tail_loop, daemon=True).start()

        # Start periodic blacklist cleanup (flush ipset) if enabled
        if self.blocking_enabled and self.clean_interval_hours > 0:
            self.logger.info(f"IPSet cleanup enabled: every {self.clean_interval_hours} hour(s)")
            threading.Thread(target=self._clean_ipset_loop, daemon=True).start()

    def _ensure_fw_rule(self, bin_name, chain, set_name, direction):
        """
        Safely checks and adds firewall rules without using shell=True.
        bin_name: 'iptables' or 'ip6tables'
        direction: 'src' or 'dst'
        """
        try:
            check_cmd = [
                bin_name, '-C', chain,
                '-m', 'set', '--match-set', set_name, direction,
                '-j', 'DROP'
            ]
            check_result = subprocess.run(check_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            if check_result.returncode != 0:
                insert_cmd = [
                    bin_name, '-I', chain, '1',
                    '-m', 'set', '--match-set', set_name, direction,
                    '-j', 'DROP'
                ]
                subprocess.run(insert_cmd, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        except Exception as e:
            self.logger.error(f"Failed to update {bin_name} for {chain}/{direction}: {e}")

    def _refresh_critical_infrastructure(self):
        new_dynamic = set()
        try:
            import psutil
            for interface, snics in psutil.net_if_addrs().items():
                for snic in snics:
                    try:
                        new_dynamic.add(ipaddress.ip_address(snic.address))
                    except:
                        pass

            res = subprocess.run(['ip', 'route', 'show', 'default'], capture_output=True, text=True)
            match = re.search(r'default via ([0-9\.]+)', res.stdout)
            if match:
                new_dynamic.add(ipaddress.ip_address(match.group(1)))

            if os.path.exists('/etc/resolv.conf'):
                with open('/etc/resolv.conf', 'r') as f:
                    for line in f:
                        if line.startswith('nameserver'):
                            try:
                                new_dynamic.add(ipaddress.ip_address(line.split()[1]))
                            except:
                                pass

            self.dynamic_whitelist = new_dynamic
        except:
            pass

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
            except Exception:
                time.sleep(1)

    def _process_line(self, line):
        try:
            ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
            for ip in ips:
                self._block(ip)

            parts = line.split()
            potential_domains = [p.strip('",') for p in parts if '.' in p and not re.match(r'\d+\.\d+\.\d+\.\d+', p)]

            for domain in potential_domains:
                if len(domain) > 3 and not domain.startswith(('192.168', '10.', '172.')):
                    self._resolve_and_block(domain)

        except:
            pass

    def _resolve_and_block(self, domain):
        try:
            if domain in ["DNS", "UDP", "TCP", "ICMP"]:
                return
            results = socket.getaddrinfo(domain, None)
            for result in results:
                resolved_ip = result[4][0]
                self._block(resolved_ip)
        except:
            pass

    def _block(self, ip):
        try:
            ip_obj = ipaddress.ip_address(ip)

            if ip_obj in self.static_whitelist or ip_obj in self.dynamic_whitelist:
                return

            if ip_obj.is_private or ip_obj.is_loopback or str(ip_obj) == "0.0.0.0":
                return

            # Check mode before blocking
            if not self.blocking_enabled:
                self.logger.warning(f"DETECTED MALICIOUS IP (Alert Only): {ip}")
                self.notifier.send_notification("Herodium Alert", f"Detected: {ip} (Not Blocked)", level='critical')
                return

            set_name = self.ipset_v4 if ip_obj.version == 4 else self.ipset_v6

            res = subprocess.run(
                ['ipset', 'add', set_name, str(ip_obj)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE
            )

            if res.returncode == 0:
                self.logger.warning(f"BLOCKED MALICIOUS IP: {ip_obj}")
                self.notifier.send_notification("Maltrail Detection", f"Blocked Threat: {ip_obj}", level='critical')

        except:
            pass
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
                subprocess.run(['ipset', 'flush', self.ipset_v4], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
                subprocess.run(['ipset', 'flush', self.ipset_v6], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
                self.logger.info('IPSet blacklist flushed (scheduled cleanup)')
            except Exception as e:
                self.logger.error(f'IPSet cleanup failed: {e}')


    def stop_monitoring(self):
        self.running = False
