# Herodium Security System (Dev Edition)

> [!CAUTION]
> **DEVELOPER USE ONLY**
> **This software is intended exclusively for developers and security researchers.**
> It is designed as a **seed/foundation** framework for building broader security tools.
> **DO NOT** deploy this tool in a production, business, or daily-driver personal environment without extensive testing in a dedicated development environment (sandbox/VM).
> This system makes significant changes to the OS kernel, network stack (IPTables/IPSet), and background services. Improper configuration or conflicts with existing software may lead to system instability or data inaccessibility. **Use at your own risk.**

---

## Overview

**Herodium** is a developer-oriented Linux security project designed as a **seed framework** for building and testing broader defensive tooling.

It runs as a privileged background engine and combines multiple defensive layers into one modular system: real-time file monitoring, removable media scanning, process and command-line inspection, optional network response logic, optional AppArmor policy application, optional system hardening, scheduled antivirus scanning, and supporting operational tools.

This repository is not positioned as a polished enterprise security suite. Its purpose is to provide a practical, extensible foundation that developers and security researchers can inspect, modify, and expand.

## Current Scope

Herodium currently focuses on these areas:

### Real-Time File Monitoring
- Watches configured filesystem paths for file creation, modification, and move events.
- Uses a queued scanning model to reduce duplicate scans during rapid file changes.
- Supports optional filtering for noisy locations such as cache directories.

### USB / External Media Monitoring
- Detects newly mounted removable media under standard Linux mount locations.
- Automatically attaches filesystem monitoring to new media.
- Queues existing files on newly detected media for initial scanning.

### Memory / Process Inspection
- Iterates running processes and inspects:
  - the executable path
  - file-based command-line arguments
- Uses ClamAV-backed scanning logic to identify infected binaries or loaded files.
- Terminates a process if an infected executable or related file is detected.

### ClamAV Integration
- Connects to the local `clamd` Unix socket.
- Supports configurable actions for detected threats:
  - `quarantine`
  - `delete`
  - `alert`
- Enforces size-based prefiltering before stream scanning.

### Network Monitoring
- Integrates with local Maltrail logs.
- Can run in either:
  - alert-only mode
  - active blocking mode
- In blocking mode, malicious IPs are added to IP sets and enforced with `iptables` / `ip6tables`.
- Supports scheduled blacklist cleanup.

### System Hardening and Host Controls
- AppArmor profile handling with multiple levels.
- Optional `sysctl` hardening rules.
- Optional ZRAM activation.
- Dynamic ClamAV resource throttling based on workload and thermal conditions.
- Optional Fail2Ban activation for SSH brute-force protection.

### Scheduled Tasks
- Supports scheduled ClamAV scanning.
- Supports optional Rkhunter checks and updates.
- The installer configures scheduled ClamAV scans through systemd timer units.

## Project Structure

```text
.
├── herodium/
│   ├── config/
│   │   └── herodium.yaml
│   ├── core/
│   │   ├── engine.py
│   │   ├── logger.py
│   │   └── __init__.py
│   ├── modules/
│   │   ├── apparmor_manager.py
│   │   ├── av_scanner.py
│   │   ├── fs_monitor.py
│   │   ├── ips_manager.py
│   │   ├── memory_hunter.py
│   │   ├── network_monitor.py
│   │   ├── notifier.py
│   │   ├── performance_manager.py
│   │   ├── scheduler.py
│   │   ├── sys_hardener.py
│   │   ├── zram_manager.py
│   │   └── __init__.py
│   └── requirements.txt
└── installer/
    ├── bin/
    │   ├── herodium-scan
    │   └── herodium-top
    ├── systemd/
    │   ├── herodium.service
    │   └── maltrail-sensor.service
    ├── install.sh
    └── uninstall.sh
```

## Supported Environment

Herodium is designed for **Debian-based Linux systems** that use:
- `apt`
- `systemd`
- AppArmor
- ClamAV

The current installer flow is oriented toward:
- Debian
- Ubuntu
- Linux Mint
- Kali Linux
  
and similar Debian/Ubuntu-based distributions.


Root privileges are required for installation and normal runtime operation.

## Resource Expectations

- The live scanner is designed to be **highly CPU-efficient** and, under normal day-to-day activity, will usually consume only a **small amount of processing power**.
- Actual CPU and memory usage can still increase during bursts of filesystem activity, removable media scans, manual scans, scheduled scans, or heavy process inspection workloads.
- Plan for **approximately 1500 MB of RAM** for comfortable operation.
- Minimum recommended hardware:
  - **4 CPU cores**
  - **8 GB RAM**

## Installation

### Prerequisites
- A Debian-based Linux distribution
- Root access (`sudo`)
- Internet access for package installation and initial signatures / dependencies
- A development or test environment such as a VM, lab machine, or sandbox

### Clone the repository

```bash
sudo apt-get install git
git clone https://github.com/ramnezer/herodium.git
cd herodium
```

### Run the installer

```bash
cd installer
chmod +x install.sh
sudo ./install.sh
```

### Installer flow

The interactive installer currently guides you through:
- Timeshift snapshot creation
- ZRAM setup
- scheduled ClamAV scan preferences
- live monitoring enable/disable
- live threat action selection
- Maltrail installation and mode
- Fail2Ban installation
- AppArmor level selection
- optional kernel hardening
- optional Rkhunter setup

## What the Installer Sets Up

Depending on your selections, the installer may configure:

- application deployment under `/opt/herodium`
- Python virtual environment under `/opt/herodium/venv`
- main service:
  - `herodium.service`
- optional Maltrail sensor service:
  - `maltrail-sensor.service`
- scheduled ClamAV scan service and timer:
  - `herodium-scheduled-scan.service`
  - `herodium-scheduled-scan.timer`
- logs under:
  - `/var/log/herodium`
- scheduled scan config under:
  - `/etc/herodium/scheduled_scan.conf`

## Runtime Paths

Common paths used by the current implementation:

```text
/opt/herodium
/opt/herodium/config/herodium.yaml
/opt/herodium/quarantine
/var/log/herodium/herodium.log
/var/log/herodium/scheduled_scan.log
/var/log/maltrail
/etc/herodium/scheduled_scan.conf
```

## Usage

### Start / Stop / Status

```bash
sudo systemctl status herodium.service
sudo systemctl restart herodium.service
sudo systemctl stop herodium.service
```

### Check scheduled scan timer

```bash
sudo systemctl status herodium-scheduled-scan.timer
```

### Check optional Maltrail sensor

```bash
sudo systemctl status maltrail-sensor.service
```

### Real-Time Logs Monitoring
```bash
sudo tail -f /var/log/herodium/herodium.log
```

### Real-time dashboard

```bash
sudo herodium-top
```

### Manual scan wrapper

```bash
sudo herodium-scan /path/to/scan
```

## Configuration

### Main engine configuration

Primary runtime configuration is stored in:

```bash
sudo nano /opt/herodium/config/herodium.yaml
```

Important keys include:

- `live_monitor.enable`
- `directories.watch_paths`
- `directories.ignore_prefixes`
- `directories.ignore_user_cache`
- `clamav.socket_path`
- `clamav.threat_action`
- `memory_scan.interval_seconds`
- `memory_scan.whitelist`
- `maltrail.enable`
- `maltrail.block_traffic`
- `maltrail.log_path`
- `maltrail.clean_interval_hours`
- `performance.enable_zram`
- `performance.cpu_limit_percent`
- `hardening.enable`
- `ips.enable`
- `apparmor.level`

After changing the YAML file:

```bash
sudo systemctl restart herodium.service
```

### Scheduled scan configuration

The installer writes scheduled scan settings to:

```bash
sudo nano /etc/herodium/scheduled_scan.conf
```

After changing scheduled scan service or timer behavior:

```bash
sudo systemctl daemon-reload
sudo systemctl restart herodium-scheduled-scan.timer
```

## Default Behavior

Out of the box, the current default configuration includes:

- live monitoring enabled
- default watch paths:
  - `/home`
  - `/tmp`
  - `/etc`
  - `/var/www`
- quarantine path:
  - `/opt/herodium/quarantine`
- ClamAV action:
  - `quarantine`
- Memory Hunter enabled with 1-second loop interval
- optional network blocking controlled by configuration
- optional hardening controlled by configuration
- AppArmor default level:
  - `2`

## Logs

Main operational logs:

- `/var/log/herodium/herodium.log`
- `/var/log/herodium/scheduled_scan.log`

If Maltrail is installed, related logs are typically stored under:

- `/var/log/maltrail/`

## Uninstallation

To remove Herodium and clean up its installed files and service units:

```bash
cd installer
chmod +x uninstall.sh
sudo ./uninstall.sh
```

The uninstaller removes:
- Herodium service units
- deployed application files
- log directories
- scheduled scan units
- local helper scripts
- optional Fail2Ban jail created by the installer
- Herodium-specific IP sets and firewall rules where applicable

It can also optionally remove related packages installed by the project.

## Important Notes

- Herodium is intentionally opinionated and root-level.
- It is meant for controlled development and research use.
- It can modify host security posture in ways that are inappropriate for unmanaged environments.
- Test changes in a VM or disposable environment before trusting them on a real system.
- If you use higher AppArmor levels or other host-hardening features, a backup-first workflow is strongly recommended.

## For Developers

This project is best understood as a starting point for:
- Linux endpoint defense experiments
- ClamAV orchestration logic
- removable media scanning workflows
- AppArmor automation prototypes
- host-level response automation
- security monitoring research on Debian-based systems

The codebase is intentionally modular so individual components can be replaced, extended, or stripped down depending on the use case.
