# Herodium Security System (Dev Edition)

> [!IMPORTANT]
> Herodium is a developer-oriented Linux security framework for testing, research, and controlled deployments.
>
> It works with system-level components such as ClamAV, AppArmor, Fail2Ban, Maltrail, ZRAM, systemd, and iptables/ipset.
> Test it in a VM, sandbox, or non-critical system before using it on a daily-driver or production machine.
>
> Herodium is a flexible foundation. Review and tune the configuration for your own system.

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
- AppArmor profile handling with multiple levels, defaulting to OS behavior unless explicitly changed.
- Optional `sysctl` hardening rules.
- Optional ZRAM activation.
- Dynamic ClamAV resource throttling based on workload and thermal conditions.
- Optional Fail2Ban activation for SSH brute-force protection.

### Scheduled Tasks
- Supports scheduled ClamAV scanning.
- Supports optional Rkhunter checks and threat-data updates.
- Never updates the local Rkhunter file-properties baseline automatically.
- The installer configures scheduled ClamAV scans through systemd timer units.

## Project Structure

```text
.
├── herodium/
│   ├── config/
│   │   └── herodium.yaml
│   ├── core/
│   │   ├── __init__.py
│   │   ├── engine.py
│   │   ├── health.py
│   │   ├── logger.py
│   │   └── system_command.py
│   ├── modules/
│   │   ├── __init__.py
│   │   ├── apparmor_manager.py
│   │   ├── apparmor_state.py
│   │   ├── av_scanner.py
│   │   ├── fs_monitor.py
│   │   ├── ips_manager.py
│   │   ├── memory_hunter.py
│   │   ├── network_monitor.py
│   │   ├── notifier.py
│   │   ├── performance_manager.py
│   │   ├── rkhunter_manager.py
│   │   ├── scan_recovery.py
│   │   ├── scheduler.py
│   │   ├── sys_hardener.py
│   │   └── zram_manager.py
│   ├── requirements.lock
│   └── requirements.txt
├── installer/
│   ├── bin/
│   │   ├── herodium-maltrail-update
│   │   ├── herodium-rkhunter-baseline
│   │   ├── herodium-scan
│   │   └── herodium-top
│   ├── systemd/
│   │   ├── herodium-maltrail-update.service
│   │   ├── herodium-maltrail-update.timer
│   │   ├── herodium.service
│   │   └── maltrail-sensor.service
│   ├── install.sh
│   ├── python-tools.lock
│   ├── supply-chain-lock.json
│   └── uninstall.sh
└── tests/
    ├── test_apparmor_installer_contract.py
    ├── test_apparmor_manager.py
    ├── test_apparmor_state.py
    ├── test_av_scanner.py
    ├── test_clamav_installer_contract.py
    ├── test_engine_health.py
    ├── test_fs_monitor.py
    ├── test_health.py
    ├── test_herodium_top.py
    ├── test_installer_reliability_contract.py
    ├── test_ips_manager.py
    ├── test_maltrail_update.py
    ├── test_memory_hunter.py
    ├── test_network_monitor.py
    ├── test_notifier.py
    ├── test_performance_manager.py
    ├── test_rkhunter_baseline_contract.py
    ├── test_rkhunter_manager.py
    ├── test_scan_recovery.py
    ├── test_scheduler.py
    ├── test_staged_deployment_installer_contract.py
    ├── test_supply_chain_installer_contract.py
    ├── test_sys_hardener.py
    ├── test_system_command.py
    └── test_zram_manager.py
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

## Optional Performance and Power Optimization

Herodium can optionally be used together with
[`auto-cpufreq`](https://github.com/AdnanHodzic/auto-cpufreq) on physical
systems.

Although `auto-cpufreq` was designed primarily for laptops, practical testing
with Herodium on a physical workstation showed improved power and thermal
efficiency without a noticeable reduction in Herodium performance.

`auto-cpufreq` dynamically manages CPU frequency scaling, governors, and turbo
boost according to system load, CPU temperature, and power state. This can
complement Herodium's own targeted ClamAV resource controls, particularly on
laptops and workstations where lower power consumption, reduced heat, and
quieter operation are desirable.

This integration is optional and is not a Herodium dependency. Results may vary
depending on:

- CPU model and scaling driver
- CPU governor configuration
- cooling capacity
- battery or AC power state
- scan size and workload intensity
- other power-management services

Avoid running multiple tools that manage the same CPU frequency or power
settings unless they have been configured specifically to coexist. In
particular, check for potential conflicts with tools or services such as TLP,
`power-profiles-daemon`, or other governor-management utilities.

### Install auto-cpufreq

Clone the official repository and run its installer:

```bash
git clone https://github.com/AdnanHodzic/auto-cpufreq.git
cd auto-cpufreq
sudo ./auto-cpufreq-installer
```

Install and enable the persistent `auto-cpufreq` daemon:

```bash
sudo auto-cpufreq --install
```

Review the current CPU, temperature, governor, and power-management status:

```bash
sudo auto-cpufreq --stats
```

For production or long-running Herodium deployments, compare scan completion
times, CPU temperature, system responsiveness, and queue behavior before and
after enabling `auto-cpufreq`.

##
##
##
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
sudo bash installer/install.sh
```

The source scripts intentionally remain non-executable. Invoke them through
`sudo bash` so archive extraction and source-control mode changes cannot alter
the documented installation path.

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
- optional Maltrail services:
  - `maltrail-sensor.service`
  - `herodium-maltrail-update.service`
  - `herodium-maltrail-update.timer`
  - code pinned by `installer/supply-chain-lock.json`
  - sensor-side downloads disabled (`--offline`)
  - controlled IOC trail refresh performed daily through staging and rollback
- scheduled ClamAV scan service and timer:
  - `herodium-scheduled-scan.service`
  - `herodium-scheduled-scan.timer`
- logs under:
  - `/var/log/herodium`
- scheduled scan config under:
  - `/etc/herodium/scheduled_scan.conf`

## Herodium Deployment and Dependency Policy

Herodium itself is built under `/opt/herodium.stage` while the currently active
service continues using `/opt/herodium`. The installer creates a stable source
manifest, copies only regular source files into the root-owned stage, and
verifies that both the source and staged snapshot match before dependency work
begins.

The staged virtual environment is new for every installation. Packaging tools
are pinned with SHA-256 hashes in `installer/python-tools.lock`; runtime
packages are pinned with SHA-256 hashes in `herodium/requirements.lock`. Pip is
run in isolated mode with user and system configuration disabled,
`--require-hashes`, `--no-deps`, and the explicit PyPI simple index. The active
`/opt/herodium/venv` is never upgraded in place.

Before activation, the installer validates the exact installed distribution
set, imports, Python syntax, YAML configuration, `pip check`, permissions, and
a content manifest. Existing root-owned configuration is preserved and updated
inside the stage. Mutable quarantine contents are copied only after the old
service has been stopped.

Activation rotates `/opt/herodium` to `/opt/herodium.previous` and renames the
fully validated stage into place. The new service must reach Herodium's
`PROTECTED` health state before the transaction can be committed. A failure or
interrupt before commit restores the previous deployment, service unit,
enabled state, and active state automatically. The validated deployment
manifest is retained under `/var/lib/herodium/supply-chain` for operator audit.

## Maltrail Supply-Chain Policy

Herodium does not install Maltrail from a moving branch. The installer reads an
immutable upstream repository, full commit identifier, and expected license
SHA-256 from `installer/supply-chain-lock.json`. It fetches only that commit,
validates the fetched object database, checks the license hash, extracts a
content-only deployment, and activates it only after the service passes a
health check. The prior `/opt/maltrail` deployment is retained as
`/opt/maltrail.previous` for immediate rollback.

The sensor starts with `--offline` and uses an explicit root-owned configuration
at `/etc/maltrail/maltrail.conf`. This keeps packet capture isolated from network
retrieval and prevents the long-running sensor from modifying its own inputs.
Runtime trail state remains namespaced by the pinned code commit.

IOC trails are refreshed separately by `herodium-maltrail-update.timer`, once
per 24 hours with a randomized delay. The updater executes only the feed modules
from the pinned Maltrail code snapshot, disables feed modules that do not expose
an HTTPS URL, restores normal TLS certificate verification, and rejects custom
remote/update-server inputs for the automated path.

Each refresh is built under a private staging HOME. The resulting CSV must pass
strict UTF-8/CSV validation, bounded row and file-size limits, and a
catastrophic-shrink guard relative to the currently active list. A valid
candidate is copied atomically into the active state directory. If the sensor
was running, it is restarted and must return with a non-zero MainPID; otherwise
the previous `trails.csv` is restored automatically. The last successful
metadata record is stored at:

```text
/var/lib/herodium/supply-chain/maltrail-trails.json
```

Run an immediate controlled refresh and inspect its timer with:

```bash
sudo herodium-maltrail-update
sudo systemctl status herodium-maltrail-update.timer
sudo journalctl -u herodium-maltrail-update.service
```

Maltrail source code still changes only through an explicit
`supply-chain-lock.json` update and a new Herodium release. Trail data is
therefore current and mutable, while executable code remains reviewed and
immutable.

## Rkhunter Baseline Safety

Herodium runs scheduled Rkhunter checks and may update Rkhunter threat-data files,
but it never runs `rkhunter --propupd` automatically. The file-properties
baseline represents trusted local system state and must only be changed after an
operator has investigated the current warnings and verified that the changes are
authorized.

Review the current warnings without changing the baseline:

```bash
sudo herodium-rkhunter-baseline --review
```

After investigating and validating all relevant changes, perform an explicit,
audited baseline update:

```bash
sudo herodium-rkhunter-baseline \
  --update \
  --acknowledge-reviewed-warnings \
  --reason "verified authorized system changes"
```

The update command requires root privileges, an explicit acknowledgement, and a
non-empty reason. It serializes operations with scheduled Rkhunter work and
writes an audit record to:

```text
/var/log/herodium/rkhunter-baseline.log
```

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
  - `1` — OS default / no Herodium AppArmor changes

## Logs

Main operational logs:

- `/var/log/herodium/herodium.log`
- `/var/log/herodium/scheduled_scan.log`

If Maltrail is installed, related logs are typically stored under:

- `/var/log/maltrail/`

## Uninstallation

To remove Herodium and clean up its installed files and service units:

```bash
sudo bash installer/uninstall.sh
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

### Installer reliability and rollback testing

The installer preserves and restores the prior Herodium unit, CLI tools, scheduled-scan assets, deployment manifest, logrotate policy, ClamAV configuration and service/socket/updater state, and the previous pinned Maltrail deployment until the activation transaction passes final health checks. Maltrail is stopped with `SIGINT` so its main process can terminate worker processes cleanly before the timeout. Mutable operator configuration is excluded from the immutable deployment manifest.

Timeshift snapshots are created as on-demand snapshots in a headless command environment without desktop notification helpers and are verified by listing the resulting snapshot before installation continues. This avoids treating a successful snapshot as failed because of an asynchronous desktop-notification error.

A controlled rollback validation can be requested explicitly by running the installer with `HERODIUM_INSTALLER_TEST_FAILPOINT=after_final_validation` and `HERODIUM_INSTALLER_TEST_ACKNOWLEDGE=ROLLBACK-TEST`. This test intentionally fails after all final service checks and must restore the previous deployment and service state; it is not enabled during normal installation. The rollback transaction covers deployed code and installer-managed activation assets. It intentionally does not uninstall APT packages or delete a verified Timeshift snapshot created before activation.
