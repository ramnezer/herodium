# Herodium Security System (Dev Edition)

> [!IMPORTANT]
> Herodium is a developer-oriented Linux security framework for testing, research, and controlled deployments.
>
> It works with system-level components such as ClamAV, Falco, AppArmor, Fail2Ban, Maltrail, ZRAM, systemd, and iptables/ipset.
> Test it in a VM, sandbox, or non-critical system before using it on a daily-driver or production machine.
>
> Herodium is a flexible foundation. Review and tune the configuration for your own system.

---

## Overview

**Herodium** is a developer-oriented Linux security project designed as a **seed framework** for building and testing broader defensive tooling.

It runs as a privileged background engine and combines multiple defensive layers into one modular system: real-time file monitoring, removable media scanning, process and command-line inspection, optional Falco-based runtime behavior monitoring, optional network response logic, optional AppArmor policy application, optional system hardening, scheduled antivirus scanning, and supporting operational tools.

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

### Falco Runtime Behavioral Monitoring
- Optionally integrates [Falco](https://falco.org/) as a host runtime behavior sensor.
- Uses Falco's modern eBPF driver to observe kernel syscall activity without turning Falco into an enforcement engine.
- Complements ClamAV: ClamAV evaluates file content, while Falco can identify high-severity runtime behavior such as security-relevant state changes.
- Runs in **alert-only** mode. Falco events never directly kill a process, quarantine a file, or change firewall state.
- Uses a high-signal `ERROR+` policy: only `ERROR`, `CRITICAL`, `ALERT`, and `EMERGENCY` Falco rules are loaded and evaluated. Lower-severity `WARNING`, `NOTICE`, `INFO`, and `DEBUG` rules are intentionally excluded to avoid routine host activity becoming an alert flood.
- Writes structured JSONL to `/var/log/herodium/falco-events.jsonl`; Herodium validates and consumes the stream through a persistent cursor, a bounded queue, and a rate-limited dispatcher.
- Logs only bounded event context such as rule, priority, process path, parent, user, and target. The dispatcher does not persist the raw Falco output or raw command line.
- Treats Falco as an optional health component: a Falco runtime failure degrades that component instead of converting Falco into an automatic response mechanism.

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
│   │   ├── falco_dispatcher.py
│   │   ├── falco_event.py
│   │   ├── falco_monitor.py
│   │   ├── falco_reader.py
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
│   ├── falco/
│   │   ├── herodium-falco-rules.yaml
│   │   └── herodium-falco.yaml
│   ├── logrotate/
│   │   └── herodium-falco
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

The main installer entrypoint, `installer/install.sh`, intentionally remains
non-executable. Invoke it through `sudo bash` so archive extraction and
source-control mode changes cannot alter the documented installation path.

### Installer flow

The interactive installer currently guides you through:
- Timeshift snapshot creation
- ZRAM setup
- scheduled ClamAV scan preferences
- live monitoring enable/disable
- live threat action selection
- Maltrail installation and mode
- optional Falco runtime behavior monitoring in alert-only mode
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
- optional Falco runtime sensor:
  - exact package version and repository trust pinned by `installer/supply-chain-lock.json`
  - `falco-modern-bpf.service` with the modern eBPF driver
  - high-signal `ERROR+` rule policy and alert-only Herodium consumption
  - Herodium configuration under `/etc/falco/config.d/herodium.yaml`
  - Herodium rules under `/etc/falco/rules.d/herodium-rules.yaml`
  - JSONL event stream under `/var/log/herodium/falco-events.jsonl`
  - persistent reader state under `/var/lib/herodium/falco`
  - log rotation through `/etc/logrotate.d/herodium-falco`
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

## Falco Runtime Monitoring and Supply-Chain Policy

Falco provides the runtime-behavior layer that file-content scanning alone cannot
provide. Herodium uses ClamAV to inspect files and process-related file content;
Falco independently observes syscall activity from the kernel and applies Falco
rules to security-relevant behavior. The integration is deliberately one-way:
Falco detects and emits events, while Herodium validates, correlates, logs, and
optionally notifies. Falco is never allowed to perform Herodium enforcement
actions such as killing processes, quarantining files, or blocking network
traffic.

The current supply-chain lock pins Falco `0.44.1`, its official DEB repository,
the expected signing-key fingerprint, and the `modern_ebpf` driver. The
installer downloads the signing key as data, verifies the exact trusted
fingerprint, installs the exact package version non-interactively, applies an
APT hold, and disables the `falcoctl` automatic artifact-follow service. This
keeps executable/rule changes tied to an explicit Herodium source and lock-file
update instead of an unattended rules update. Falco's modern eBPF driver is
bundled with Falco and is the upstream default driver on supported systems.

Herodium intentionally configures Falco with:

```yaml
priority: error
```

Falco therefore loads and evaluates only rules with a priority at least as
severe as `ERROR`: `ERROR`, `CRITICAL`, `ALERT`, and `EMERGENCY`. This is a
high-signal endpoint policy rather than a full Falco telemetry feed. Rules at
`WARNING`, `NOTICE`, `INFO`, and `DEBUG` are intentionally not active in this
integration because normal desktop and administrative activity can otherwise
produce excessive alerts. Herodium applies an independent `ERROR` minimum in
its dispatcher as defense in depth.

Herodium also ships a small local Falco rules file. The current custom rule
detects writes below `/etc/systemd/system` and classifies them as `ERROR`, which
keeps persistence-relevant systemd changes visible under the high-signal
policy. Upstream Falco rules at `ERROR` or higher remain available as well.

### Falco event pipeline

```text
Linux kernel syscalls
        |
        v
Falco 0.44.1 + modern eBPF
        |
        v
/var/log/herodium/falco-events.jsonl
        |
        v
strict Falco JSON parser / persistent reader
        |
        v
bounded Falco monitor queue
        |
        v
ERROR+ dispatcher with cooldown/deduplication
        |
        v
Herodium log and optional desktop notification
```

The JSON parser rejects malformed or oversized records, duplicate JSON keys,
unsupported nesting, invalid priorities, and other out-of-contract input. The
Falco JSONL file itself is root-owned and mode `0600`; because it is Falco's
sensor stream, upstream rules may include fields such as command-line context
in that file. Herodium deliberately does not copy raw Falco output or raw
`proc.cmdline` into its processed `herodium.log` alert summaries. The reader
uses a root-owned persistent cursor at
`/var/lib/herodium/falco/cursor.json`, starts at end-of-file on a clean first
installation, handles rename rotation and copy/truncation safely, waits for
partial records, and bounds work per poll. The monitor queue is bounded, and the
dispatcher drains bounded batches with a bounded alert cache and cooldown.

The event log is rotated daily, retained for seven rotations, capped by a
25 MiB `maxsize`, and reopened by signalling Falco after rotation. The event
stream is intentionally preserved across normal upgrades, while the cursor is
preserved so old events are not replayed. During an in-place Herodium upgrade,
the installer temporarily quiesces a Herodium-managed Falco sensor after the
Herodium consumer stops and resumes/validates Falco only after installer-managed
systemd writes are complete. This prevents the installer from generating its
own persistence alerts without adding a broad rule exception or discarding the
persistent cursor.

### Falco ownership and uninstall safety

Herodium records Falco ownership in the private root-owned marker:

```text
/var/lib/herodium/falco/ownership.json
```

The marker distinguishes a Falco package/repository installed by Herodium from
a pre-existing Falco deployment. The installer refuses to silently claim or
reconfigure unowned Falco assets. On uninstall, Herodium purges Falco and its
repository only when the ownership marker is valid and explicitly states that
Herodium created them; otherwise external Falco state is preserved. Herodium's
own Falco config, rules, logrotate policy, cursor, and ownership state are
removed according to that ownership contract.

Operational checks:

```bash
sudo systemctl status falco-modern-bpf.service
sudo tail -f /var/log/herodium/falco-events.jsonl
sudo grep 'Falco alert:' /var/log/herodium/herodium.log | tail
```

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
/var/log/herodium/falco-events.jsonl
/var/lib/herodium/falco/cursor.json
/var/lib/herodium/falco/ownership.json
/etc/falco/config.d/herodium.yaml
/etc/falco/rules.d/herodium-rules.yaml
/etc/logrotate.d/herodium-falco
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

### Check optional Falco runtime sensor

```bash
sudo systemctl status falco-modern-bpf.service
```

Falco's structured event stream can be inspected separately from Herodium's
processed alerts:

```bash
sudo tail -f /var/log/herodium/falco-events.jsonl
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
- `falco.enable`
- `falco.mode` (`alert_only` only)
- `falco.event_log_path`
- `falco.cursor_path`
- `falco.start_position`
- `falco.queue_max_size`
- `falco.dispatch.minimum_priority`
- `falco.dispatch.notification_minimum_priority`
- `falco.dispatch.alert_cooldown_seconds`
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
- Falco disabled in the base YAML unless selected by the installer
- when Falco is enabled, mode is alert-only and both Falco and Herodium use an `ERROR+` minimum
- optional hardening controlled by configuration
- AppArmor default level:
  - `1` — OS default / no Herodium AppArmor changes

## Logs

Main operational logs:

- `/var/log/herodium/herodium.log`
- `/var/log/herodium/scheduled_scan.log`
- `/var/log/herodium/falco-events.jsonl` when Falco is enabled

`herodium.log` contains the bounded, processed Falco alert summary. The raw
Falco JSONL stream is kept separately for the reader contract and does not mean
that every Falco record will be surfaced as a Herodium alert; the dispatcher
still enforces its configured minimum priority and cooldown.

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
- Herodium-specific Falco configuration, rules, logrotate policy, cursor, and ownership state
- a Falco package/repository only when the validated ownership marker shows that Herodium installed them
- Herodium-specific IP sets and firewall rules where applicable

It can also optionally remove related packages installed by the project. A
pre-existing or unowned Falco installation is deliberately preserved rather
than silently purged or reconfigured.

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
- high-signal Falco/eBPF runtime-behavior monitoring
- removable media scanning workflows
- AppArmor automation prototypes
- host-level response automation
- security monitoring research on Debian-based systems

The codebase is intentionally modular so individual components can be replaced, extended, or stripped down depending on the use case.

### Installer reliability and rollback testing

The installer preserves and restores the prior Herodium unit, CLI tools, scheduled-scan assets, deployment manifest, logrotate policy, ClamAV configuration and service/socket/updater state, the previous pinned Maltrail deployment, and Herodium-managed Falco transaction state until the activation transaction passes final health checks. During upgrades a managed Falco sensor is quiesced only for installer-owned systemd writes and is revalidated before Herodium starts. Maltrail is stopped with `SIGINT` so its main process can terminate worker processes cleanly before the timeout. Mutable operator configuration is excluded from the immutable deployment manifest.

Timeshift snapshots are created as on-demand snapshots in a headless command environment without desktop notification helpers and are verified by listing the resulting snapshot before installation continues. This avoids treating a successful snapshot as failed because of an asynchronous desktop-notification error.

A controlled rollback validation can be requested explicitly by running the installer with `HERODIUM_INSTALLER_TEST_FAILPOINT=after_final_validation` and `HERODIUM_INSTALLER_TEST_ACKNOWLEDGE=ROLLBACK-TEST`. This test intentionally fails after all final service checks and must restore the previous deployment and service state; it is not enabled during normal installation. The rollback transaction covers deployed code and installer-managed activation assets. General dependency packages installed before activation are not automatically removed, while a Falco package created by the current uncommitted Falco transaction is purged during Falco rollback. A verified Timeshift snapshot created before activation is never deleted by rollback.
