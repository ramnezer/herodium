#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# HERODIUM INSTALLER V2.6 (COMPLETE WIZARD)
# ==============================================================================

# --- Variables ---
APP_DIR="/opt/herodium"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# --- Defaults (avoid installer exit on CANCEL / unset choices) ---
ENABLE_ZRAM="false"
LIVE_SCAN="true"
INSTALL_MALTRAIL="false"
MALTRAIL_ACTION="alert"
CLEAN_INTERVAL="weekly"
INSTALL_FAIL2BAN="false"
INSTALL_RKHUNTER="false"
RK_FREQ="weekly"
ENABLE_HARDENING="false"
CLAM_SCAN_TYPE="HOME"
CLAM_FREQ="weekly"
THREAT_ACTION="quarantine"
SCHED_THREAT_ACTION="quarantine"
APPARMOR_LEVEL="2"
# --- Runtime status for final summary ---
SNAPSHOT_STATUS="Skipped"
ZRAM_STATUS="Disabled"

# --- Check Root ---
if [[ $EUID -ne 0 ]]; then
   echo "CRITICAL: This script must be run as root (sudo)."
   exit 1
fi

# --- Install UI Dependencies (Whiptail) ---
if ! command -v whiptail &> /dev/null; then
    echo "Installing installer UI dependencies..."
    apt-get update -y && apt-get install -y whiptail
fi

# ==============================================================================
# WIZARD FUNCTIONS
# ==============================================================================

welcome_msg() {
    whiptail --title "Herodium Security Installer" --msgbox "Welcome to Herodium Auto-Security System Installer.\n\nWe will now guide you through the security configuration.\n\nKey features: Backup, Antivirus, Network Defense, and Hardening." 12 70
}

# --- 1. Backup Strategy (Timeshift) ---

setup_timeshift() {
    if (whiptail --title "Step 1: System Backup" --yesno "Before applying security changes, it is CRITICAL to create a system snapshot.\n\nThis allows you to rollback if the hardening breaks any functionality.\n\nDo you want to install Timeshift and create a snapshot now?" 15 70); then
        
        echo "[INFO] Installing Timeshift..."
        apt-get install -y timeshift

        # Check disk space (safety)
        FREE_SPACE=$(df / --output=avail | tail -1)
        if [[ "$FREE_SPACE" -lt 10000000 ]]; then # 10GB roughly
             whiptail --msgbox "WARNING: Low disk space (<10GB). Snapshot creation skipped to prevent crash." 8 60
             SNAPSHOT_STATUS="Skipped (Low disk space)"
        else
             echo "[INFO] Configuring Timeshift target device..."
             
             # Auto-detect Root UUID
             ROOT_UUID=$(findmnt -n -o UUID /)
             
             if [[ -z "$ROOT_UUID" ]]; then
                 echo "Warning: Could not detect Root UUID. Skipping auto-config."
             else
                 echo " -> Detected Root UUID: $ROOT_UUID"
                 
# Create configuration manually to bypass CLI issues
mkdir -p /etc/timeshift

TS_CFG="/etc/timeshift/timeshift.json"
TS_ALT="/etc/timeshift.json"

backup_ts_cfg() {
    local f="$1"
    if [[ -f "$f" ]]; then
        local bak="${f}.bak-$(date +%Y%m%d-%H%M%S)"
        cp -a "$f" "$bak" 2>/dev/null || true
        echo " -> Existing Timeshift config backed up: $bak"
    fi
}

# Backup any existing configs (different distros/versions may use different paths)
backup_ts_cfg "$TS_CFG"
backup_ts_cfg "$TS_ALT"

# If Timeshift is already configured, do NOT overwrite user settings
if [[ -f "$TS_CFG" || -f "$TS_ALT" ]]; then
    echo " -> Existing Timeshift configuration detected (leaving it unchanged)"
else
    cat <<EOF > "${TS_CFG}"
{
  "backup_device_uuid" : "$ROOT_UUID",
  "parent_device_uuid" : "",
  "do_first_run" : "false",
  "btrfs_mode" : "false",
  "include_btrfs_home" : "false",
  "stop_cron_emails" : "true",
  "schedule_monthly" : "false",
  "schedule_weekly" : "false",
  "schedule_daily" : "false",
  "schedule_hourly" : "false",
  "schedule_boot" : "false",
  "count_monthly" : "2",
  "count_weekly" : "3",
  "count_daily" : "5",
  "count_hourly" : "6",
  "count_boot" : "5",
  "snapshot_size" : "0",
  "snapshot_count" : "0",
  "exclude" : [
    "/home/*/.cache/***",
    "/root/.cache/***",
    "/var/cache/***"
  ],
  "exclude-apps" : []
}
EOF
    chmod 0644 "${TS_CFG}" || true
    echo " -> Configuration written to ${TS_CFG}"
fi

# IMPORTANT: close the ROOT_UUID if/else (make sure this fi exists in your file)
fi

             
             echo "[INFO] Creating Snapshot (Label: Herodium_Pre_Install)..."
             # 
             if timeshift --create --comments "Herodium_Pre_Install" --tags D --yes; then
                 SNAPSHOT_STATUS="Created (Herodium_Pre_Install)"
             else
                 SNAPSHOT_STATUS="Attempted (check Timeshift logs)"
             fi

             
             whiptail --msgbox "Snapshot process completed. Check Timeshift logs if unsure." 8 60
        fi
    fi
}

# --- 2. ZRAM (Memory Optimization) ---
setup_zram() {
    if (whiptail --title "Step 2: Memory Optimization (ZRAM)" --yesno "ZRAM compresses data in RAM effectively doubling your memory.\n\nThis is vital for running ClamAV and Maltrail together on older hardware.\n\nInstall and configure ZRAM (Default: 50% RAM)?" 15 70); then
        ENABLE_ZRAM="true"
        ZRAM_STATUS="Enabled (50% RAM)"
        echo "[INFO] Configuring ZRAM..."
        apt-get install -y zram-tools
        
        # Write config
        mkdir -p /etc/default
        echo "ALGO=zstd" > /etc/default/zramswap
        echo "PERCENT=50" >> /etc/default/zramswap
        
        systemctl restart zramswap || true
    fi
}

# --- 3. ClamAV Configuration ---
ask_clamav_prefs() {
    # 3.1 Scheduled Scan
    CLAM_SCAN_TYPE=$(whiptail --title "Step 3a: Antivirus Scheduler" --menu "Choose Scheduled Scan Type:" 15 70 2 \
        "HOME" "Scan /home directories only" \
        "FULL" "Scan Entire System" 3>&1 1>&2 2>&3) || CLAM_SCAN_TYPE="HOME"

    CLAM_FREQ=$(whiptail --title "Step 3a: Antivirus Scheduler" --menu "Choose Frequency:" 15 70 3 \
        "daily" "Once a day" \
        "weekly" "Once a week" \
        "monthly" "Once a month" 3>&1 1>&2 2>&3) || CLAM_FREQ="weekly"

    # 3.2 Scheduled Scan Threat Handling (separate from Live Monitor)
    SCHED_THREAT_ACTION=$(whiptail --title "Step 3b: Scheduled Scan Threat Handling" --menu "When scheduled scans find a threat, what should happen?" 15 70 3 \
        "quarantine" "Move to Quarantine (Recommended)" \
        "delete" "Delete immediately (Risky)" \
        "alert" "Alert only (Log)" 3>&1 1>&2 2>&3) || SCHED_THREAT_ACTION="quarantine"


    # 3.2 Live Monitor
    LIVE_SCAN="false"
    if (whiptail --title "Step 3b: Live Monitor" --yesno "Enable Live Real-Time Scanning?\n\nModules:\n- RAM Memory Hunter\n- USB/External Drive Sentry\n- Home Directory Watcher\n\n(Consumes more RAM)" 15 70); then
        LIVE_SCAN="true"
    fi

    # 3.3 Threat Handling
    THREAT_ACTION=$(whiptail --title "Step 3c: Live Monitor Threat Handling" --menu "When LIVE monitoring finds a threat, what should happen?" 15 70 3 \
        "quarantine" "Move to Quarantine (Recommended)" \
        "delete" "Delete immediately (Risky)" \
        "alert" "Alert only (Log)" 3>&1 1>&2 2>&3) || THREAT_ACTION="quarantine"
}

# --- 4. Network Defense (Maltrail) ---
ask_maltrail_prefs() {
    MALTRAIL_ACTION="alert"
    CLEAN_INTERVAL="weekly"

    if (whiptail --title "Step 4: Network Defense" --yesno "Install Maltrail (Malicious Traffic Detection)?\n\nDetects port scans, attackers, and malware beacons." 15 70); then
        INSTALL_MALTRAIL="true"
        
        BLOCK_CHOICE=$(whiptail --title "Maltrail Mode" --menu "Choose Protection Mode:" 15 70 2 \
            "alert" "Alert Only (Passive)" \
            "block" "Block Attackers (Active IPS)" 3>&1 1>&2 2>&3) || BLOCK_CHOICE="alert"
        
        if [[ "$BLOCK_CHOICE" == "block" ]]; then
            MALTRAIL_ACTION="block"
            CLEAN_INTERVAL=$(whiptail --title "List Cleaning" --menu "How often to clear the blocklist?" 15 70 2 \
                "daily" "Every 24 Hours (Low False Positives)" \
                "weekly" "Every 7 Days (Stricter)" 3>&1 1>&2 2>&3) || CLEAN_INTERVAL="weekly"
        fi
    else
        INSTALL_MALTRAIL="false"
    fi
}

# --- 5. Fail2Ban anti-brute-force attacks ---
ask_fail2ban_prefs() {
    INSTALL_FAIL2BAN="false"
    if (whiptail --title "Step 5: Anti-brute-force Protection" --yesno "Install Fail2Ban with Anti-brute-force configuration?\n\nThis will configure SSH protection with aggressive ban policies to mitigate brute-force attacks.\n\nRecommended: YES" 15 70); then
        INSTALL_FAIL2BAN="true"
    fi
}

# --- 6. AppArmor & Hardening ---
ask_system_hardening() {
    # 6.1 AppArmor
    APPARMOR_LEVEL=$(whiptail --title "Step 6: AppArmor Level" --menu "Select AppArmor Strictness:" 15 70 4 \
        "1" "Default (OS Default)" \
        "2" "Light (Complain Mode - Logging only)" \
        "3" "Medium (Enforce - Blocks known threats)" \
        "4" "Strong (Full Audit - May break apps)" 3>&1 1>&2 2>&3) || APPARMOR_LEVEL="2"

    if [[ "$APPARMOR_LEVEL" -ge 3 ]]; then
        if (whiptail --yesno "High security level selected.\nCreate another specific backup before applying AppArmor rules?" 10 60); then
             timeshift --create --comments "Pre_AppArmor_Change" --tags O || true
        fi
    fi

    # 6.2 Hardening (Sysctl)
    ENABLE_HARDENING="false"
    if (whiptail --title "Step 7: Kernel Hardening" --yesno "WARNING: Apply Kernel Network Hardening?\n\nPrevents IP Spoofing and Redirects.\n\nNOT RECOMMENDED for beginners or complex network setups (Bridges/VPNs).\n\nApply?" 15 70); then
        ENABLE_HARDENING="true"
    fi

    # 6.3 Rkhunter
    INSTALL_RKHUNTER="false"
    if (whiptail --title "Step 8: Rootkit Hunter" --yesno "Install Rkhunter (Rootkit Scanner)?" 10 60); then
        INSTALL_RKHUNTER="true"
        RK_FREQ=$(whiptail --menu "Rkhunter Scan Frequency:" 15 60 2 "daily" "Daily" "weekly" "Weekly" 3>&1 1>&2 2>&3) || RK_FREQ="weekly"
    fi
}


# --- 7. Fail2Ban Installation Function ---
setup_fail2ban_ddos() {
    if [[ "$INSTALL_FAIL2BAN" == "true" ]]; then
        echo "[INFO] Installing and configuring Fail2Ban (anti-brute-force attacks)..."
        apt-get install -y fail2ban
        
        # Write optimized DDoS config directly
        cat <<EOF > /etc/fail2ban/jail.d/herodium-ddos.conf
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
backend = systemd
# DDoS Logic:
maxretry = 3
findtime = 60
bantime = 1h
bantime.increment = true
EOF
        systemctl restart fail2ban
        echo "[INFO] Fail2Ban configured for anti-brute-force."
    else
        echo "[INFO] Skipping Fail2Ban installation."
    fi
}

# ==============================================================================
# MAIN INSTALLATION LOGIC
# ==============================================================================

# 1. Run Wizard
welcome_msg
setup_timeshift
setup_zram
ask_clamav_prefs
ask_maltrail_prefs
ask_fail2ban_prefs
ask_system_hardening

# 2. Base System Dependencies
echo "[INFO] Installing base dependencies..."
apt-get update -y
apt-get install -y python3 python3-venv python3-pip python3-dev git rsync curl build-essential procps ipset iptables apparmor apparmor-utils apparmor-profiles clamav clamav-daemon clamav-freshclam

if [[ "${APPARMOR_LEVEL}" == "4" ]]; then
    echo "[INFO] Installing AppArmor Level 4 extra dependencies..."
    apt-get install -y apparmor-profiles-extra auditd
fi

if [[ "$INSTALL_RKHUNTER" == "true" ]]; then
    apt-get install -y rkhunter
    echo "[INFO] Updating Rkhunter baseline properties (Essential)..."
    rkhunter --propupd
fi

# 3. Fail2Ban Installation (Now conditional)
setup_fail2ban_ddos

# 4. FIX AND CONFIGURE CLAMAV
echo "[INFO] Configuring ClamAV socket and database..."
systemctl stop clamav-daemon || true
systemctl stop clamav-freshclam || true

if grep -q "LocalSocket " /etc/clamav/clamd.conf; then
    sed -i 's|^LocalSocket .*|LocalSocket /var/run/clamav/clamd.ctl|' /etc/clamav/clamd.conf
else
    echo "LocalSocket /var/run/clamav/clamd.ctl" >> /etc/clamav/clamd.conf
fi

mkdir -p /var/run/clamav
chown clamav:clamav /var/run/clamav

if [[ ! -f /var/lib/clamav/main.cvd && ! -f /var/lib/clamav/main.cld ]]; then
    echo " -> Virus database missing. Downloading initial database..."
    freshclam --no-dns || true
fi

systemctl enable clamav-daemon
systemctl start clamav-daemon

echo " -> Waiting for ClamAV Socket..."
MAX_RETRIES=45
COUNT=0
while [[ ! -S /var/run/clamav/clamd.ctl ]]; do
    sleep 1
    COUNT=$((COUNT + 1))
    if [[ $COUNT -ge $MAX_RETRIES ]]; then
        echo "WARNING: ClamAV socket did not appear after 45 seconds."
        break
    fi
done

# 5. Deploy Code
echo "[INFO] Deploying Herodium code..."
mkdir -p "${APP_DIR}"
rsync -a --delete --exclude "venv/" --exclude "logs/" --exclude "quarantine/" "${REPO_DIR}/herodium/" "${APP_DIR}/"

# --- Ownership/Permissions Hardening (important: prevent user-level tampering) ---
echo "[INFO] Hardening /opt/herodium permissions..."
chown -R root:root "${APP_DIR}" || true
chmod 755 "${APP_DIR}" || true
chmod -R go-w "${APP_DIR}" || true
chmod 700 "${APP_DIR}/quarantine" 2>/dev/null || true
chmod 755 "${APP_DIR}/config" 2>/dev/null || true
chmod 640 "${APP_DIR}/config/herodium.yaml" 2>/dev/null || true

# 6. Logs & Dirs
mkdir -p /var/log/herodium "${APP_DIR}/quarantine"
chmod 700 "${APP_DIR}/quarantine"

# --- Secure Herodium logs (root only) ---
# Ensure log directory is private
chown root:root /var/log/herodium || true
chmod 0700 /var/log/herodium || true

# Ensure main log files exist with secure perms (do NOT clobber if already exists)
for f in /var/log/herodium/herodium.log /var/log/herodium/scheduled_scan.log; do
  if [[ ! -f "$f" ]]; then
    install -m 0600 -o root -g root /dev/null "$f" || true
  else
    chown root:root "$f" || true
    chmod 0600 "$f" || true
  fi
done

# Tighten any other *.log files that may already exist (best-effort)
find /var/log/herodium -maxdepth 1 -type f -name '*.log' -exec chmod 0600 {} + 2>/dev/null || true

if [[ -e "${APP_DIR}/logs" && ! -L "${APP_DIR}/logs" ]]; then
  if [[ -d "${APP_DIR}/logs" && -z "$(ls -A "${APP_DIR}/logs" 2>/dev/null || true)" ]]; then
    rmdir "${APP_DIR}/logs" || true
  fi
fi
if [[ ! -e "${APP_DIR}/logs" ]]; then
  ln -s /var/log/herodium "${APP_DIR}/logs"
fi

# 6.5 Log rotation (prevents unlimited log growth)
if ! command -v logrotate >/dev/null 2>&1; then

  apt-get install -y logrotate
fi

cat >/etc/logrotate.d/herodium <<'EOF'
/var/log/herodium/*.log {
  weekly
  rotate 8
  compress
  delaycompress
  missingok
  notifempty
  copytruncate
# Secure permissions for log files (Only root can read/write)
# NOTE: 'create' is largely ignored when 'copytruncate' is used,
# but it is set to 0600 here for safety if copytruncate is ever removed.
  create 0600 root root
}
EOF

# 7. Python Venv
echo "[INFO] Setting up Python environment..."
python3 -m venv "${APP_DIR}/venv"
"${APP_DIR}/venv/bin/pip" install --upgrade pip wheel setuptools
"${APP_DIR}/venv/bin/pip" install -r "${APP_DIR}/requirements.txt"

# 8. Update Configuration
echo "[INFO] Updating Configuration based on your choices..."

"${APP_DIR}/venv/bin/python3" - <<END
import yaml

config_path = "${APP_DIR}/config/herodium.yaml"
try:
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f) or {}

    # --- UPDATED LOGIC: Correctly set intervals based on scan type ---
    if 'scheduler' not in config: config['scheduler'] = {}
    
    # 1. Determine base interval
    freq_map = {'daily': 24, 'weekly': 168, 'monthly': 720}
    interval = freq_map.get("${CLAM_FREQ}", 168)
    
    # 2. Apply based on Type (Home vs Full)
    # Scheduled scans are handled by systemd timer (avoid duplicate scans in engine)
    config['scheduler']['scan_via_systemd'] = True
    config['scheduler']['scan_type'] = "${CLAM_SCAN_TYPE}"
    config['scheduler']['scan_frequency'] = "${CLAM_FREQ}"
    config['scheduler']['home_scan_interval_hours'] = 0
    config['scheduler']['full_scan_interval_hours'] = 0

    # Rkhunter schedule (disable if not installed)
    if "${INSTALL_RKHUNTER}" == "true":
        config['scheduler']['rkhunter_interval_hours'] = 24 if "${RK_FREQ}" == "daily" else 168
    else:
        config['scheduler']['rkhunter_interval_hours'] = 0
    
    if 'clamav' not in config: config['clamav'] = {}
    config['clamav']['threat_action'] = "${THREAT_ACTION}"
    # --- ClamAV size limits (align defaults with clamd.conf) ---
    # NOTE: Herodium uses these as a prefilter. clamd.conf is still the hard limit.
    config['clamav'].setdefault('max_file_size_mb', 25)
    config['clamav'].setdefault('stream_max_length_mb', config['clamav'].get('max_file_size_mb', 25))
    # Scheduled scan policy
    config['scheduler']['threat_action'] = "${SCHED_THREAT_ACTION}"

    # Live Monitor flag
    if 'live_monitor' not in config: config['live_monitor'] = {}
    config['live_monitor']['enable'] = True if "${LIVE_SCAN}" == "true" else False
 

    # Update Maltrail
    if 'maltrail' not in config: config['maltrail'] = {}
    config['maltrail']['enable'] = True if "${INSTALL_MALTRAIL}" == "true" else False
    config['maltrail']['block_traffic'] = True if "${MALTRAIL_ACTION}" == "block" else False
    config['maltrail']['clean_interval_hours'] = 24 if "${CLEAN_INTERVAL}" == "daily" else 168

    # Update IPS (Fail2Ban State)
    if 'ips' not in config: config['ips'] = {}
    config['ips']['enable'] = True if "${INSTALL_FAIL2BAN}" == "true" else False

    # Update AppArmor
    if 'apparmor' not in config: config['apparmor'] = {}
    config['apparmor']['level'] = int("${APPARMOR_LEVEL}")

    # Update Hardening
    if 'hardening' not in config: config['hardening'] = {}
    config['hardening']['enable'] = True if "${ENABLE_HARDENING}" == "true" else False

    # ZRAM enable flag
    if 'performance' not in config: config['performance'] = {}
    config['performance']['enable_zram'] = True if "${ENABLE_ZRAM}" == "true" else False

    # Save
    with open(config_path, 'w') as f:
        yaml.safe_dump(config, f, sort_keys=False, default_flow_style=False)
    print("YAML Config updated successfully.")
except Exception as e:
    print(f"Error updating config: {e}")
END

# 9. Install Maltrail
if [[ "$INSTALL_MALTRAIL" == "true" ]]; then
    echo "[INFO] Installing Maltrail..."
    MALTRAIL_DIR="/opt/maltrail"
    if [[ ! -d "${MALTRAIL_DIR}/.git" ]]; then
        git clone --depth 1 https://github.com/stamparm/maltrail.git "${MALTRAIL_DIR}"
    else
        git -C "${MALTRAIL_DIR}" pull --ff-only || true
    fi
    apt-get install -y python3-pcapy-ng || apt-get install -y python3-pcapy
    mkdir -p /etc/maltrail /var/log/maltrail
    if [[ ! -f /etc/maltrail/maltrail.conf ]]; then
        cp "${MALTRAIL_DIR}/maltrail.conf" /etc/maltrail/maltrail.conf
    fi
    install -m 0644 "${REPO_DIR}/installer/systemd/maltrail-sensor.service" /etc/systemd/system/maltrail-sensor.service
    systemctl enable --now maltrail-sensor.service
fi

# 10. Final Systemd Setup
echo "[INFO] Installing Herodium Service..."
install -m 0644 "${REPO_DIR}/installer/systemd/herodium.service" /etc/systemd/system/herodium.service
install -m 0755 "${REPO_DIR}/installer/bin/herodium-scan" /usr/local/bin/herodium-scan
install -m 0755 "${REPO_DIR}/installer/bin/herodium-top" /usr/local/bin/herodium-top

systemctl daemon-reload
systemctl enable herodium.service
systemctl restart herodium.service

# 11. Configure ClamAV Scheduled Scans (POLICY-AWARE)
SCAN_TARGET="/"
if [[ "$CLAM_SCAN_TYPE" == "HOME" ]]; then
    SCAN_TARGET="/home"
fi

echo "[INFO] Writing scheduled scan config..."
install -d -m 0755 /etc/herodium
cat >/etc/herodium/scheduled_scan.conf <<EOF
SCAN_TARGET="${SCAN_TARGET}"
ACTION="${SCHED_THREAT_ACTION}"
QDIR="${APP_DIR}/quarantine"
EOF
chmod 0644 /etc/herodium/scheduled_scan.conf

echo "[INFO] Installing scheduled scan script..."
cat >/usr/local/bin/herodium_scheduled_scan.sh <<'BASH'
#!/usr/bin/env bash
set -euo pipefail

# English comments only
LOGDIR="/var/log/herodium"
LOGFILE="${LOGDIR}/scheduled_scan.log"
mkdir -p "${LOGDIR}"
touch "${LOGFILE}"
chmod 0600 "${LOGFILE}" || true
exec >>"${LOGFILE}" 2>&1

echo "==== Herodium Scheduled Scan: $(date) ===="

# Load installer-provided config if present
CONF="/etc/herodium/scheduled_scan.conf"
if [[ -f "${CONF}" ]]; then
  # shellcheck disable=SC1090
  source "${CONF}"
fi

: "${SCAN_TARGET:=/home}"
: "${ACTION:=quarantine}"
: "${QDIR:=/opt/herodium/quarantine}"

echo "[INFO] Starting scan: target=${SCAN_TARGET} action=${ACTION}"

case "${ACTION}" in
  delete)
    clamdscan --fdpass --multiscan --remove=yes -- "${SCAN_TARGET}"
    ;;
  quarantine)
    mkdir -p "${QDIR}"
    chmod 700 "${QDIR}" || true
    clamdscan --fdpass --multiscan --move="${QDIR}" -- "${SCAN_TARGET}"
    ;;
  alert|*)
    clamdscan --fdpass --multiscan -- "${SCAN_TARGET}"
    ;;
esac

echo "[INFO] Scan finished with exit code: $?"
BASH
chmod 0755 /usr/local/bin/herodium_scheduled_scan.sh

# --- Systemd timer for scheduled scan (stable scheduling) ---
echo "[INFO] Installing systemd timer for scheduled scans..."

# Choose schedule time (03:15) based on CLAM_FREQ
ONCAL="*-*-* 03:15:00"
case "${CLAM_FREQ}" in
  daily)   ONCAL="*-*-* 03:15:00" ;;
  weekly)  ONCAL="Sun *-*-* 03:15:00" ;;
  monthly) ONCAL="*-*-01 03:15:00" ;;
esac

cat >/etc/systemd/system/herodium-scheduled-scan.service <<'EOF'
[Unit]
Description=Herodium Scheduled ClamAV Scan
After=clamav-daemon.service network.target
Wants=clamav-daemon.service

[Service]
Type=oneshot
# Treat "threats found" (exit code 1) as success
SuccessExitStatus=0 1
Nice=19
IOSchedulingClass=idle
ExecStartPre=/bin/bash -c 'for i in $(seq 1 60); do [[ -S /var/run/clamav/clamd.ctl ]] && exit 0; sleep 1; done; exit 1'
ExecStart=/usr/local/bin/herodium_scheduled_scan.sh
TimeoutStartSec=21600
EOF

# Write timer with the chosen OnCalendar
cat >/etc/systemd/system/herodium-scheduled-scan.timer <<EOF
[Unit]
Description=Run Herodium scheduled scan (${CLAM_FREQ})

[Timer]
OnCalendar=${ONCAL}
Persistent=true
RandomizedDelaySec=1800
Unit=herodium-scheduled-scan.service

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now herodium-scheduled-scan.timer


# The waiting time is intended to ensure that important services are loaded after installation.
echo ""
echo "Please wait, this will take some time..."
echo ""
sleep 120
echo ""
echo "Installation Complete!"
# --- Build final summary ---
CLAMAV_SUMMARY="Live=${LIVE_SCAN} (${THREAT_ACTION}), Scheduled=${CLAM_SCAN_TYPE}/${CLAM_FREQ} (${SCHED_THREAT_ACTION})"

MALTRAIL_SUMMARY="Not installed"
if [[ "${INSTALL_MALTRAIL}" == "true" ]]; then
  if [[ "${MALTRAIL_ACTION}" == "block" ]]; then
    MALTRAIL_SUMMARY="Installed (BLOCK, clean=${CLEAN_INTERVAL})"
  else
    MALTRAIL_SUMMARY="Installed (ALERT only)"
  fi
fi

RKHUNTER_SUMMARY="Not installed"
if [[ "${INSTALL_RKHUNTER}" == "true" ]]; then
  RKHUNTER_SUMMARY="Installed (${RK_FREQ})"
fi

whiptail --msgbox "Installation Complete!\n\n- Snapshot: ${SNAPSHOT_STATUS}\n- ZRAM: ${ZRAM_STATUS}\n- ClamAV: ${CLAMAV_SUMMARY}\n- Maltrail: ${MALTRAIL_SUMMARY}\n- Rkhunter: ${RKHUNTER_SUMMARY}\n- Fail2Ban: ${INSTALL_FAIL2BAN}\n- AppArmor: Level ${APPARMOR_LEVEL}\n\nRun 'sudo herodium-top' to monitor." 18 78

