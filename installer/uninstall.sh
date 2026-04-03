#!/usr/bin/env bash
set -e

# ==============================================================================
# HERODIUM UNINSTALLER
# Safely removes Herodium Security System and optionally its dependencies.
# ==============================================================================

# --- Variables ---
APP_DIR="/opt/herodium"
MALTRAIL_DIR="/opt/maltrail"
LOG_DIR="/var/log/herodium"
MALTRAIL_LOG_DIR="/var/log/maltrail"

# --- Check Root ---
if [[ $EUID -ne 0 ]]; then
   echo "CRITICAL: This script must be run as root (sudo)."
   exit 1
fi

# --- Install UI Dependencies (Whiptail) ---
if ! command -v whiptail &> /dev/null; then
    apt-get update -y && apt-get install -y whiptail
fi

# ==============================================================================
# CONFIRMATION
# ==============================================================================

if ! (whiptail --title "Herodium Uninstaller" --yesno "WARNING: You are about to uninstall Herodium Security System.\n\nThis will:\n1. Stop and remove background services.\n2. Delete application files and logs.\n3. Remove custom security configurations.\n\nAre you sure you want to proceed?" 15 60); then
    echo "[INFO] Uninstallation aborted by user."
    exit 0
fi

echo ""
echo "=========================================="
echo "Starting Uninstallation..."
echo "=========================================="

# 1. Stop and Disable Services
echo "[1/6] Stopping services..."
systemctl stop herodium.service 2>/dev/null || true
systemctl stop maltrail-sensor.service 2>/dev/null || true
systemctl stop herodium-scheduled-scan.timer 2>/dev/null || true
systemctl stop herodium-scheduled-scan.service 2>/dev/null || true

systemctl disable herodium.service 2>/dev/null || true
systemctl disable maltrail-sensor.service 2>/dev/null || true
systemctl disable herodium-scheduled-scan.timer 2>/dev/null || true
systemctl disable herodium-scheduled-scan.service 2>/dev/null || true

# Revert firewall/ipset rules created by Herodium (best effort, idempotent)
echo " -> Reverting Herodium firewall/ipset rules..."

remove_iptables_rule() {
    local bin="$1"
    local chain="$2"
    shift 2
    if command -v "${bin}" &>/dev/null; then
        if "${bin}" -C "${chain}" "$@" 2>/dev/null; then
            "${bin}" -D "${chain}" "$@" 2>/dev/null || true
        fi
    fi
}

# IPv4 rules (iptables)
remove_iptables_rule iptables INPUT  -m set --match-set herodium_blacklist dst -j DROP
remove_iptables_rule iptables INPUT  -m set --match-set herodium_blacklist src -j DROP
remove_iptables_rule iptables OUTPUT -m set --match-set herodium_blacklist dst -j DROP
remove_iptables_rule iptables OUTPUT -m set --match-set herodium_blacklist src -j DROP

# IPv6 rules (ip6tables) - remove if present
remove_iptables_rule ip6tables INPUT  -m set --match-set herodium_blacklist_v6 dst -j DROP
remove_iptables_rule ip6tables INPUT  -m set --match-set herodium_blacklist_v6 src -j DROP
remove_iptables_rule ip6tables OUTPUT -m set --match-set herodium_blacklist_v6 dst -j DROP
remove_iptables_rule ip6tables OUTPUT -m set --match-set herodium_blacklist_v6 src -j DROP

# Remove ipsets if present (after rules removal)
if command -v ipset &>/dev/null; then
    ipset destroy herodium_blacklist 2>/dev/null || true
    ipset destroy herodium_blacklist_v6 2>/dev/null || true
fi

# 2. Remove Systemd Units
echo "[2/6] Removing service files..."
rm -f /etc/systemd/system/herodium.service
rm -f /etc/systemd/system/maltrail-sensor.service
rm -f /etc/systemd/system/herodium-scheduled-scan.service
rm -f /etc/systemd/system/herodium-scheduled-scan.timer
systemctl daemon-reload

# 3. Remove Files and Directories
echo "[3/6] Cleaning up files..."

# Best-effort restore of AppArmor baseline state before deleting Herodium files
if [[ -d /opt/herodium/apparmor_state_data/baseline_force-complain || -d /etc/apparmor.d/force-complain ]]; then
    echo " -> Restoring AppArmor baseline mode state..."

    rm -rf /etc/apparmor.d/force-complain 2>/dev/null || true

    if [[ -d /opt/herodium/apparmor_state_data/baseline_force-complain ]]; then
        cp -a /opt/herodium/apparmor_state_data/baseline_force-complain /etc/apparmor.d/force-complain
    else
        mkdir -p /etc/apparmor.d/force-complain
    fi

    systemctl reload-or-restart apparmor 2>/dev/null || true
    systemctl disable --now auditd 2>/dev/null || true
fi

rm -rf "${APP_DIR}"
rm -rf "${MALTRAIL_DIR}"
rm -rf "${LOG_DIR}"
rm -rf "${MALTRAIL_LOG_DIR}"
rm -rf "/etc/maltrail"
rm -f /etc/logrotate.d/herodium
rm -rf "/etc/herodium"

# Remove Binaries/Scripts
rm -f /usr/local/bin/herodium-scan
rm -f /usr/local/bin/herodium-top
rm -f /usr/local/bin/herodium_scheduled_scan.sh

# Remove Fail2Ban Custom Config
if [[ -f /etc/fail2ban/jail.d/herodium-ddos.conf ]]; then
    echo " -> Removing Fail2Ban Herodium jail..."
    rm -f /etc/fail2ban/jail.d/herodium-ddos.conf
    systemctl restart fail2ban || true
fi

# Remove Custom Signatures
rm -f /var/lib/clamav/herodium.ndb

# 4. Optional: Remove Dependencies
echo "[4/6] Handling dependencies..."
DEPENDENCIES_MSG="Do you want to remove the security packages installed by Herodium?\n(ClamAV, Fail2Ban, Rkhunter, ZRAM, Maltrail libs)\n\nAnswer NO if you used these tools before Herodium."

if (whiptail --title "Remove Dependencies?" --yesno "$DEPENDENCIES_MSG" 15 70); then
    echo "[INFO] Removing dependencies..."
    apt-get remove --purge -y clamav clamav-daemon clamav-freshclam fail2ban rkhunter zram-tools python3-pcapy
    apt-get autoremove -y
    echo "[INFO] Dependencies removed."
else
    echo "[INFO] Keeping dependencies (User selected NO)."
fi

# 5. Optional: Revert ZRAM
if [[ -f /etc/default/zramswap ]]; then
    if (whiptail --title "Disable ZRAM?" --yesno "Do you want to disable ZRAM (Memory Compression)?" 10 60); then
        systemctl stop zramswap 2>/dev/null || true
        systemctl disable zramswap 2>/dev/null || true
        rm -f /etc/default/zramswap
        echo "[INFO] ZRAM disabled."
    fi
fi

# 6. Final Notice about Timeshift
echo "[6/6] Finishing up..."

echo ""
echo "Uninstallation Complete."
echo "---------------------------------------------------------"
echo "NOTE: We did NOT remove the Timeshift snapshots created."
echo "If you wish to fully revert the system state (Kernel/AppArmor),"
echo "please open Timeshift and restore the 'Herodium_Pre_Install' snapshot."
echo "---------------------------------------------------------"

whiptail --msgbox "Uninstallation Complete.\n\nThe system has been cleaned.\n\nTo restore System-Level changes (like AppArmor policies),\nplease use the Timeshift snapshot created during installation." 12 60
