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
FALCO_STATE_DIR="/var/lib/herodium/falco"
FALCO_MARKER_PATH="${FALCO_STATE_DIR}/ownership.json"
FALCO_SOURCE_LIST="/etc/apt/sources.list.d/herodium-falco.list"
FALCO_KEYRING="/usr/share/keyrings/herodium-falco-archive-keyring.gpg"
FALCO_CONFIG_PATH="/etc/falco/config.d/herodium.yaml"
FALCO_RULES_PATH="/etc/falco/rules.d/herodium-rules.yaml"
FALCO_LOGROTATE_PATH="/etc/logrotate.d/herodium-falco"
FALCO_MARKER_VALID="false"
FALCO_PACKAGE_MANAGED="false"
FALCO_REPOSITORY_MANAGED="false"
FALCO_WAS_ACTIVE="false"

# --- Check Root ---
if [[ $EUID -ne 0 ]]; then
   echo "CRITICAL: This script must be run as root (sudo)."
   exit 1
fi

# --- Install UI Dependencies (Whiptail) ---
if ! command -v whiptail &> /dev/null; then
    apt-get update -y && apt-get install -y whiptail
fi



falco_uninstall_package_is_installed() {
    dpkg-query -W -f='${db:Status-Status}\n' falco 2>/dev/null \
        | grep -Fx 'installed' >/dev/null
}

load_falco_uninstall_ownership() {
    local mode
    local parsed

    if [[ ! -e "${FALCO_MARKER_PATH}" ]]; then
        return 0
    fi
    if [[ -L "${FALCO_MARKER_PATH}" || ! -f "${FALCO_MARKER_PATH}" ]]; then
        echo "WARNING: Falco ownership marker is unsafe; Falco package/repository will be preserved."
        return 0
    fi
    if [[ "$(stat -c '%u' -- "${FALCO_MARKER_PATH}")" != "0" ]]; then
        echo "WARNING: Falco ownership marker is not root-owned; Falco package/repository will be preserved."
        return 0
    fi
    mode="$(stat -c '%a' -- "${FALCO_MARKER_PATH}")"
    if (( (8#${mode}) & 0077 )); then
        echo "WARNING: Falco ownership marker is not private; Falco package/repository will be preserved."
        return 0
    fi

    parsed="$(python3 - "${FALCO_MARKER_PATH}" <<'PYFALCOUNINSTALL'
import json
import sys
from pathlib import Path

try:
    data = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
except (OSError, UnicodeError, json.JSONDecodeError) as exc:
    raise SystemExit(f"invalid marker: {exc}")
if set(data) != {
    "schema_version",
    "package_installed_by_herodium",
    "repository_installed_by_herodium",
} or data["schema_version"] != 1:
    raise SystemExit("unexpected marker schema")
for key in (
    "package_installed_by_herodium",
    "repository_installed_by_herodium",
):
    if not isinstance(data[key], bool):
        raise SystemExit(f"non-boolean marker field: {key}")
if data["package_installed_by_herodium"] != data["repository_installed_by_herodium"]:
    raise SystemExit("inconsistent Falco ownership marker")
print(
    "\t".join(
        (
            "true" if data["package_installed_by_herodium"] else "false",
            "true" if data["repository_installed_by_herodium"] else "false",
        )
    )
)
PYFALCOUNINSTALL
)" || {
        echo "WARNING: Falco ownership marker is invalid; Falco package/repository will be preserved."
        return 0
    }

    IFS=$'\t' read -r \
        FALCO_PACKAGE_MANAGED \
        FALCO_REPOSITORY_MANAGED \
        <<< "${parsed}"
    FALCO_MARKER_VALID="true"
}

cleanup_herodium_falco_integration() {
    local remove_package="false"

    if [[ "${FALCO_MARKER_VALID}" != "true" ]]; then
        echo " -> No validated Herodium Falco ownership marker; preserving all Falco state."
        return 0
    fi

    if systemctl is-active --quiet falco.service 2>/dev/null; then
        FALCO_WAS_ACTIVE="true"
    fi

    rm -f -- \
        "${FALCO_CONFIG_PATH}" \
        "${FALCO_RULES_PATH}" \
        "${FALCO_LOGROTATE_PATH}"

    if [[ "${FALCO_MARKER_VALID}" == "true" \
        && "${FALCO_PACKAGE_MANAGED}" == "true" ]] \
        && falco_uninstall_package_is_installed; then
        if whiptail --title "Remove Falco?" --yesno \
            "Falco was originally installed by Herodium.\n\nRemove the Falco package too?\n\nChoose NO if you now use Falco independently." \
            13 70; then
            remove_package="true"
        fi

        apt-mark unhold falco >/dev/null 2>&1 || true
        systemctl unmask falcoctl-artifact-follow.service >/dev/null 2>&1 || true
        if [[ "${remove_package}" == "true" ]]; then
            systemctl stop falco-modern-bpf.service >/dev/null 2>&1 || true
            systemctl disable falco-modern-bpf.service >/dev/null 2>&1 || true
            DEBIAN_FRONTEND=noninteractive apt-get purge -y falco
            echo " -> Herodium-installed Falco package removed."
        elif [[ "${FALCO_WAS_ACTIVE}" == "true" ]]; then
            systemctl restart falco-modern-bpf.service || true
            echo " -> Falco package kept; Herodium-specific configuration removed."
        else
            echo " -> Falco package kept; Herodium-specific configuration removed."
        fi
    elif [[ "${FALCO_WAS_ACTIVE}" == "true" ]]; then
        systemctl restart falco.service || true
        echo " -> Pre-existing Falco kept; Herodium-specific configuration removed."
    fi

    if [[ "${FALCO_MARKER_VALID}" == "true" \
        && "${FALCO_REPOSITORY_MANAGED}" == "true" ]]; then
        rm -f -- "${FALCO_SOURCE_LIST}" "${FALCO_KEYRING}"
        apt-get update -y || true
    fi

    if [[ "${FALCO_MARKER_VALID}" == "true" ]]; then
        rm -f -- "${FALCO_MARKER_PATH}" "${FALCO_STATE_DIR}/cursor.json"
        if [[ -d "${FALCO_STATE_DIR}" && ! -L "${FALCO_STATE_DIR}" ]]; then
            rmdir "${FALCO_STATE_DIR}" 2>/dev/null || true
        fi
    fi
}

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

load_falco_uninstall_ownership

# 1. Stop and Disable Services
echo "[1/6] Stopping services..."
systemctl stop herodium.service 2>/dev/null || true
systemctl stop herodium-maltrail-update.timer 2>/dev/null || true
systemctl stop herodium-maltrail-update.service 2>/dev/null || true
systemctl stop maltrail-sensor.service 2>/dev/null || true
systemctl stop herodium-scheduled-scan.timer 2>/dev/null || true
systemctl stop herodium-scheduled-scan.service 2>/dev/null || true

systemctl disable herodium.service 2>/dev/null || true
systemctl disable herodium-maltrail-update.timer 2>/dev/null || true
systemctl disable herodium-maltrail-update.service 2>/dev/null || true
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
        while "${bin}" -C "${chain}" "$@" 2>/dev/null; do
            "${bin}" -D "${chain}" "$@" 2>/dev/null || break
        done
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
rm -f /etc/systemd/system/herodium-maltrail-update.service
rm -f /etc/systemd/system/herodium-maltrail-update.timer
rm -f /etc/systemd/system/herodium-scheduled-scan.service
rm -f /etc/systemd/system/herodium-scheduled-scan.timer
systemctl daemon-reload

# 3. Remove Files and Directories
echo "[3/6] Cleaning up files..."

# Restore the persistent AppArmor baseline before deleting application files.
# Persistent state remains under /var/lib/herodium so upgrades and reinstalls
# cannot accidentally redefine the pre-Herodium baseline.
APPARMOR_STATE_TOOL="${APP_DIR}/modules/apparmor_state.py"

if [[ -f "${APPARMOR_STATE_TOOL}" ]]; then
    echo " -> Restoring AppArmor baseline mode state..."
    set +e
    python3 "${APPARMOR_STATE_TOOL}" restore
    APPARMOR_RESTORE_RC=$?
    set -e

    if [[ ${APPARMOR_RESTORE_RC} -eq 0 ]]; then
        if systemctl reload-or-restart apparmor; then
            python3 "${APPARMOR_STATE_TOOL}" write-level 1
            echo " -> AppArmor baseline restored; persistent state preserved."
        else
            echo "WARNING: AppArmor baseline files were restored, but AppArmor reload failed."
        fi
    elif [[ ${APPARMOR_RESTORE_RC} -eq 2 ]]; then
        echo " -> No Herodium AppArmor baseline found; leaving force-complain state unchanged."
    else
        echo "WARNING: AppArmor baseline restoration failed; persistent state was preserved for recovery."
    fi
    echo " -> Leaving auditd service state unchanged."
else
    echo "WARNING: AppArmor state tool is unavailable; persistent state was left unchanged."
fi

cleanup_herodium_falco_integration

rm -rf "${APP_DIR}"
rm -rf "${LOG_DIR}"
rm -f /etc/logrotate.d/herodium
rm -rf "/etc/herodium"

# Maltrail may have existed before Herodium.
# Do not remove external Maltrail files unless the user explicitly chooses to.
if [[ -d "${MALTRAIL_DIR}" || -d "${MALTRAIL_LOG_DIR}" || -d "/etc/maltrail" ]]; then
    if (whiptail --title "Remove Maltrail files?" --yesno "Maltrail files/directories were found:\n\n- ${MALTRAIL_DIR}\n- ${MALTRAIL_LOG_DIR}\n- /etc/maltrail\n\nRemove them as part of Herodium uninstall?\n\nChoose NO if Maltrail existed before Herodium or you are not sure." 16 74); then
        rm -rf "${MALTRAIL_DIR}"
        rm -rf "${MALTRAIL_LOG_DIR}"
        rm -rf "/etc/maltrail"
        echo " -> Maltrail files removed."
    else
        echo " -> Keeping Maltrail files/directories."
    fi
fi

# Remove Binaries/Scripts
rm -f /usr/local/bin/herodium-scan
rm -f /usr/local/bin/herodium-top
rm -f /usr/local/sbin/herodium-rkhunter-baseline
rm -f /usr/local/sbin/herodium-maltrail-update
rm -f /usr/local/bin/herodium_scheduled_scan.sh
rm -rf /run/herodium-maltrail-update

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
