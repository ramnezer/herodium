#!/usr/bin/env bash
set -Eeuo pipefail

# ==============================================================================
# HERODIUM INSTALLER (COMPLETE WIZARD)
# ==============================================================================

# --- Variables ---
APP_DIR="/opt/herodium"
APP_STAGE_DIR="/opt/herodium.stage"
APP_PREVIOUS_DIR="/opt/herodium.previous"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SUPPLY_CHAIN_LOCK="${REPO_DIR}/installer/supply-chain-lock.json"
PYTHON_TOOLS_LOCK="${REPO_DIR}/installer/python-tools.lock"
RUNTIME_REQUIREMENTS_LOCK="${REPO_DIR}/herodium/requirements.lock"
DEPLOYMENT_MANIFEST_DIR="/var/lib/herodium/supply-chain"
DEPLOYMENT_MANIFEST_PATH="${DEPLOYMENT_MANIFEST_DIR}/herodium-deployment.sha256"
SOURCE_MANIFEST_TMP=""
HERODIUM_LOG_VERIFY_OFFSET=0
MALTRAIL_DIR="/opt/maltrail"
MALTRAIL_PREVIOUS_DIR="/opt/maltrail.previous"
MALTRAIL_STATE_BASE="/var/lib/maltrail"
MALTRAIL_REPOSITORY=""
MALTRAIL_COMMIT=""
MALTRAIL_LICENSE_SHA256=""

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
APPARMOR_LEVEL="1"
# --- Runtime status for final summary ---
SNAPSHOT_STATUS="Skipped"
ZRAM_STATUS="Disabled"

# --- Existing service quiesce / transactional deployment state ---
HERODIUM_WAS_ACTIVE="false"
HERODIUM_ENABLEMENT=""
HERODIUM_CURRENT_ROTATED="false"
HERODIUM_NEW_INSTALLED="false"
HERODIUM_DEPLOYMENT_COMMITTED="false"
HERODIUM_UNIT_EXISTED="false"
HERODIUM_UNIT_CHANGED="false"
HERODIUM_UNIT_BACKUP=""
HERODIUM_CLI_CHANGED="false"
HERODIUM_SCAN_EXISTED="false"
HERODIUM_SCAN_BACKUP=""
HERODIUM_TOP_EXISTED="false"
HERODIUM_TOP_BACKUP=""
HERODIUM_RKHUNTER_TOOL_EXISTED="false"
HERODIUM_RKHUNTER_TOOL_BACKUP=""
HERODIUM_LOGROTATE_EXISTED="false"
HERODIUM_LOGROTATE_CHANGED="false"
HERODIUM_LOGROTATE_BACKUP=""
DEPLOYMENT_MANIFEST_EXISTED="false"
DEPLOYMENT_MANIFEST_CHANGED="false"
DEPLOYMENT_MANIFEST_BACKUP=""
INSTALL_PHASE="pre_quiesce"

# --- Installer-wide service/config transaction state ---
CLAMAV_STATE_CAPTURED="false"
CLAMAV_CONFIG_CHANGED="false"
CLAMAV_CONFIG_EXISTED="false"
CLAMAV_CONFIG_BACKUP=""
CLAMAV_CONFIG_MODE="0644"
CLAMAV_CONFIG_UID="0"
CLAMAV_CONFIG_GID="0"
CLAMAV_DAEMON_WAS_ACTIVE="false"
CLAMAV_DAEMON_ENABLEMENT=""
CLAMAV_SOCKET_WAS_ACTIVE="false"
CLAMAV_SOCKET_ENABLEMENT=""
CLAMAV_FRESHCLAM_WAS_ACTIVE="false"
CLAMAV_FRESHCLAM_ENABLEMENT=""

MALTRAIL_TRANSACTION_STARTED="false"
MALTRAIL_TRANSACTION_READY="false"
MALTRAIL_WAS_ACTIVE="false"
MALTRAIL_ENABLEMENT=""
MALTRAIL_CURRENT_ROTATED="false"
MALTRAIL_NEW_INSTALLED="false"
MALTRAIL_UNIT_EXISTED="false"
MALTRAIL_UNIT_CHANGED="false"
MALTRAIL_UNIT_BACKUP=""
MALTRAIL_CONFIG_EXISTED="false"
MALTRAIL_CONFIG_CHANGED="false"
MALTRAIL_CONFIG_BACKUP=""
MALTRAIL_ENV_EXISTED="false"
MALTRAIL_ENV_CHANGED="false"
MALTRAIL_ENV_BACKUP=""
MALTRAIL_MARKER_EXISTED="false"
MALTRAIL_MARKER_CHANGED="false"
MALTRAIL_MARKER_BACKUP=""
MALTRAIL_PENDING_COMMIT=""
MALTRAIL_STATE_DIR=""
MALTRAIL_STATE_DIR_EXISTED="false"
MALTRAIL_FETCH_DIR=""
MALTRAIL_STAGE_DIR=""

SCHEDULED_ASSETS_CHANGED="false"
SCHEDULED_TIMER_WAS_ACTIVE="false"
SCHEDULED_TIMER_ENABLEMENT=""
SCHEDULED_CONF_EXISTED="false"
SCHEDULED_CONF_BACKUP=""
SCHEDULED_SCRIPT_EXISTED="false"
SCHEDULED_SCRIPT_BACKUP=""
SCHEDULED_SERVICE_EXISTED="false"
SCHEDULED_SERVICE_BACKUP=""
SCHEDULED_TIMER_EXISTED="false"
SCHEDULED_TIMER_BACKUP=""

remove_safe_directory() {
    local path="$1"

    if [[ -L "${path}" ]]; then
        echo "[CRITICAL] Refusing to remove symlinked installer path: ${path}"
        return 1
    fi
    if [[ -e "${path}" ]]; then
        rm -rf --one-file-system -- "${path}"
    fi
}

ensure_safe_root_directory() {
    local path="$1"
    local target_mode="$2"
    local current_mode

    if [[ -L "${path}" || ( -e "${path}" && ! -d "${path}" ) ]]; then
        echo "[CRITICAL] Installer directory is not a safe directory: ${path}"
        return 1
    fi
    if [[ -d "${path}" ]]; then
        if [[ "$(stat -c '%u' -- "${path}")" != "0" ]]; then
            echo "[CRITICAL] Installer directory must be owned by root: ${path}"
            return 1
        fi
        current_mode="$(stat -c '%a' -- "${path}")"
        if (( (8#${current_mode}) & 0022 )); then
            echo "[CRITICAL] Installer directory must not be group/world-writable: ${path}"
            return 1
        fi
    fi
    install -d -o root -g root -m "${target_mode}" "${path}"
}

backup_activation_file() {
    local path="$1"
    local existed_variable="$2"
    local backup_variable="$3"
    local backup
    local mode

    if [[ ! -e "${path}" ]]; then
        printf -v "${existed_variable}" '%s' "false"
        printf -v "${backup_variable}" '%s' ""
        return 0
    fi
    if [[ -L "${path}" || ! -f "${path}" ]]; then
        echo "[CRITICAL] Existing activation asset is not a safe regular file: ${path}"
        return 1
    fi
    if [[ "$(stat -c '%u' -- "${path}")" != "0" ]]; then
        echo "[CRITICAL] Existing activation asset must be owned by root: ${path}"
        return 1
    fi
    mode="$(stat -c '%a' -- "${path}")"
    if (( (8#${mode}) & 0022 )); then
        echo "[CRITICAL] Existing activation asset must not be group/world-writable: ${path}"
        return 1
    fi

    backup="$(mktemp /run/herodium-activation.XXXXXX)"
    install -o root -g root -m 0600 "${path}" "${backup}"
    printf -v "${existed_variable}" '%s' "true"
    printf -v "${backup_variable}" '%s' "${backup}"
}

restore_activation_file() {
    local path="$1"
    local existed="$2"
    local backup="$3"
    local mode="$4"

    if [[ "${existed}" == "true" && -n "${backup}" && -f "${backup}" ]]; then
        install -o root -g root -m "${mode}" "${backup}" "${path}" || true
    else
        rm -f -- "${path}"
    fi
}

backup_herodium_cli_assets() {
    backup_activation_file \
        /usr/local/bin/herodium-scan \
        HERODIUM_SCAN_EXISTED \
        HERODIUM_SCAN_BACKUP
    backup_activation_file \
        /usr/local/bin/herodium-top \
        HERODIUM_TOP_EXISTED \
        HERODIUM_TOP_BACKUP
    backup_activation_file \
        /usr/local/sbin/herodium-rkhunter-baseline \
        HERODIUM_RKHUNTER_TOOL_EXISTED \
        HERODIUM_RKHUNTER_TOOL_BACKUP
}

backup_herodium_auxiliary_assets() {
    backup_activation_file \
        /etc/logrotate.d/herodium \
        HERODIUM_LOGROTATE_EXISTED \
        HERODIUM_LOGROTATE_BACKUP
    backup_activation_file \
        "${DEPLOYMENT_MANIFEST_PATH}" \
        DEPLOYMENT_MANIFEST_EXISTED \
        DEPLOYMENT_MANIFEST_BACKUP
}

backup_scheduled_scan_assets() {
    SCHEDULED_TIMER_ENABLEMENT="$(
        read_unit_enablement herodium-scheduled-scan.timer
    )"
    if systemctl is-active --quiet herodium-scheduled-scan.timer 2>/dev/null; then
        SCHEDULED_TIMER_WAS_ACTIVE="true"
    fi

    backup_activation_file \
        /etc/herodium/scheduled_scan.conf \
        SCHEDULED_CONF_EXISTED \
        SCHEDULED_CONF_BACKUP
    backup_activation_file \
        /usr/local/bin/herodium_scheduled_scan.sh \
        SCHEDULED_SCRIPT_EXISTED \
        SCHEDULED_SCRIPT_BACKUP
    backup_activation_file \
        /etc/systemd/system/herodium-scheduled-scan.service \
        SCHEDULED_SERVICE_EXISTED \
        SCHEDULED_SERVICE_BACKUP
    backup_activation_file \
        /etc/systemd/system/herodium-scheduled-scan.timer \
        SCHEDULED_TIMER_EXISTED \
        SCHEDULED_TIMER_BACKUP
}

rollback_scheduled_scan_assets() {
    set +e

    if [[ "${SCHEDULED_ASSETS_CHANGED}" != "true" ]]; then
        return 0
    fi

    systemctl stop herodium-scheduled-scan.timer >/dev/null 2>&1 || true
    systemctl stop herodium-scheduled-scan.service >/dev/null 2>&1 || true

    restore_activation_file \
        /etc/herodium/scheduled_scan.conf \
        "${SCHEDULED_CONF_EXISTED}" \
        "${SCHEDULED_CONF_BACKUP}" \
        0644
    restore_activation_file \
        /usr/local/bin/herodium_scheduled_scan.sh \
        "${SCHEDULED_SCRIPT_EXISTED}" \
        "${SCHEDULED_SCRIPT_BACKUP}" \
        0755
    restore_activation_file \
        /etc/systemd/system/herodium-scheduled-scan.service \
        "${SCHEDULED_SERVICE_EXISTED}" \
        "${SCHEDULED_SERVICE_BACKUP}" \
        0644
    restore_activation_file \
        /etc/systemd/system/herodium-scheduled-scan.timer \
        "${SCHEDULED_TIMER_EXISTED}" \
        "${SCHEDULED_TIMER_BACKUP}" \
        0644

    systemctl daemon-reload >/dev/null 2>&1 || true
    restore_unit_enablement \
        herodium-scheduled-scan.timer \
        "${SCHEDULED_TIMER_ENABLEMENT}"
    if [[ "${SCHEDULED_TIMER_WAS_ACTIVE}" == "true" ]]; then
        systemctl start herodium-scheduled-scan.timer >/dev/null 2>&1 || true
    fi

    SCHEDULED_ASSETS_CHANGED="false"
}

commit_scheduled_scan_assets() {
    rm -f -- \
        "${SCHEDULED_CONF_BACKUP:-}" \
        "${SCHEDULED_SCRIPT_BACKUP:-}" \
        "${SCHEDULED_SERVICE_BACKUP:-}" \
        "${SCHEDULED_TIMER_BACKUP:-}"
    SCHEDULED_ASSETS_CHANGED="false"
}

read_unit_enablement() {
    local unit="$1"

    systemctl is-enabled "${unit}" 2>/dev/null || true
}

restore_unit_enablement() {
    local unit="$1"
    local state="$2"

    case "${state}" in
        enabled|enabled-runtime|linked|linked-runtime)
            systemctl unmask "${unit}" >/dev/null 2>&1 || true
            systemctl enable "${unit}" >/dev/null 2>&1 || true
            ;;
        disabled)
            systemctl unmask "${unit}" >/dev/null 2>&1 || true
            systemctl disable "${unit}" >/dev/null 2>&1 || true
            ;;
        masked|masked-runtime)
            systemctl mask "${unit}" >/dev/null 2>&1 || true
            ;;
        static|indirect|generated|transient|alias|not-found|"")
            ;;
        *)
            echo "[WARNING] Unknown systemd enablement state for ${unit}: ${state}"
            ;;
    esac
}

capture_clamav_state() {
    local config_path="/etc/clamav/clamd.conf"

    if [[ "${CLAMAV_STATE_CAPTURED}" == "true" ]]; then
        return 0
    fi

    systemctl daemon-reload

    CLAMAV_DAEMON_ENABLEMENT="$(read_unit_enablement clamav-daemon.service)"
    CLAMAV_SOCKET_ENABLEMENT="$(read_unit_enablement clamav-daemon.socket)"
    CLAMAV_FRESHCLAM_ENABLEMENT="$(read_unit_enablement clamav-freshclam.service)"

    if systemctl is-active --quiet clamav-daemon.service; then
        CLAMAV_DAEMON_WAS_ACTIVE="true"
    fi
    if systemctl is-active --quiet clamav-daemon.socket; then
        CLAMAV_SOCKET_WAS_ACTIVE="true"
    fi
    if systemctl is-active --quiet clamav-freshclam.service; then
        CLAMAV_FRESHCLAM_WAS_ACTIVE="true"
    fi

    if [[ -e "${config_path}" ]]; then
        if [[ -L "${config_path}" || ! -f "${config_path}" ]]; then
            echo "[CRITICAL] ClamAV configuration is not a safe regular file."
            return 1
        fi
        CLAMAV_CONFIG_UID="$(stat -c '%u' -- "${config_path}")"
        CLAMAV_CONFIG_GID="$(stat -c '%g' -- "${config_path}")"
        CLAMAV_CONFIG_MODE="$(stat -c '%a' -- "${config_path}")"
        if [[ "${CLAMAV_CONFIG_UID}" != "0" ]]; then
            echo "[CRITICAL] ClamAV configuration must be owned by root."
            return 1
        fi
        if (( (8#${CLAMAV_CONFIG_MODE}) & 0022 )); then
            echo "[CRITICAL] ClamAV configuration must not be group/world-writable."
            return 1
        fi
        CLAMAV_CONFIG_BACKUP="$(mktemp /run/herodium-clamd.conf.XXXXXX)"
        install -o root -g root -m 0600 \
            "${config_path}" "${CLAMAV_CONFIG_BACKUP}"
        CLAMAV_CONFIG_EXISTED="true"
    fi

    CLAMAV_STATE_CAPTURED="true"
}

rollback_clamav_configuration() {
    local config_path="/etc/clamav/clamd.conf"

    set +e
    if [[ "${CLAMAV_CONFIG_CHANGED}" != "true" ]]; then
        return 0
    fi

    systemctl stop \
        clamav-daemon.socket \
        clamav-daemon.service \
        clamav-freshclam.service >/dev/null 2>&1 || true

    if [[ "${CLAMAV_CONFIG_EXISTED}" == "true" \
        && -f "${CLAMAV_CONFIG_BACKUP}" ]]; then
        install \
            -o "${CLAMAV_CONFIG_UID}" \
            -g "${CLAMAV_CONFIG_GID}" \
            -m "${CLAMAV_CONFIG_MODE}" \
            "${CLAMAV_CONFIG_BACKUP}" "${config_path}" || true
    else
        rm -f -- "${config_path}"
    fi

    systemctl daemon-reload >/dev/null 2>&1 || true
    restore_unit_enablement clamav-daemon.socket "${CLAMAV_SOCKET_ENABLEMENT}"
    restore_unit_enablement clamav-daemon.service "${CLAMAV_DAEMON_ENABLEMENT}"
    restore_unit_enablement clamav-freshclam.service "${CLAMAV_FRESHCLAM_ENABLEMENT}"

    if [[ "${CLAMAV_SOCKET_WAS_ACTIVE}" == "true" ]]; then
        systemctl start clamav-daemon.socket >/dev/null 2>&1 || true
    fi
    if [[ "${CLAMAV_DAEMON_WAS_ACTIVE}" == "true" ]]; then
        systemctl start clamav-daemon.service >/dev/null 2>&1 || true
    fi
    if [[ "${CLAMAV_FRESHCLAM_WAS_ACTIVE}" == "true" ]]; then
        systemctl start clamav-freshclam.service >/dev/null 2>&1 || true
    fi

    rm -f -- "${CLAMAV_CONFIG_BACKUP:-}"
    CLAMAV_CONFIG_CHANGED="false"
}

commit_clamav_configuration() {
    rm -f -- "${CLAMAV_CONFIG_BACKUP:-}"
    CLAMAV_CONFIG_CHANGED="false"
}

rollback_maltrail_deployment() {
    set +e

    if [[ "${MALTRAIL_TRANSACTION_STARTED}" != "true" ]]; then
        return 0
    fi

    systemctl stop maltrail-sensor.service >/dev/null 2>&1 || true

    if [[ "${MALTRAIL_NEW_INSTALLED}" == "true" ]]; then
        remove_safe_directory "${MALTRAIL_DIR}" || true
        MALTRAIL_NEW_INSTALLED="false"
    fi
    if [[ "${MALTRAIL_CURRENT_ROTATED}" == "true" \
        && -d "${MALTRAIL_PREVIOUS_DIR}" \
        && ! -L "${MALTRAIL_PREVIOUS_DIR}" ]]; then
        mv -- "${MALTRAIL_PREVIOUS_DIR}" "${MALTRAIL_DIR}" || true
        MALTRAIL_CURRENT_ROTATED="false"
    fi

    if [[ "${MALTRAIL_UNIT_CHANGED}" == "true" ]]; then
        restore_activation_file \
            /etc/systemd/system/maltrail-sensor.service \
            "${MALTRAIL_UNIT_EXISTED}" \
            "${MALTRAIL_UNIT_BACKUP}" \
            0644
    fi
    if [[ "${MALTRAIL_CONFIG_CHANGED}" == "true" ]]; then
        restore_activation_file \
            /etc/maltrail/maltrail.conf \
            "${MALTRAIL_CONFIG_EXISTED}" \
            "${MALTRAIL_CONFIG_BACKUP}" \
            0640
    fi
    if [[ "${MALTRAIL_ENV_CHANGED}" == "true" ]]; then
        restore_activation_file \
            /etc/maltrail/herodium-maltrail.env \
            "${MALTRAIL_ENV_EXISTED}" \
            "${MALTRAIL_ENV_BACKUP}" \
            0600
    fi
    if [[ "${MALTRAIL_MARKER_CHANGED}" == "true" ]]; then
        restore_activation_file \
            /var/lib/herodium/supply-chain/maltrail-commit \
            "${MALTRAIL_MARKER_EXISTED}" \
            "${MALTRAIL_MARKER_BACKUP}" \
            0600
    fi

    if [[ "${MALTRAIL_STATE_DIR_EXISTED}" != "true" \
        && -n "${MALTRAIL_STATE_DIR}" ]]; then
        remove_safe_directory "${MALTRAIL_STATE_DIR}" || true
    fi

    systemctl daemon-reload >/dev/null 2>&1 || true
    restore_unit_enablement maltrail-sensor.service "${MALTRAIL_ENABLEMENT}"
    if [[ "${MALTRAIL_WAS_ACTIVE}" == "true" \
        && -d "${MALTRAIL_DIR}" ]]; then
        systemctl start maltrail-sensor.service >/dev/null 2>&1 || true
    fi

    remove_safe_directory "${MALTRAIL_FETCH_DIR:-}" >/dev/null 2>&1 || true
    remove_safe_directory "${MALTRAIL_STAGE_DIR:-}" >/dev/null 2>&1 || true
    rm -f -- \
        "${MALTRAIL_UNIT_BACKUP:-}" \
        "${MALTRAIL_CONFIG_BACKUP:-}" \
        "${MALTRAIL_ENV_BACKUP:-}" \
        "${MALTRAIL_MARKER_BACKUP:-}"
    MALTRAIL_TRANSACTION_STARTED="false"
    MALTRAIL_TRANSACTION_READY="false"
}

persist_maltrail_commit_marker() {
    local marker_path="/var/lib/herodium/supply-chain/maltrail-commit"
    local marker_temp

    if [[ "${MALTRAIL_TRANSACTION_STARTED}" != "true" \
        || -z "${MALTRAIL_PENDING_COMMIT}" ]]; then
        return 0
    fi

    install -d -o root -g root -m 0700 \
        /var/lib/herodium/supply-chain
    marker_temp="$(mktemp \
        /var/lib/herodium/supply-chain/.maltrail-commit.XXXXXX)"
    printf '%s\n' "${MALTRAIL_PENDING_COMMIT}" \
        | install -o root -g root -m 0600 /dev/stdin "${marker_temp}"
    mv -f -- "${marker_temp}" "${marker_path}"
    MALTRAIL_MARKER_CHANGED="true"
}

commit_maltrail_deployment() {
    remove_safe_directory "${MALTRAIL_FETCH_DIR:-}" >/dev/null 2>&1 || true
    remove_safe_directory "${MALTRAIL_STAGE_DIR:-}" >/dev/null 2>&1 || true
    rm -f -- \
        "${MALTRAIL_UNIT_BACKUP:-}" \
        "${MALTRAIL_CONFIG_BACKUP:-}" \
        "${MALTRAIL_ENV_BACKUP:-}" \
        "${MALTRAIL_MARKER_BACKUP:-}"
    MALTRAIL_TRANSACTION_STARTED="false"
    MALTRAIL_TRANSACTION_READY="false"
}

rollback_herodium_deployment() {
    set +e

    systemctl stop herodium.service >/dev/null 2>&1 || true

    if [[ "${HERODIUM_NEW_INSTALLED}" == "true" ]]; then
        remove_safe_directory "${APP_DIR}" || true
        HERODIUM_NEW_INSTALLED="false"
    fi

    if [[ "${HERODIUM_CURRENT_ROTATED}" == "true" \
        && -d "${APP_PREVIOUS_DIR}" \
        && ! -L "${APP_PREVIOUS_DIR}" ]]; then
        mv -- "${APP_PREVIOUS_DIR}" "${APP_DIR}" || \
            echo "[CRITICAL] Unable to restore the previous Herodium deployment."
        HERODIUM_CURRENT_ROTATED="false"
    fi

    if [[ "${HERODIUM_UNIT_CHANGED}" == "true" ]]; then
        if [[ "${HERODIUM_UNIT_EXISTED}" == "true" \
            && -n "${HERODIUM_UNIT_BACKUP}" \
            && -f "${HERODIUM_UNIT_BACKUP}" ]]; then
            install -o root -g root -m 0644 \
                "${HERODIUM_UNIT_BACKUP}" \
                /etc/systemd/system/herodium.service || true
        else
            rm -f -- /etc/systemd/system/herodium.service
        fi
    fi

    if [[ "${HERODIUM_CLI_CHANGED}" == "true" ]]; then
        restore_activation_file \
            /usr/local/bin/herodium-scan \
            "${HERODIUM_SCAN_EXISTED}" \
            "${HERODIUM_SCAN_BACKUP}" \
            0755
        restore_activation_file \
            /usr/local/bin/herodium-top \
            "${HERODIUM_TOP_EXISTED}" \
            "${HERODIUM_TOP_BACKUP}" \
            0755
        restore_activation_file \
            /usr/local/sbin/herodium-rkhunter-baseline \
            "${HERODIUM_RKHUNTER_TOOL_EXISTED}" \
            "${HERODIUM_RKHUNTER_TOOL_BACKUP}" \
            0755
    fi
    if [[ "${HERODIUM_LOGROTATE_CHANGED}" == "true" ]]; then
        restore_activation_file \
            /etc/logrotate.d/herodium \
            "${HERODIUM_LOGROTATE_EXISTED}" \
            "${HERODIUM_LOGROTATE_BACKUP}" \
            0644
    fi
    if [[ "${DEPLOYMENT_MANIFEST_CHANGED}" == "true" ]]; then
        restore_activation_file \
            "${DEPLOYMENT_MANIFEST_PATH}" \
            "${DEPLOYMENT_MANIFEST_EXISTED}" \
            "${DEPLOYMENT_MANIFEST_BACKUP}" \
            0600
    fi

    systemctl daemon-reload >/dev/null 2>&1 || true
    restore_unit_enablement herodium.service "${HERODIUM_ENABLEMENT}"

    if [[ "${HERODIUM_WAS_ACTIVE}" == "true" && -d "${APP_DIR}" ]]; then
        systemctl start herodium.service || \
            echo "[CRITICAL] Unable to restart the previous Herodium service."
    fi

    remove_safe_directory "${APP_STAGE_DIR}" >/dev/null 2>&1 || true
    rm -f -- \
        "${HERODIUM_UNIT_BACKUP:-}" \
        "${HERODIUM_SCAN_BACKUP:-}" \
        "${HERODIUM_TOP_BACKUP:-}" \
        "${HERODIUM_RKHUNTER_TOOL_BACKUP:-}" \
        "${HERODIUM_LOGROTATE_BACKUP:-}" \
        "${DEPLOYMENT_MANIFEST_BACKUP:-}" \
        "${SOURCE_MANIFEST_TMP:-}"
}

handle_install_failure() {
    local exit_code="$1"

    trap - ERR INT TERM
    set +e

    rm -f -- "${SOURCE_MANIFEST_TMP:-}"

    if [[ "${HERODIUM_DEPLOYMENT_COMMITTED}" != "true" ]]; then
        case "${INSTALL_PHASE}" in
            staging|staged)
                remove_safe_directory "${APP_STAGE_DIR}" || true
                ;;
            quiescing|quiesced|deploying|service_restarted|finalizing)
                echo "[WARNING] Installation failed; rolling back installer-managed state."
                systemctl stop herodium.service >/dev/null 2>&1 || true
                rollback_scheduled_scan_assets
                rollback_maltrail_deployment
                rollback_clamav_configuration
                rollback_herodium_deployment
                ;;
        esac
    fi

    exit "${exit_code}"
}

trap 'handle_install_failure $?' ERR
trap 'handle_install_failure 130' INT
trap 'handle_install_failure 143' TERM

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
# SUPPLY-CHAIN HELPERS
# ==============================================================================

load_supply_chain_lock() {
    local lock_mode
    local parsed

    if [[ ! -f "${SUPPLY_CHAIN_LOCK}" || -L "${SUPPLY_CHAIN_LOCK}" ]]; then
        echo "[CRITICAL] Supply-chain lock is missing, not a regular file, or is a symlink: ${SUPPLY_CHAIN_LOCK}"
        return 1
    fi

    lock_mode="$(stat -c '%a' -- "${SUPPLY_CHAIN_LOCK}")"
    if (( (8#${lock_mode}) & 0002 )); then
        echo "[CRITICAL] Supply-chain lock must not be world-writable: ${SUPPLY_CHAIN_LOCK}"
        return 1
    fi

    parsed="$(python3 - "${SUPPLY_CHAIN_LOCK}" <<'PYLOCK'
import json
import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
try:
    data = json.loads(path.read_text(encoding="utf-8"))
except (OSError, UnicodeError, json.JSONDecodeError) as exc:
    raise SystemExit(f"invalid supply-chain lock: {exc}")

if set(data) != {"schema_version", "maltrail"}:
    raise SystemExit("unexpected top-level keys in supply-chain lock")
if data["schema_version"] != 1:
    raise SystemExit("unsupported supply-chain lock schema")

maltrail = data["maltrail"]
if not isinstance(maltrail, dict) or set(maltrail) != {
    "repository",
    "commit",
    "license_sha256",
}:
    raise SystemExit("unexpected Maltrail lock fields")

repository = maltrail["repository"]
commit = maltrail["commit"]
license_sha256 = maltrail["license_sha256"]

if repository != "https://github.com/stamparm/maltrail.git":
    raise SystemExit("Maltrail repository is not the approved upstream")
if not isinstance(commit, str) or re.fullmatch(r"[0-9a-f]{40}", commit) is None:
    raise SystemExit("Maltrail commit must be a full lowercase SHA-1")
if not isinstance(license_sha256, str) or re.fullmatch(
    r"[0-9a-f]{64}", license_sha256
) is None:
    raise SystemExit("Maltrail license hash must be a lowercase SHA-256")

print("\t".join((repository, commit, license_sha256)))
PYLOCK
)" || {
        echo "[CRITICAL] Unable to parse ${SUPPLY_CHAIN_LOCK}."
        return 1
    }

    IFS=$'\t' read -r \
        MALTRAIL_REPOSITORY \
        MALTRAIL_COMMIT \
        MALTRAIL_LICENSE_SHA256 \
        <<< "${parsed}"
}

run_pinned_git() {
    GIT_CONFIG_GLOBAL=/dev/null \
    GIT_CONFIG_NOSYSTEM=1 \
    GIT_TERMINAL_PROMPT=0 \
        git -c protocol.file.allow=never "$@"
}

select_pcap_package() {
    local candidate

    for candidate in python3-pcapy-ng python3-pcapy; do
        if apt-cache show "${candidate}" 2>/dev/null \
            | grep -Fx "Package: ${candidate}" >/dev/null; then
            printf '%s\n' "${candidate}"
            return 0
        fi
    done

    return 1
}

validate_installer_lock_file() {
    local lock_path="$1"
    local lock_kind="$2"
    local mode

    if [[ ! -f "${lock_path}" || -L "${lock_path}" ]]; then
        echo "[CRITICAL] Required lock is missing, not regular, or is a symlink: ${lock_path}"
        return 1
    fi

    mode="$(stat -c '%a' -- "${lock_path}")"
    if (( (8#${mode}) & 0002 )); then
        echo "[CRITICAL] Required lock must not be world-writable: ${lock_path}"
        return 1
    fi

    python3 - "${lock_path}" "${lock_kind}" <<'PYREQUIREMENTS'
import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
lock_kind = sys.argv[2]
expected = {
    "tools": {
        "packaging": "26.2",
        "pip": "26.2",
        "setuptools": "82.0.1",
        "wheel": "0.47.0",
    },
    "runtime": {
        "psutil": "7.2.1",
        "pyclamd": "0.4.0",
        "pyyaml": "6.0.3",
        "watchdog": "6.0.0",
    },
}.get(lock_kind)
if expected is None:
    raise SystemExit(f"unsupported dependency-lock kind: {lock_kind}")
try:
    lines = path.read_text(encoding="utf-8").splitlines()
except (OSError, UnicodeError) as exc:
    raise SystemExit(f"unable to read dependency lock: {exc}")

requirement_re = re.compile(
    r"(?P<name>[A-Za-z0-9_.-]+)==(?P<version>[A-Za-z0-9_.+!-]+)(?:[ ]+\\)?"
)
hash_re = re.compile(r"[ ]+--hash=sha256:[0-9a-f]{64}(?:[ ]+\\)?")
packages: dict[str, int] = {}
versions: dict[str, str] = {}
current: str | None = None

for number, raw in enumerate(lines, start=1):
    if not raw.strip() or raw.lstrip().startswith("#"):
        continue
    requirement = requirement_re.fullmatch(raw)
    if requirement is not None:
        normalized = requirement.group("name").lower().replace("_", "-")
        if normalized in packages:
            raise SystemExit(f"duplicate package at line {number}: {normalized}")
        packages[normalized] = 0
        versions[normalized] = requirement.group("version")
        current = normalized
        continue
    if hash_re.fullmatch(raw) is not None and current is not None:
        packages[current] += 1
        continue
    raise SystemExit(f"unsupported dependency-lock syntax at line {number}: {raw!r}")

if not packages:
    raise SystemExit("dependency lock contains no packages")
missing = sorted(name for name, count in packages.items() if count == 0)
if missing:
    raise SystemExit(f"packages missing hashes: {missing}")
if versions != expected:
    raise SystemExit(
        f"dependency lock set mismatch: expected={expected!r}, actual={versions!r}"
    )
PYREQUIREMENTS
}

validate_herodium_source_tree() {
    local source_root="${REPO_DIR}/herodium"
    local unsafe

    if [[ ! -d "${source_root}" || -L "${source_root}" ]]; then
        echo "[CRITICAL] Herodium source root is missing or is a symlink: ${source_root}"
        return 1
    fi

    unsafe="$(find "${source_root}" -xdev \
        \( ! -type f ! -type d \) -print -quit)"
    if [[ -n "${unsafe}" ]]; then
        echo "[CRITICAL] Herodium source contains an unsupported special file: ${unsafe}"
        return 1
    fi

    unsafe="$(find "${source_root}" -xdev \
        \( -type f -o -type d \) -perm -0002 -print -quit)"
    if [[ -n "${unsafe}" ]]; then
        echo "[CRITICAL] Herodium source contains a world-writable path: ${unsafe}"
        return 1
    fi
}

validate_existing_herodium_config() {
    local config_path="${APP_DIR}/config/herodium.yaml"
    local owner_uid
    local mode

    if [[ ! -e "${config_path}" ]]; then
        return 0
    fi
    if [[ -L "${config_path}" || ! -f "${config_path}" ]]; then
        echo "[CRITICAL] Existing Herodium config is not a safe regular file: ${config_path}"
        return 1
    fi

    owner_uid="$(stat -c '%u' -- "${config_path}")"
    mode="$(stat -c '%a' -- "${config_path}")"
    if [[ "${owner_uid}" != "0" ]]; then
        echo "[CRITICAL] Existing Herodium config must be owned by root: ${config_path}"
        return 1
    fi
    if (( (8#${mode}) & 0022 )); then
        echo "[CRITICAL] Existing Herodium config must not be group/world-writable: ${config_path}"
        return 1
    fi
}

install_verified_staging_asset() {
    local source_path="$1"
    local destination_path="$2"
    local destination_mode="$3"
    local source_mode
    local expected_sha256

    if [[ ! -f "${source_path}" || -L "${source_path}" ]]; then
        echo "[CRITICAL] Installer asset is missing, not regular, or is a symlink: ${source_path}"
        return 1
    fi
    source_mode="$(stat -c '%a' -- "${source_path}")"
    if (( (8#${source_mode}) & 0002 )); then
        echo "[CRITICAL] Installer asset must not be world-writable: ${source_path}"
        return 1
    fi

    expected_sha256="$(sha256sum -- "${source_path}" | awk '{print $1}')"
    install -o root -g root -m "${destination_mode}" \
        "${source_path}" "${destination_path}"
    printf '%s  %s\n' "${expected_sha256}" "${destination_path}" \
        | sha256sum -c - >/dev/null
}

validate_staged_systemd_units() {
    local source_unit
    local verify_unit
    local verify_rc

    source_unit="${APP_STAGE_DIR}/supply-chain/installer/systemd/herodium.service"
    verify_unit="$(
        mktemp \
            "${APP_STAGE_DIR}/supply-chain/herodium-verify.XXXXXX.service"
    )"

    if ! python3 - \
        "${source_unit}" \
        "${verify_unit}" \
        "${APP_DIR}" \
        "${APP_STAGE_DIR}" <<'PYSYSTEMD'
from pathlib import Path
import os
import sys

source = Path(sys.argv[1])
destination = Path(sys.argv[2])
active_root = Path(sys.argv[3])
stage_root = Path(sys.argv[4])

stage_python = stage_root / "venv/bin/python3"
stage_engine = stage_root / "core/engine.py"

if not stage_python.is_file() or not os.access(stage_python, os.X_OK):
    raise SystemExit("staged Python executable is missing or not executable")
if not stage_engine.is_file():
    raise SystemExit("staged Herodium engine is missing")

text = source.read_text(encoding="utf-8")
active_working = f"WorkingDirectory={active_root}"
active_exec = (
    f"ExecStart={active_root}/venv/bin/python3 "
    f"{active_root}/core/engine.py"
)
stage_working = f"WorkingDirectory={stage_root}"
stage_exec = (
    f"ExecStart={stage_root}/venv/bin/python3 "
    f"{stage_root}/core/engine.py"
)

if text.count(active_working) != 1 or text.count(active_exec) != 1:
    raise SystemExit("Herodium service template has unexpected runtime paths")

rendered = text.replace(active_working, stage_working)
rendered = rendered.replace(active_exec, stage_exec)

if rendered.count(stage_working) != 1 or rendered.count(stage_exec) != 1:
    raise SystemExit("unable to render staged Herodium service unit")

destination.write_text(rendered, encoding="utf-8")
os.chmod(destination, 0o600)
PYSYSTEMD
    then
        rm -f -- "${verify_unit}"
        return 1
    fi

    if systemd-analyze verify \
        "${verify_unit}" \
        "${APP_STAGE_DIR}/supply-chain/installer/systemd/maltrail-sensor.service"; then
        rm -f -- "${verify_unit}"
    else
        verify_rc="$?"
        rm -f -- "${verify_unit}"
        return "${verify_rc}"
    fi

    echo "[PASS] Staged systemd units validated."
}

run_staged_pip() {
    local command="$1"
    shift

    if [[ "${command}" == "install" ]]; then
        PIP_CONFIG_FILE=/dev/null \
        PIP_NO_CACHE_DIR=1 \
        PYTHONNOUSERSITE=1 \
            "${APP_STAGE_DIR}/venv/bin/python3" -m pip \
                --isolated \
                --disable-pip-version-check \
                --no-input \
                install \
                --index-url https://pypi.org/simple \
                "$@"
    else
        PIP_CONFIG_FILE=/dev/null \
        PIP_NO_CACHE_DIR=1 \
        PYTHONNOUSERSITE=1 \
            "${APP_STAGE_DIR}/venv/bin/python3" -m pip \
                --isolated \
                --disable-pip-version-check \
                --no-input \
                "${command}" \
                "$@"
    fi
}

update_staged_herodium_config() {
    HERODIUM_STAGE_CONFIG="${APP_STAGE_DIR}/config/herodium.yaml" \
    HERODIUM_CLAM_FREQ="${CLAM_FREQ}" \
    HERODIUM_CLAM_SCAN_TYPE="${CLAM_SCAN_TYPE}" \
    HERODIUM_INSTALL_RKHUNTER="${INSTALL_RKHUNTER}" \
    HERODIUM_RK_FREQ="${RK_FREQ}" \
    HERODIUM_THREAT_ACTION="${THREAT_ACTION}" \
    HERODIUM_SCHED_THREAT_ACTION="${SCHED_THREAT_ACTION}" \
    HERODIUM_LIVE_SCAN="${LIVE_SCAN}" \
    HERODIUM_INSTALL_MALTRAIL="${INSTALL_MALTRAIL}" \
    HERODIUM_MALTRAIL_ACTION="${MALTRAIL_ACTION}" \
    HERODIUM_CLEAN_INTERVAL="${CLEAN_INTERVAL}" \
    HERODIUM_INSTALL_FAIL2BAN="${INSTALL_FAIL2BAN}" \
    HERODIUM_APPARMOR_LEVEL="${APPARMOR_LEVEL}" \
    HERODIUM_ENABLE_HARDENING="${ENABLE_HARDENING}" \
    HERODIUM_ENABLE_ZRAM="${ENABLE_ZRAM}" \
        "${APP_STAGE_DIR}/venv/bin/python3" - <<'PYCONFIG'
import os
from pathlib import Path

import yaml


def enabled(name: str) -> bool:
    return os.environ[name] == "true"


config_path = Path(os.environ["HERODIUM_STAGE_CONFIG"])
config = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
if not isinstance(config, dict):
    raise SystemExit("Herodium config root must be a mapping")

scheduler = config.setdefault("scheduler", {})
scheduler["scan_via_systemd"] = True
scheduler["scan_type"] = os.environ["HERODIUM_CLAM_SCAN_TYPE"]
scheduler["scan_frequency"] = os.environ["HERODIUM_CLAM_FREQ"]
scheduler["home_scan_interval_hours"] = 0
scheduler["full_scan_interval_hours"] = 0
scheduler["rkhunter_interval_hours"] = (
    24 if os.environ["HERODIUM_RK_FREQ"] == "daily" else 168
) if enabled("HERODIUM_INSTALL_RKHUNTER") else 0
scheduler["threat_action"] = os.environ["HERODIUM_SCHED_THREAT_ACTION"]

clamav = config.setdefault("clamav", {})
clamav["threat_action"] = os.environ["HERODIUM_THREAT_ACTION"]
clamav.setdefault("max_file_size_mb", 25)
clamav.setdefault("stream_max_length_mb", clamav["max_file_size_mb"])

config.setdefault("live_monitor", {})["enable"] = enabled("HERODIUM_LIVE_SCAN")

maltrail = config.setdefault("maltrail", {})
maltrail["enable"] = enabled("HERODIUM_INSTALL_MALTRAIL")
maltrail["block_traffic"] = os.environ["HERODIUM_MALTRAIL_ACTION"] == "block"
maltrail["clean_interval_hours"] = (
    24 if os.environ["HERODIUM_CLEAN_INTERVAL"] == "daily" else 168
)

config.setdefault("ips", {})["enable"] = enabled("HERODIUM_INSTALL_FAIL2BAN")
config.setdefault("apparmor", {})["level"] = int(os.environ["HERODIUM_APPARMOR_LEVEL"])
config.setdefault("hardening", {})["enable"] = enabled("HERODIUM_ENABLE_HARDENING")
config.setdefault("performance", {})["enable_zram"] = enabled("HERODIUM_ENABLE_ZRAM")

serialized = yaml.safe_dump(config, sort_keys=False, default_flow_style=False)
config_path.write_text(serialized, encoding="utf-8")
print("[PASS] Staged YAML configuration updated and validated.")
PYCONFIG
}

create_staged_deployment_manifest() {
    local manifest="${APP_STAGE_DIR}/.herodium-deployment.sha256"

    (
        cd "${APP_STAGE_DIR}"
        find . -xdev -type f \
            ! -path './venv/*' \
            ! -path './quarantine/*' \
            ! -path './config/herodium.yaml' \
            ! -name '.herodium-deployment.sha256' \
            -print0 \
            | sort -z \
            | xargs -0 -r sha256sum \
            > "${manifest}"
        sha256sum -c "${manifest}" >/dev/null
    )
    chmod 0600 "${manifest}"
}

validate_staged_python_environment() {
    "${APP_STAGE_DIR}/venv/bin/python3" - <<'PYVERIFY'
from importlib import metadata

expected = {
    "packaging": "26.2",
    "pip": "26.2",
    "psutil": "7.2.1",
    "pyclamd": "0.4.0",
    "pyyaml": "6.0.3",
    "setuptools": "82.0.1",
    "watchdog": "6.0.0",
    "wheel": "0.47.0",
}
installed = {
    distribution.metadata["Name"].lower(): distribution.version
    for distribution in metadata.distributions()
}
if installed != expected:
    raise SystemExit(
        f"staged distribution set mismatch: expected={expected!r}, installed={installed!r}"
    )

import psutil  # noqa: F401
import pyclamd  # noqa: F401
import watchdog  # noqa: F401
import yaml  # noqa: F401

print("[PASS] Staged dependency versions and imports validated.")
PYVERIFY

    "${APP_STAGE_DIR}/venv/bin/python3" - <<'PYCOMPILE'
from pathlib import Path

root = Path("/opt/herodium.stage")
count = 0
for path in sorted(root.rglob("*.py")):
    if "venv" in path.parts:
        continue
    compile(path.read_text(encoding="utf-8"), str(path), "exec")
    count += 1
print(f"[PASS] Staged Python syntax validated: {count} files")
PYCOMPILE
}

create_herodium_source_manifest() {
    SOURCE_MANIFEST_TMP="$(mktemp /run/herodium-source-manifest.XXXXXX)"
    chmod 0600 "${SOURCE_MANIFEST_TMP}"

    (
        cd "${REPO_DIR}/herodium"
        find . -xdev \
            \( -path './venv' -o -path './logs' -o -path './quarantine' \
               -o -path '*/__pycache__' \) -prune -o \
            -type f ! -name '*.pyc' ! -name '*.pyo' -print0 \
            | sort -z \
            | xargs -0 -r sha256sum \
            > "${SOURCE_MANIFEST_TMP}"
    )

    if [[ ! -s "${SOURCE_MANIFEST_TMP}" ]]; then
        echo "[CRITICAL] Herodium source manifest is empty."
        return 1
    fi
}

verify_herodium_source_snapshot() {
    (
        cd "${REPO_DIR}/herodium"
        sha256sum -c "${SOURCE_MANIFEST_TMP}" >/dev/null
    )
    (
        cd "${APP_STAGE_DIR}"
        sha256sum -c "${SOURCE_MANIFEST_TMP}" >/dev/null
    )
}

prepare_staged_herodium_deployment() {
    echo "[INFO] Building staged Herodium deployment..."
    INSTALL_PHASE="staging"

    validate_installer_lock_file "${PYTHON_TOOLS_LOCK}" tools
    validate_installer_lock_file "${RUNTIME_REQUIREMENTS_LOCK}" runtime
    validate_herodium_source_tree
    validate_existing_herodium_config
    create_herodium_source_manifest

    remove_safe_directory "${APP_STAGE_DIR}"
    install -d -o root -g root -m 0755 "${APP_STAGE_DIR}"

    rsync -rlt --delete \
        --exclude '__pycache__/' \
        --exclude '*.pyc' \
        --exclude '*.pyo' \
        --exclude 'venv/' \
        --exclude 'logs/' \
        --exclude 'quarantine/' \
        "${REPO_DIR}/herodium/" \
        "${APP_STAGE_DIR}/"

    verify_herodium_source_snapshot
    rm -f -- "${SOURCE_MANIFEST_TMP}"
    SOURCE_MANIFEST_TMP=""

    find "${APP_STAGE_DIR}" -xdev -type d -exec chmod 0755 {} +
    find "${APP_STAGE_DIR}" -xdev -type f -exec chmod 0644 {} +
    chown -R root:root "${APP_STAGE_DIR}"

    install -d -o root -g root -m 0755 \
        "${APP_STAGE_DIR}/supply-chain" \
        "${APP_STAGE_DIR}/supply-chain/installer" \
        "${APP_STAGE_DIR}/supply-chain/installer/bin" \
        "${APP_STAGE_DIR}/supply-chain/installer/systemd"

    install_verified_staging_asset \
        "${PYTHON_TOOLS_LOCK}" \
        "${APP_STAGE_DIR}/supply-chain/python-tools.lock" \
        0644
    install_verified_staging_asset \
        "${SUPPLY_CHAIN_LOCK}" \
        "${APP_STAGE_DIR}/supply-chain/installer/supply-chain-lock.json" \
        0644
    install_verified_staging_asset \
        "${REPO_DIR}/installer/systemd/herodium.service" \
        "${APP_STAGE_DIR}/supply-chain/installer/systemd/herodium.service" \
        0644
    install_verified_staging_asset \
        "${REPO_DIR}/installer/systemd/maltrail-sensor.service" \
        "${APP_STAGE_DIR}/supply-chain/installer/systemd/maltrail-sensor.service" \
        0644
    install_verified_staging_asset \
        "${REPO_DIR}/installer/bin/herodium-scan" \
        "${APP_STAGE_DIR}/supply-chain/installer/bin/herodium-scan" \
        0644
    install_verified_staging_asset \
        "${REPO_DIR}/installer/bin/herodium-top" \
        "${APP_STAGE_DIR}/supply-chain/installer/bin/herodium-top" \
        0644
    install_verified_staging_asset \
        "${REPO_DIR}/installer/bin/herodium-rkhunter-baseline" \
        "${APP_STAGE_DIR}/supply-chain/installer/bin/herodium-rkhunter-baseline" \
        0644

    if [[ -f "${APP_DIR}/config/herodium.yaml" ]]; then
        install -o root -g root -m 0640 \
            "${APP_DIR}/config/herodium.yaml" \
            "${APP_STAGE_DIR}/config/herodium.yaml"
    fi

    install -d -o root -g root -m 0700 "${APP_STAGE_DIR}/quarantine"
    ln -s /var/log/herodium "${APP_STAGE_DIR}/logs"

    python3 -m venv --clear "${APP_STAGE_DIR}/venv"
    run_staged_pip install \
        --require-hashes \
        --no-deps \
        --only-binary=:all: \
        -r "${APP_STAGE_DIR}/supply-chain/python-tools.lock"
    run_staged_pip install \
        --require-hashes \
        --no-deps \
        --no-build-isolation \
        --prefer-binary \
        -r "${APP_STAGE_DIR}/requirements.lock"
    run_staged_pip check

    update_staged_herodium_config
    chmod 0640 "${APP_STAGE_DIR}/config/herodium.yaml"
    validate_staged_python_environment
    validate_staged_systemd_units
    create_staged_deployment_manifest

    INSTALL_PHASE="staged"
    echo "[PASS] Staged Herodium deployment is ready for activation."
}

copy_runtime_state_into_stage() {
    local quarantine_path="${APP_DIR}/quarantine"
    local unsafe

    if [[ -L "${quarantine_path}" ]]; then
        echo "[CRITICAL] Existing quarantine path must not be a symlink: ${quarantine_path}"
        return 1
    fi
    if [[ -d "${quarantine_path}" ]]; then
        if [[ "$(stat -c '%u' -- "${quarantine_path}")" != "0" ]]; then
            echo "[CRITICAL] Existing quarantine directory must be owned by root."
            return 1
        fi
        unsafe="$(find "${quarantine_path}" -xdev \
            \( ! -type f ! -type d \) -print -quit)"
        if [[ -n "${unsafe}" ]]; then
            echo "[CRITICAL] Existing quarantine contains an unsupported path: ${unsafe}"
            return 1
        fi
        unsafe="$(find "${quarantine_path}" -xdev ! -user root -print -quit)"
        if [[ -n "${unsafe}" ]]; then
            echo "[CRITICAL] Existing quarantine contains a non-root-owned path: ${unsafe}"
            return 1
        fi

        rsync -rlt --delete -- "${quarantine_path}/" "${APP_STAGE_DIR}/quarantine/"
    fi
    chown -R root:root "${APP_STAGE_DIR}/quarantine"
    find "${APP_STAGE_DIR}/quarantine" -xdev -type d -exec chmod 0700 {} +
    find "${APP_STAGE_DIR}/quarantine" -xdev -type f -exec chmod 0600 {} +
}

activate_staged_herodium_deployment() {
    echo "[INFO] Activating staged Herodium deployment..."
    INSTALL_PHASE="deploying"

    if [[ -L "${APP_DIR}" || -L "${APP_PREVIOUS_DIR}" ]]; then
        echo "[CRITICAL] Refusing deployment rotation through a symlinked /opt path."
        return 1
    fi

    remove_safe_directory "${APP_PREVIOUS_DIR}"
    if [[ -d "${APP_DIR}" ]]; then
        mv -- "${APP_DIR}" "${APP_PREVIOUS_DIR}"
        HERODIUM_CURRENT_ROTATED="true"
    fi

    mv -- "${APP_STAGE_DIR}" "${APP_DIR}"
    HERODIUM_NEW_INSTALLED="true"

    (
        cd "${APP_DIR}"
        sha256sum -c .herodium-deployment.sha256 >/dev/null
    )
    echo "[PASS] Herodium deployment activated and manifest verified."
}

backup_herodium_service_unit() {
    local unit_path="/etc/systemd/system/herodium.service"

    HERODIUM_ENABLEMENT="$(read_unit_enablement herodium.service)"

    if [[ -e "${unit_path}" ]]; then
        if [[ -L "${unit_path}" || ! -f "${unit_path}" ]]; then
            echo "[CRITICAL] Existing Herodium service unit is not a safe regular file."
            return 1
        fi
        HERODIUM_UNIT_EXISTED="true"
        HERODIUM_UNIT_BACKUP="$(mktemp /run/herodium.service.XXXXXX)"
        install -o root -g root -m 0600 "${unit_path}" "${HERODIUM_UNIT_BACKUP}"
    fi
}

validate_activated_herodium_service() {
    local current_size
    local start_byte

    for _ in $(seq 1 45); do
        current_size="$(stat -c '%s' /var/log/herodium/herodium.log)"
        if (( current_size < HERODIUM_LOG_VERIFY_OFFSET )); then
            start_byte=1
        else
            start_byte=$((HERODIUM_LOG_VERIFY_OFFSET + 1))
        fi

        if systemctl is-active --quiet herodium.service \
            && tail -c "+${start_byte}" /var/log/herodium/herodium.log \
                | awk '/System is PROTECTED[.] Monitoring active[.][.][.]/ { found=1 } END { exit !found }'; then
            echo "[PASS] Activated Herodium service reached PROTECTED state."
            return 0
        fi
        sleep 1
    done

    echo "[CRITICAL] Activated Herodium service did not reach PROTECTED state."
    systemctl status herodium.service --no-pager || true
    tail -n 80 /var/log/herodium/herodium.log || true
    return 1
}

validate_previous_deployment_candidate() {
    local immutable_manifest

    if [[ ! -e "${APP_PREVIOUS_DIR}" ]]; then
        echo "[INFO] No previous Herodium deployment exists yet."
        return 0
    fi
    if [[ -L "${APP_PREVIOUS_DIR}" || ! -d "${APP_PREVIOUS_DIR}" ]]; then
        echo "[CRITICAL] Previous Herodium deployment is not a safe directory."
        return 1
    fi
    if [[ "$(stat -c '%u' -- "${APP_PREVIOUS_DIR}")" != "0" ]]; then
        echo "[CRITICAL] Previous Herodium deployment must be owned by root."
        return 1
    fi
    if [[ ! -x "${APP_PREVIOUS_DIR}/venv/bin/python3" \
        || ! -f "${APP_PREVIOUS_DIR}/core/engine.py" ]]; then
        echo "[CRITICAL] Previous Herodium deployment is not runnable."
        return 1
    fi
    if [[ -f "${APP_PREVIOUS_DIR}/.herodium-deployment.sha256" ]]; then
        immutable_manifest="$(mktemp /run/herodium-previous-manifest.XXXXXX)"
        awk '$2 != "./config/herodium.yaml"' \
            "${APP_PREVIOUS_DIR}/.herodium-deployment.sha256" \
            > "${immutable_manifest}"
        if ! (
            cd "${APP_PREVIOUS_DIR}"
            sha256sum -c "${immutable_manifest}" >/dev/null
        ); then
            rm -f -- "${immutable_manifest}"
            echo "[CRITICAL] Previous Herodium deployment manifest validation failed."
            return 1
        fi
        rm -f -- "${immutable_manifest}"
    fi
    echo "[PASS] Previous Herodium rollback candidate validated."
}

validate_final_installer_state() {
    local units=(
        /etc/systemd/system/herodium.service
        /etc/systemd/system/herodium-scheduled-scan.service
        /etc/systemd/system/herodium-scheduled-scan.timer
    )

    if [[ "${INSTALL_MALTRAIL}" == "true" ]]; then
        units+=(/etc/systemd/system/maltrail-sensor.service)
    fi
    systemd-analyze verify "${units[@]}"

    systemctl is-active --quiet herodium.service
    systemctl is-active --quiet clamav-daemon.service
    systemctl is-active --quiet clamav-daemon.socket
    systemctl is-active --quiet herodium-scheduled-scan.timer
    if [[ "${INSTALL_MALTRAIL}" == "true" ]]; then
        systemctl is-active --quiet maltrail-sensor.service
    elif systemctl is-active --quiet maltrail-sensor.service 2>/dev/null; then
        echo "[CRITICAL] Maltrail remained active after it was disabled by policy."
        return 1
    fi
    if [[ "${CLAMAV_FRESHCLAM_WAS_ACTIVE}" == "true" ]]; then
        systemctl is-active --quiet clamav-freshclam.service
    fi
    "${APP_DIR}/venv/bin/python3" -m pip check
    (
        cd "${APP_DIR}"
        sha256sum -c .herodium-deployment.sha256 >/dev/null
    )
    validate_previous_deployment_candidate
    echo "[PASS] Final installer service state validated."
}

trigger_installer_test_failpoint() {
    local phase="$1"
    local requested="${HERODIUM_INSTALLER_TEST_FAILPOINT:-}"

    if [[ -z "${requested}" ]]; then
        return 0
    fi
    if [[ "${HERODIUM_INSTALLER_TEST_ACKNOWLEDGE:-}" \
        != "ROLLBACK-TEST" ]]; then
        echo "[CRITICAL] Installer test failpoints require explicit ROLLBACK-TEST acknowledgement."
        return 1
    fi
    if [[ "${requested}" == "${phase}" ]]; then
        echo "[TEST] Triggering installer rollback failpoint: ${phase}"
        return 97
    fi
}

commit_herodium_deployment() {
    local manifest_temp

    install -d -o root -g root -m 0700 "${DEPLOYMENT_MANIFEST_DIR}"

    # Persist all transaction metadata while rollback backups are still available.
    persist_maltrail_commit_marker
    DEPLOYMENT_MANIFEST_CHANGED="true"
    manifest_temp="$(mktemp \
        "${DEPLOYMENT_MANIFEST_DIR}/.herodium-deployment.XXXXXX")"
    install -o root -g root -m 0600 \
        "${APP_DIR}/.herodium-deployment.sha256" \
        "${manifest_temp}"
    mv -f -- "${manifest_temp}" "${DEPLOYMENT_MANIFEST_PATH}"

    # No fallible deployment mutation occurs after this commit point.
    HERODIUM_DEPLOYMENT_COMMITTED="true"
    commit_scheduled_scan_assets
    commit_maltrail_deployment
    commit_clamav_configuration

    rm -f -- \
        "${HERODIUM_UNIT_BACKUP:-}" \
        "${HERODIUM_SCAN_BACKUP:-}" \
        "${HERODIUM_TOP_BACKUP:-}" \
        "${HERODIUM_RKHUNTER_TOOL_BACKUP:-}" \
        "${HERODIUM_LOGROTATE_BACKUP:-}" \
        "${DEPLOYMENT_MANIFEST_BACKUP:-}" \
        "${SOURCE_MANIFEST_TMP:-}"
    echo "[PASS] Installer-wide deployment transaction committed."
}


validate_existing_maltrail_config() {
    local config_path="/etc/maltrail/maltrail.conf"
    local owner_uid
    local mode

    if [[ -L "${config_path}" || ! -f "${config_path}" ]]; then
        echo "[CRITICAL] Existing Maltrail config is not a safe regular file: ${config_path}"
        return 1
    fi

    owner_uid="$(stat -c '%u' -- "${config_path}")"
    mode="$(stat -c '%a' -- "${config_path}")"

    if [[ "${owner_uid}" != "0" ]]; then
        echo "[CRITICAL] Existing Maltrail config must be owned by root: ${config_path}"
        return 1
    fi
    if (( (8#${mode}) & 0022 )); then
        echo "[CRITICAL] Existing Maltrail config must not be group/world-writable: ${config_path}"
        return 1
    fi
}

begin_maltrail_transaction() {
    local unit_path="/etc/systemd/system/maltrail-sensor.service"

    if [[ "${MALTRAIL_TRANSACTION_STARTED}" == "true" ]]; then
        return 0
    fi

    MALTRAIL_ENABLEMENT="$(read_unit_enablement maltrail-sensor.service)"
    if systemctl is-active --quiet maltrail-sensor.service 2>/dev/null; then
        MALTRAIL_WAS_ACTIVE="true"
    fi

    backup_activation_file \
        "${unit_path}" \
        MALTRAIL_UNIT_EXISTED \
        MALTRAIL_UNIT_BACKUP
    backup_activation_file \
        /etc/maltrail/maltrail.conf \
        MALTRAIL_CONFIG_EXISTED \
        MALTRAIL_CONFIG_BACKUP
    backup_activation_file \
        /etc/maltrail/herodium-maltrail.env \
        MALTRAIL_ENV_EXISTED \
        MALTRAIL_ENV_BACKUP
    backup_activation_file \
        /var/lib/herodium/supply-chain/maltrail-commit \
        MALTRAIL_MARKER_EXISTED \
        MALTRAIL_MARKER_BACKUP

    MALTRAIL_TRANSACTION_STARTED="true"
}

deactivate_maltrail_if_disabled() {
    begin_maltrail_transaction

    if systemctl is-active --quiet maltrail-sensor.service 2>/dev/null; then
        systemctl stop maltrail-sensor.service
    fi
    systemctl disable maltrail-sensor.service >/dev/null 2>&1 || true
    MALTRAIL_TRANSACTION_READY="true"
    echo "[PASS] Maltrail service disabled by current installer policy."
}

install_pinned_maltrail() {
    local pcap_package
    local actual_commit
    local actual_license_sha256
    local unit_path="/etc/systemd/system/maltrail-sensor.service"

    begin_maltrail_transaction
    SUPPLY_CHAIN_LOCK="${APP_DIR}/supply-chain/installer/supply-chain-lock.json"
    load_supply_chain_lock

    pcap_package="$(select_pcap_package)" || {
        echo "[CRITICAL] No supported pcapy package is available from configured APT repositories."
        return 1
    }

    echo "[INFO] Installing Maltrail packet-capture dependency: ${pcap_package}"
    apt-get install -y "${pcap_package}"
    python3 -c 'import pcapy' || {
        echo "[CRITICAL] The installed pcapy package is not importable."
        return 1
    }

    if [[ -L "${MALTRAIL_DIR}" || -L "${MALTRAIL_PREVIOUS_DIR}" ]]; then
        echo "[CRITICAL] Refusing Maltrail deployment through a symlinked runtime path."
        return 1
    fi

    MALTRAIL_FETCH_DIR="$(mktemp -d /opt/.maltrail-fetch.XXXXXX)"
    MALTRAIL_STAGE_DIR="$(mktemp -d /opt/.maltrail-stage.XXXXXX)"

    echo "[INFO] Fetching pinned Maltrail commit: ${MALTRAIL_COMMIT}"
    run_pinned_git init --quiet "${MALTRAIL_FETCH_DIR}"
    run_pinned_git -C "${MALTRAIL_FETCH_DIR}" remote add origin "${MALTRAIL_REPOSITORY}"
    run_pinned_git -C "${MALTRAIL_FETCH_DIR}" \
        fetch --quiet --depth 1 --no-tags origin "${MALTRAIL_COMMIT}"

    actual_commit="$(
        run_pinned_git -C "${MALTRAIL_FETCH_DIR}" \
            rev-parse --verify "FETCH_HEAD^{commit}"
    )"
    if [[ "${actual_commit}" != "${MALTRAIL_COMMIT}" ]]; then
        echo "[CRITICAL] Maltrail commit verification failed."
        return 1
    fi

    run_pinned_git -C "${MALTRAIL_FETCH_DIR}" \
        update-ref refs/heads/herodium-pinned "${actual_commit}"
    run_pinned_git -C "${MALTRAIL_FETCH_DIR}" \
        symbolic-ref HEAD refs/heads/herodium-pinned
    run_pinned_git -C "${MALTRAIL_FETCH_DIR}" fsck --full --strict --no-dangling
    if run_pinned_git -C "${MALTRAIL_FETCH_DIR}" show "${MALTRAIL_COMMIT}:.gitmodules" \
        >/dev/null 2>&1; then
        echo "[CRITICAL] Pinned Maltrail source unexpectedly contains submodules."
        return 1
    fi

    run_pinned_git -C "${MALTRAIL_FETCH_DIR}" archive --format=tar "${MALTRAIL_COMMIT}" \
        | tar --extract --directory="${MALTRAIL_STAGE_DIR}" \
            --no-same-owner --no-same-permissions

    if [[ ! -f "${MALTRAIL_STAGE_DIR}/sensor.py" \
        || ! -f "${MALTRAIL_STAGE_DIR}/maltrail.conf" \
        || ! -f "${MALTRAIL_STAGE_DIR}/LICENSE" ]]; then
        echo "[CRITICAL] Pinned Maltrail payload is incomplete."
        return 1
    fi

    actual_license_sha256="$(sha256sum "${MALTRAIL_STAGE_DIR}/LICENSE" | awk '{print $1}')"
    if [[ "${actual_license_sha256}" != "${MALTRAIL_LICENSE_SHA256}" ]]; then
        echo "[CRITICAL] Maltrail license hash verification failed."
        return 1
    fi

    find "${MALTRAIL_STAGE_DIR}" -type d -exec chmod 0755 {} +
    find "${MALTRAIL_STAGE_DIR}" -type f -exec chmod 0644 {} +
    chown -R root:root "${MALTRAIL_STAGE_DIR}"

    ensure_safe_root_directory /etc/maltrail 0755
    ensure_safe_root_directory /var/log/maltrail 0755
    ensure_safe_root_directory "${MALTRAIL_STATE_BASE}" 0700

    if [[ -e /etc/maltrail/maltrail.conf ]]; then
        validate_existing_maltrail_config
    else
        MALTRAIL_CONFIG_CHANGED="true"
        install -o root -g root -m 0640 \
            "${MALTRAIL_STAGE_DIR}/maltrail.conf" \
            /etc/maltrail/maltrail.conf
    fi

    MALTRAIL_STATE_DIR="${MALTRAIL_STATE_BASE}/offline-${MALTRAIL_COMMIT}"
    if [[ -d "${MALTRAIL_STATE_DIR}" && ! -L "${MALTRAIL_STATE_DIR}" ]]; then
        local unsafe_state
        local state_mode

        MALTRAIL_STATE_DIR_EXISTED="true"
        state_mode="$(stat -c '%a' -- "${MALTRAIL_STATE_DIR}")"
        if [[ "$(stat -c '%u' -- "${MALTRAIL_STATE_DIR}")" != "0" \
            || $(( (8#${state_mode}) & 0022 )) -ne 0 ]]; then
            echo "[CRITICAL] Existing Maltrail state directory is not private and root-owned."
            return 1
        fi
        unsafe_state="$(find "${MALTRAIL_STATE_DIR}" -xdev \
            \( ! -type f ! -type d \) -print -quit)"
        if [[ -n "${unsafe_state}" ]]; then
            echo "[CRITICAL] Existing Maltrail state contains an unsupported path: ${unsafe_state}"
            return 1
        fi
        unsafe_state="$(find "${MALTRAIL_STATE_DIR}" -xdev ! -user root -print -quit)"
        if [[ -n "${unsafe_state}" ]]; then
            echo "[CRITICAL] Existing Maltrail state contains a non-root-owned path: ${unsafe_state}"
            return 1
        fi
        unsafe_state="$(find "${MALTRAIL_STATE_DIR}" -xdev \
            -perm /022 -print -quit)"
        if [[ -n "${unsafe_state}" ]]; then
            echo "[CRITICAL] Existing Maltrail state contains a writable path: ${unsafe_state}"
            return 1
        fi
    elif [[ -e "${MALTRAIL_STATE_DIR}" ]]; then
        echo "[CRITICAL] Maltrail state path is not a safe directory: ${MALTRAIL_STATE_DIR}"
        return 1
    fi
    install -d -o root -g root -m 0700 "${MALTRAIL_STATE_DIR}"

    MALTRAIL_ENV_CHANGED="true"
    {
        printf 'HOME=%s\n' "${MALTRAIL_STATE_DIR}"
        printf 'HERODIUM_MALTRAIL_COMMIT=%s\n' "${MALTRAIL_COMMIT}"
    } | install -o root -g root -m 0600 /dev/stdin \
        /etc/maltrail/herodium-maltrail.env

    MALTRAIL_UNIT_CHANGED="true"
    install -o root -g root -m 0644 \
        "${APP_DIR}/supply-chain/installer/systemd/maltrail-sensor.service" \
        "${unit_path}"
    systemctl daemon-reload

    if [[ "${MALTRAIL_WAS_ACTIVE}" == "true" ]]; then
        systemctl stop maltrail-sensor.service
        if systemctl is-active --quiet maltrail-sensor.service; then
            echo "[CRITICAL] Maltrail did not stop cleanly."
            return 1
        fi
        echo "[PASS] Maltrail service stopped cleanly."
    fi

    remove_safe_directory "${MALTRAIL_PREVIOUS_DIR}"
    if [[ -e "${MALTRAIL_DIR}" ]]; then
        mv -- "${MALTRAIL_DIR}" "${MALTRAIL_PREVIOUS_DIR}"
        MALTRAIL_CURRENT_ROTATED="true"
    fi

    mv -- "${MALTRAIL_STAGE_DIR}" "${MALTRAIL_DIR}"
    MALTRAIL_STAGE_DIR=""
    MALTRAIL_NEW_INSTALLED="true"

    systemctl unmask maltrail-sensor.service >/dev/null 2>&1 || true
    systemctl enable maltrail-sensor.service
    systemctl restart maltrail-sensor.service

    for _ in $(seq 1 20); do
        if systemctl is-active --quiet maltrail-sensor.service \
            && [[ "$(systemctl show maltrail-sensor.service -p MainPID --value)" != "0" ]]; then
            MALTRAIL_TRANSACTION_READY="true"
            break
        fi
        sleep 1
    done
    if [[ "${MALTRAIL_TRANSACTION_READY}" != "true" ]]; then
        echo "[CRITICAL] Pinned Maltrail failed health validation; restoring previous deployment."
        return 1
    fi

    MALTRAIL_PENDING_COMMIT="${MALTRAIL_COMMIT}"
    MALTRAIL_MARKER_CHANGED="true"
    remove_safe_directory "${MALTRAIL_FETCH_DIR}"
    MALTRAIL_FETCH_DIR=""
    echo "[PASS] Maltrail installed at pinned commit ${MALTRAIL_COMMIT} in offline feed mode."
}

# ==============================================================================
# WIZARD FUNCTIONS
# ==============================================================================

welcome_msg() {
    whiptail --title "Herodium Security Installer" --msgbox "Welcome to Herodium Auto-Security System Installer.\n\nWe will now guide you through the security configuration.\n\nKey features: Backup, Antivirus, Network Defense, and Hardening." 12 70
}

# --- 1. Backup Strategy (Timeshift) ---

create_timeshift_command_path() {
    local command_dir="$1"
    local search_dir
    local candidate
    local name
    local mode

    install -d -o root -g root -m 0700 "${command_dir}"
    for search_dir in /usr/sbin /usr/bin /sbin /bin; do
        [[ -d "${search_dir}" ]] || continue
        for candidate in "${search_dir}"/*; do
            [[ -x "${candidate}" && ! -d "${candidate}" ]] || continue
            name="${candidate##*/}"
            [[ "${name}" == "notify-send" ]] && continue
            if [[ -L "${candidate}" ]]; then
                candidate="$(readlink -f -- "${candidate}")"
            fi
            [[ -f "${candidate}" ]] || continue
            [[ "$(stat -c '%u' -- "${candidate}")" == "0" ]] || continue
            mode="$(stat -c '%a' -- "${candidate}")"
            (( (8#${mode}) & 0022 )) && continue
            if [[ ! -e "${command_dir}/${name}" ]]; then
                ln -s -- "${candidate}" "${command_dir}/${name}"
            fi
        done
    done
}

run_timeshift_headless() {
    local command_dir
    local exit_code

    command_dir="$(mktemp -d /run/herodium-timeshift-path.XXXXXX)"
    create_timeshift_command_path "${command_dir}"

    set +e
    env -i \
        HOME=/root \
        USER=root \
        LOGNAME=root \
        LANG=C \
        LC_ALL=C.UTF-8 \
        PATH="${command_dir}" \
        /usr/bin/timeshift --scripted "$@"
    exit_code="$?"
    set -e

    remove_safe_directory "${command_dir}"
    return "${exit_code}"
}

create_verified_timeshift_snapshot() {
    local comments="$1"
    local output_file
    local list_file
    local snapshot_name
    local exit_code

    output_file="$(mktemp /run/herodium-timeshift-create.XXXXXX)"
    list_file="$(mktemp /run/herodium-timeshift-list.XXXXXX)"

    set +e
    run_timeshift_headless \
        --create \
        --comments "${comments}" \
        --tags O \
        --yes \
        2>&1 | tee "${output_file}"
    exit_code="${PIPESTATUS[0]}"
    set -e

    if [[ "${exit_code}" != "0" ]]; then
        rm -f -- "${output_file}" "${list_file}"
        return 1
    fi

    snapshot_name="$(
        sed -n "s/.*Tagged snapshot '\([^']*\)'.*/\1/p" "${output_file}" \
            | tail -n 1
    )"
    if [[ -z "${snapshot_name}" ]]; then
        echo "[ERROR] Timeshift did not report the created snapshot name."
        rm -f -- "${output_file}" "${list_file}"
        return 1
    fi

    if ! run_timeshift_headless --list >"${list_file}" 2>&1; then
        echo "[ERROR] Unable to verify the Timeshift snapshot list."
        rm -f -- "${output_file}" "${list_file}"
        return 1
    fi
    if ! grep -Fq -- "${snapshot_name}" "${list_file}"; then
        echo "[ERROR] Created Timeshift snapshot was not found in the repository."
        rm -f -- "${output_file}" "${list_file}"
        return 1
    fi

    rm -f -- "${output_file}" "${list_file}"
    echo "[PASS] Timeshift snapshot verified: ${snapshot_name}"
}

setup_timeshift() {
    local free_space
    local root_uuid
    local ts_cfg="/etc/timeshift/timeshift.json"
    local ts_alt="/etc/timeshift.json"

    if ! whiptail --title "Step 1: System Backup" --yesno \
        "Before applying security changes, it is CRITICAL to create a system snapshot.\n\nThis allows you to rollback if the hardening breaks any functionality.\n\nDo you want to install Timeshift and create a snapshot now?" \
        15 70; then
        return 0
    fi

    echo "[INFO] Installing Timeshift..."
    apt-get install -y timeshift

    free_space="$(df / --output=avail | tail -1)"
    if [[ "${free_space}" -lt 10000000 ]]; then
        whiptail --msgbox \
            "WARNING: Low disk space (<10GB). Snapshot creation skipped to prevent crash." \
            8 60
        SNAPSHOT_STATUS="Skipped (Low disk space)"
        return 0
    fi

    echo "[INFO] Configuring Timeshift target device..."
    root_uuid="$(findmnt -n -o UUID /)"
    if [[ -z "${root_uuid}" ]]; then
        echo "[ERROR] Could not detect the root filesystem UUID."
        SNAPSHOT_STATUS="Failed (root UUID unavailable)"
    else
        echo " -> Detected Root UUID: ${root_uuid}"
        install -d -o root -g root -m 0755 /etc/timeshift

        backup_ts_cfg() {
            local config_path="$1"
            local backup_path

            [[ -e "${config_path}" ]] || return 0
            if [[ -L "${config_path}" || ! -f "${config_path}" ]]; then
                echo "[CRITICAL] Timeshift config is not a safe regular file: ${config_path}"
                return 1
            fi
            if [[ "$(stat -c '%u' -- "${config_path}")" != "0" ]]; then
                echo "[CRITICAL] Timeshift config must be owned by root: ${config_path}"
                return 1
            fi
            backup_path="${config_path}.bak-$(date +%Y%m%d-%H%M%S)"
            install -o root -g root -m 0600 \
                "${config_path}" "${backup_path}"
            echo " -> Existing Timeshift config backed up: ${backup_path}"
        }

        backup_ts_cfg "${ts_cfg}"
        backup_ts_cfg "${ts_alt}"

        if [[ -f "${ts_cfg}" || -f "${ts_alt}" ]]; then
            echo " -> Existing Timeshift configuration detected (leaving it unchanged)"
        else
            cat >"${ts_cfg}" <<EOF
{
  "backup_device_uuid" : "${root_uuid}",
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
            chmod 0644 "${ts_cfg}"
            echo " -> Configuration written to ${ts_cfg}"
        fi

        echo "[INFO] Creating verified Timeshift snapshot (Label: Herodium_Pre_Install)..."
        if create_verified_timeshift_snapshot "Herodium_Pre_Install"; then
            SNAPSHOT_STATUS="Created and verified (Herodium_Pre_Install)"
            return 0
        fi
        SNAPSHOT_STATUS="Failed"
    fi

    if ! whiptail --title "Timeshift Snapshot Failed" --yesno \
        "The requested pre-install snapshot could not be verified.\n\nContinue the installation without a verified snapshot?" \
        12 70; then
        echo "[CRITICAL] Installation cancelled because no verified snapshot exists."
        return 1
    fi
    SNAPSHOT_STATUS="Failed (operator continued)"
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
        "2" "Light/Test (Complain Mode - may reduce existing enforcement)" \
        "3" "Medium (Enforce - Blocks known threats)" \
        "4" "Strong (Full Audit - May break apps)" 3>&1 1>&2 2>&3) || APPARMOR_LEVEL="1"

    if [[ "$APPARMOR_LEVEL" -ge 3 ]]; then
        if (whiptail --yesno "High security level selected.\nCreate another specific backup before applying AppArmor rules?" 10 60); then
             if ! create_verified_timeshift_snapshot "Pre_AppArmor_Change"; then
                 echo "[WARNING] Unable to verify the optional pre-AppArmor snapshot."
             fi
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


remove_herodium_firewall_state() {
    echo "[INFO] Removing old Herodium firewall/ipset state (non-blocking mode)..."

    remove_herodium_iptables_rule() {
        local bin="$1"
        local chain="$2"
        shift 2

        if command -v "${bin}" >/dev/null 2>&1; then
            while "${bin}" -C "${chain}" "$@" 2>/dev/null; do
                "${bin}" -D "${chain}" "$@" 2>/dev/null || break
            done
        fi
    }

    # IPv4 rules created by Herodium blocking mode
    remove_herodium_iptables_rule iptables INPUT  -m set --match-set herodium_blacklist dst -j DROP
    remove_herodium_iptables_rule iptables INPUT  -m set --match-set herodium_blacklist src -j DROP
    remove_herodium_iptables_rule iptables OUTPUT -m set --match-set herodium_blacklist dst -j DROP
    remove_herodium_iptables_rule iptables OUTPUT -m set --match-set herodium_blacklist src -j DROP

    # IPv6 rules created by Herodium blocking mode
    remove_herodium_iptables_rule ip6tables INPUT  -m set --match-set herodium_blacklist_v6 dst -j DROP
    remove_herodium_iptables_rule ip6tables INPUT  -m set --match-set herodium_blacklist_v6 src -j DROP
    remove_herodium_iptables_rule ip6tables OUTPUT -m set --match-set herodium_blacklist_v6 dst -j DROP
    remove_herodium_iptables_rule ip6tables OUTPUT -m set --match-set herodium_blacklist_v6 src -j DROP

    if command -v ipset >/dev/null 2>&1; then
        ipset destroy herodium_blacklist 2>/dev/null || true
        ipset destroy herodium_blacklist_v6 2>/dev/null || true
    fi
}


configure_clamav_transactionally() {
    local max_retries=45
    local count=0
    local unit

    echo "[INFO] Configuring ClamAV socket and database transactionally..."
    capture_clamav_state
    CLAMAV_CONFIG_CHANGED="true"

    systemctl stop \
        clamav-daemon.socket \
        clamav-daemon.service \
        clamav-freshclam.service
    for unit in \
        clamav-daemon.socket \
        clamav-daemon.service \
        clamav-freshclam.service; do
        if systemctl is-active --quiet "${unit}"; then
            echo "[CRITICAL] ${unit} did not stop cleanly."
            return 1
        fi
    done

    set_clamd_option() {
        local option="$1"
        local value="$2"

        if grep -Eq "^[[:space:]]*${option}[[:space:]]+" /etc/clamav/clamd.conf; then
            sed -Ei \
                "s|^[[:space:]]*${option}[[:space:]]+.*|${option} ${value}|" \
                /etc/clamav/clamd.conf
        else
            printf '%s %s\n' "${option}" "${value}" >> /etc/clamav/clamd.conf
        fi
    }

    CLAMAV_TEMP_DIR="/var/lib/clamav/herodium-tmp"
    set_clamd_option "LocalSocket" "/var/run/clamav/clamd.ctl"
    set_clamd_option "TemporaryDirectory" "${CLAMAV_TEMP_DIR}"

    install -d -o clamav -g clamav -m 0700 /var/run/clamav
    install -d -o clamav -g clamav -m 0700 "${CLAMAV_TEMP_DIR}"

    if [[ ! -f /var/lib/clamav/main.cvd && ! -f /var/lib/clamav/main.cld ]]; then
        echo " -> Virus database missing. Downloading initial database..."
        freshclam --no-dns
    fi

    systemctl daemon-reload
    systemctl unmask clamav-daemon.socket clamav-daemon.service >/dev/null 2>&1 || true
    systemctl enable clamav-daemon.socket clamav-daemon.service
    systemctl start clamav-daemon.socket
    systemctl start clamav-daemon.service

    echo " -> Waiting for ClamAV Socket..."
    while [[ ! -S /var/run/clamav/clamd.ctl ]]; do
        sleep 1
        count=$((count + 1))
        if [[ "${count}" -ge "${max_retries}" ]]; then
            echo "[CRITICAL] ClamAV socket did not appear after 45 seconds."
            return 1
        fi
    done

    if [[ "${CLAMAV_FRESHCLAM_WAS_ACTIVE}" == "true" ]]; then
        systemctl unmask clamav-freshclam.service >/dev/null 2>&1 || true
        systemctl start clamav-freshclam.service
    fi
    restore_unit_enablement \
        clamav-freshclam.service \
        "${CLAMAV_FRESHCLAM_ENABLEMENT}"

    echo "[PASS] ClamAV service, socket, and updater state configured."
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
systemctl daemon-reload

if [[ "${APPARMOR_LEVEL}" == "4" ]]; then
    echo "[INFO] Installing AppArmor Level 4 extra dependencies..."
    apt-get install -y apparmor-profiles-extra auditd
fi

if [[ "$INSTALL_RKHUNTER" == "true" ]]; then
    apt-get install -y rkhunter
    echo "[INFO] Rkhunter installed without modifying the local file-properties baseline."
    echo "[ACTION REQUIRED] Review the system and create/update the baseline explicitly with:"
    echo "  sudo herodium-rkhunter-baseline --review"
    echo '  sudo herodium-rkhunter-baseline --update --acknowledge-reviewed-warnings --reason "verified authorized system changes"'
fi

# 3. Fail2Ban Installation (Now conditional)
setup_fail2ban_ddos

# Stale blocking state is removed only after the installer-wide transaction commits.

# 4. Build and validate the complete replacement while the current service remains active.
prepare_staged_herodium_deployment

# 5. Capture every activation asset before any service is quiesced.
backup_herodium_service_unit
backup_herodium_cli_assets
backup_herodium_auxiliary_assets
backup_scheduled_scan_assets

# 6. Quiesce the existing Herodium service before migrating mutable state or activation.
echo "[INFO] Quiescing existing Herodium service..."
INSTALL_PHASE="quiescing"
if systemctl is-active --quiet herodium.service; then
    HERODIUM_WAS_ACTIVE="true"
    systemctl stop herodium.service
fi
INSTALL_PHASE="quiesced"

# 7. Configure ClamAV with service-state rollback.
configure_clamav_transactionally

# 8. Preserve AppArmor state before deployment rotation/deletion
echo "[INFO] Preparing persistent AppArmor state..."
"${APP_STAGE_DIR}/venv/bin/python3" \
    "${APP_STAGE_DIR}/modules/apparmor_state.py" migrate

# 7. Copy mutable runtime state only after quiesce, then atomically rotate deployments.
copy_runtime_state_into_stage
activate_staged_herodium_deployment

# 8. Logs and log rotation
install -d -o root -g root -m 0700 /var/log/herodium

for log_file in /var/log/herodium/herodium.log /var/log/herodium/scheduled_scan.log; do
    if [[ ! -f "${log_file}" ]]; then
        install -m 0600 -o root -g root /dev/null "${log_file}"
    else
        chown root:root "${log_file}"
        chmod 0600 "${log_file}"
    fi
done
find /var/log/herodium -maxdepth 1 -type f -name '*.log' \
    -exec chmod 0600 {} + 2>/dev/null || true

if [[ ! -L "${APP_DIR}/logs" \
    || "$(readlink -- "${APP_DIR}/logs")" != "/var/log/herodium" ]]; then
    echo "[CRITICAL] Activated deployment has an invalid logs link."
    exit 1
fi

if ! command -v logrotate >/dev/null 2>&1; then
    apt-get install -y logrotate
fi

HERODIUM_LOGROTATE_CHANGED="true"
cat >/etc/logrotate.d/herodium <<'EOF'
/var/log/herodium/*.log {
  weekly
  rotate 8
  compress
  delaycompress
  missingok
  notifempty
  copytruncate
  create 0600 root root
}
EOF

# 9. Install Maltrail from the immutable supply-chain lock.
if [[ "${INSTALL_MALTRAIL}" == "true" ]]; then
    echo "[INFO] Installing pinned Maltrail deployment..."
    install_pinned_maltrail
else
    deactivate_maltrail_if_disabled
fi

# 10. Final Systemd Setup
echo "[INFO] Installing Herodium Service..."
HERODIUM_UNIT_CHANGED="true"
HERODIUM_CLI_CHANGED="true"
install -o root -g root -m 0644 \
    "${APP_DIR}/supply-chain/installer/systemd/herodium.service" \
    /etc/systemd/system/herodium.service
install -o root -g root -m 0755 \
    "${APP_DIR}/supply-chain/installer/bin/herodium-scan" \
    /usr/local/bin/herodium-scan
install -o root -g root -m 0755 \
    "${APP_DIR}/supply-chain/installer/bin/herodium-top" \
    /usr/local/bin/herodium-top
install -o root -g root -m 0755 \
    "${APP_DIR}/supply-chain/installer/bin/herodium-rkhunter-baseline" \
    /usr/local/sbin/herodium-rkhunter-baseline

systemctl daemon-reload
systemctl unmask herodium.service >/dev/null 2>&1 || true
systemctl enable herodium.service
HERODIUM_LOG_VERIFY_OFFSET="$(stat -c '%s' /var/log/herodium/herodium.log)"
systemctl restart herodium.service
INSTALL_PHASE="service_restarted"
validate_activated_herodium_service

# 11. Configure ClamAV Scheduled Scans (POLICY-AWARE)
SCAN_TARGET="/"
if [[ "$CLAM_SCAN_TYPE" == "HOME" ]]; then
    SCAN_TARGET="/home"
fi

echo "[INFO] Writing scheduled scan config..."
SCHEDULED_ASSETS_CHANGED="true"
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

#
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

# Avoid scanning pseudo-filesystems, scanner databases, and Herodium-owned output paths.
# These paths can create noise, wasted work, permission issues, or recursive scanning.
CLAMDSCAN_EXCLUDES=(
  "--exclude-dir=^/proc($|/)"
  "--exclude-dir=^/sys($|/)"
  "--exclude-dir=^/dev($|/)"
  "--exclude-dir=^/run($|/)"
  "--exclude-dir=^/var/lib/clamav($|/)"
  "--exclude-dir=^/var/lib/maltrail($|/)"
  "--exclude-dir=^/opt/herodium/quarantine($|/)"
  "--exclude-dir=^/var/log/herodium($|/)"
  "--exclude-dir=^/root/.maltrail($|/)"
)

case "${ACTION}" in
  delete)
    clamdscan --fdpass --multiscan "${CLAMDSCAN_EXCLUDES[@]}" --remove=yes -- "${SCAN_TARGET}"
    ;;
  quarantine)
    mkdir -p "${QDIR}"
    chmod 700 "${QDIR}" || true
    clamdscan --fdpass --multiscan "${CLAMDSCAN_EXCLUDES[@]}" --move="${QDIR}" -- "${SCAN_TARGET}"
    ;;
  alert|*)
    clamdscan --fdpass --multiscan "${CLAMDSCAN_EXCLUDES[@]}" -- "${SCAN_TARGET}"
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

FINAL_UNITS=(
  /etc/systemd/system/herodium.service
  /etc/systemd/system/herodium-scheduled-scan.service
  /etc/systemd/system/herodium-scheduled-scan.timer
)
if [[ "${INSTALL_MALTRAIL}" == "true" ]]; then
  FINAL_UNITS+=(/etc/systemd/system/maltrail-sensor.service)
fi
systemd-analyze verify "${FINAL_UNITS[@]}"
systemctl daemon-reload
systemctl unmask herodium-scheduled-scan.timer >/dev/null 2>&1 || true
systemctl enable --now herodium-scheduled-scan.timer

INSTALL_PHASE="finalizing"
validate_final_installer_state
trigger_installer_test_failpoint after_final_validation
commit_herodium_deployment
if [[ "${INSTALL_MALTRAIL}" != "true" || "${MALTRAIL_ACTION}" != "block" ]]; then
    remove_herodium_firewall_state
fi
INSTALL_PHASE="complete"
trap - ERR INT TERM

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
  RKHUNTER_SUMMARY="Installed (${RK_FREQ}; baseline updates are operator-controlled)"
fi

whiptail --msgbox "Installation Complete!\n\n- Snapshot: ${SNAPSHOT_STATUS}\n- ZRAM: ${ZRAM_STATUS}\n- ClamAV: ${CLAMAV_SUMMARY}\n- Maltrail: ${MALTRAIL_SUMMARY}\n- Rkhunter: ${RKHUNTER_SUMMARY}\n- Fail2Ban: ${INSTALL_FAIL2BAN}\n- AppArmor: Level ${APPARMOR_LEVEL}\n\nRun 'sudo herodium-top' to monitor." 18 78
