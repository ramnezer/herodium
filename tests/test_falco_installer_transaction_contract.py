import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
INSTALLER = PROJECT_ROOT / "installer/install.sh"
UNINSTALLER = PROJECT_ROOT / "installer/uninstall.sh"
CONFIG = PROJECT_ROOT / "herodium/config/herodium.yaml"


class FalcoInstallerTransactionContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.installer = INSTALLER.read_text(encoding="utf-8")
        cls.uninstaller = UNINSTALLER.read_text(encoding="utf-8")

    def test_safe_default_and_wizard_are_alert_only(self):
        self.assertIn('INSTALL_FALCO="false"', self.installer)
        self.assertIn("ask_falco_prefs() {", self.installer)
        self.assertIn("modern eBPF driver", self.installer)
        self.assertIn("ALERT-ONLY", self.installer)
        self.assertIn('HERODIUM_INSTALL_FALCO="${INSTALL_FALCO}"', self.installer)
        self.assertIn('falco["enable"] = enabled("HERODIUM_INSTALL_FALCO")', self.installer)
        self.assertIn('falco["mode"] = "alert_only"', self.installer)

    def test_supply_chain_values_are_consumed_by_shell_only_after_validation(self):
        for variable in (
            "FALCO_REPOSITORY",
            "FALCO_SUITE",
            "FALCO_COMPONENT",
            "FALCO_KEY_URL",
            "FALCO_TRUSTED_FINGERPRINT",
            "FALCO_PACKAGE_VERSION",
            "FALCO_DRIVER",
        ):
            self.assertIn(variable, self.installer)
        self.assertIn('FALCO_PACKAGE_VERSION=""', self.installer)
        self.assertIn('FALCO_DRIVER=""', self.installer)
        self.assertIn('load_supply_chain_lock\n    validate_herodium_source_tree', self.installer)

    def test_signing_key_is_downloaded_as_data_and_exact_fingerprint_is_exported(self):
        self.assertIn("install_verified_falco_repository() {", self.installer)
        self.assertIn("--proto '=https' --tlsv1.2", self.installer)
        self.assertIn('--output "${FALCO_KEY_TMP}"', self.installer)
        self.assertIn('gpg --batch --no-options --import "${FALCO_KEY_TMP}"', self.installer)
        self.assertIn('--fingerprint "${FALCO_TRUSTED_FINGERPRINT}"', self.installer)
        self.assertIn('gpg --batch --no-options --export "${FALCO_TRUSTED_FINGERPRINT}"', self.installer)
        self.assertNotIn("curl | gpg", self.installer)
        self.assertNotIn("apt-key", self.installer)

    def test_repository_is_scoped_to_dedicated_signed_by_keyring(self):
        self.assertIn(
            'FALCO_SOURCE_LIST="/etc/apt/sources.list.d/herodium-falco.list"',
            self.installer,
        )
        self.assertIn(
            'FALCO_KEYRING="/usr/share/keyrings/herodium-falco-archive-keyring.gpg"',
            self.installer,
        )
        self.assertIn("deb [signed-by=%s] %s %s %s", self.installer)
        self.assertIn("apt-cache madison falco", self.installer)
        self.assertNotIn("trusted=yes", self.installer)

    def test_package_install_is_exact_noninteractive_modern_ebpf_without_auto_updates(self):
        self.assertIn("DEBIAN_FRONTEND=noninteractive", self.installer)
        self.assertIn("FALCO_FRONTEND=noninteractive", self.installer)
        self.assertIn('FALCO_DRIVER_CHOICE="${FALCO_DRIVER}"', self.installer)
        self.assertIn("FALCOCTL_ENABLED=no", self.installer)
        self.assertIn('"falco=${FALCO_PACKAGE_VERSION}"', self.installer)
        self.assertIn("apt-mark hold falco", self.installer)
        self.assertIn("systemctl mask falcoctl-artifact-follow.service", self.installer)
        self.assertIn("systemctl enable falco-modern-bpf.service", self.installer)

    def test_herodium_starts_after_installer_managed_systemd_writes(self):
        scheduled_service = self.installer.index(
            "cat >/etc/systemd/system/herodium-scheduled-scan.service"
        )
        scheduled_timer = self.installer.index(
            "cat >/etc/systemd/system/herodium-scheduled-scan.timer"
        )
        timer_enable = self.installer.index(
            "systemctl enable --now herodium-scheduled-scan.timer"
        )
        herodium_restart = self.installer.index(
            "systemctl restart herodium.service"
        )

        self.assertLess(scheduled_service, herodium_restart)
        self.assertLess(scheduled_timer, herodium_restart)
        self.assertLess(timer_enable, herodium_restart)

    def test_upgrade_quiesces_managed_falco_after_consumer_stop(self):
        main = self.installer.split("# 6. Quiesce the existing Herodium service", 1)[1]
        herodium_stop = main.index("systemctl stop herodium.service")
        managed_marker_guard = main.index(
            '( -e "${FALCO_MARKER_PATH}" || -L "${FALCO_MARKER_PATH}" )'
        )
        falco_quiesce = main.index("quiesce_falco_for_installer_writes")

        self.assertLess(herodium_stop, managed_marker_guard)
        self.assertLess(managed_marker_guard, falco_quiesce)

    def test_preexisting_external_falco_is_validated_before_quiesce(self):
        section = self.installer.split("install_pinned_falco() {", 1)[1].split(
            "deactivate_falco_if_disabled() {", 1
        )[0]
        compatibility = section.index("validate_preexisting_falco_compatibility")
        quiesce = section.index("quiesce_falco_for_installer_writes")

        self.assertLess(compatibility, quiesce)

    def test_falco_stays_quiesced_until_installer_systemd_writes_finish(self):
        prepared = self.installer.split("install_pinned_falco() {", 1)[1].split(
            "deactivate_falco_if_disabled() {", 1
        )[0]
        self.assertIn("quiesce_falco_for_installer_writes", prepared)
        self.assertNotIn("systemctl restart falco-modern-bpf.service", prepared)

        scheduled_timer = self.installer.index(
            "cat >/etc/systemd/system/herodium-scheduled-scan.timer"
        )
        timer_enable = self.installer.index(
            "systemctl enable --now herodium-scheduled-scan.timer"
        )
        falco_resume = self.installer.rindex("activate_falco_after_installer_writes")
        herodium_restart = self.installer.rindex("systemctl restart herodium.service")

        self.assertLess(scheduled_timer, falco_resume)
        self.assertLess(timer_enable, falco_resume)
        self.assertLess(falco_resume, herodium_restart)

    def test_falco_resume_revalidates_runtime_before_herodium_start(self):
        section = self.installer.split("activate_falco_after_installer_writes() {", 1)[1].split(
            "validate_falco_runtime_state() {", 1
        )[0]
        restart = section.index("systemctl restart falco-modern-bpf.service")
        validation = section.index("validate_falco_runtime_state")
        self.assertLess(restart, validation)
        self.assertIn('FALCO_INSTALLER_QUIESCED="false"', section)

    def test_fresh_install_resets_stale_cursor_before_herodium_start(self):
        section = self.installer.split(
            "prepare_falco_cursor_for_fresh_install() {", 1
        )[1].split("cleanup_falco_cursor_after_failed_fresh_install() {", 1)[0]
        self.assertIn('"${INSTALL_FALCO}" != "true"', section)
        self.assertIn('"${HERODIUM_CURRENT_ROTATED}" == "true"', section)
        self.assertIn('ensure_safe_root_directory "${FALCO_STATE_DIR}" 0700', section)
        self.assertIn('rm -f -- "${FALCO_CURSOR_PATH}"', section)

        cursor_reset = self.installer.rindex("prepare_falco_cursor_for_fresh_install")
        herodium_restart = self.installer.rindex("systemctl restart herodium.service")
        self.assertLess(cursor_reset, herodium_restart)

    def test_failed_fresh_install_removes_new_falco_cursor_before_rollback(self):
        cleanup = self.installer.split(
            "cleanup_falco_cursor_after_failed_fresh_install() {", 1
        )[1].split("cleanup_falco_temporary_paths() {", 1)[0]
        self.assertIn('"${HERODIUM_CURRENT_ROTATED}" == "true"', cleanup)
        self.assertIn('rm -f -- "${FALCO_CURSOR_PATH}"', cleanup)

        handler = self.installer.split("handle_install_failure() {", 1)[1].split(
            "trap 'handle_install_failure", 1
        )[0]
        cursor_cleanup = handler.index("cleanup_falco_cursor_after_failed_fresh_install")
        deployment_rollback = handler.index("rollback_herodium_deployment")
        self.assertLess(cursor_cleanup, deployment_rollback)

    def test_held_package_is_still_recognized_as_installed(self):
        section = self.installer.split("falco_package_is_installed() {", 1)[1].split(
            "falco_package_version() {", 1
        )[0]
        self.assertIn("${db:Status-Status}", section)
        self.assertIn("grep -Fx 'installed'", section)
        self.assertNotIn("-f='${Status}'", section)
        self.assertNotIn("install ok installed", section)

    def test_preexisting_falco_is_never_silently_reconfigured(self):
        compat = self.installer.split(
            "validate_preexisting_falco_compatibility() {", 1
        )[1].split("install_verified_falco_repository() {", 1)[0]
        self.assertIn('actual_version="$(falco_package_version)"', compat)
        self.assertIn("falco_package_is_held", compat)
        self.assertIn("systemctl is-active --quiet falco-modern-bpf.service", compat)
        self.assertIn("falco-kmod.service", compat)
        self.assertIn("falco-custom.service", compat)
        self.assertIn("masked|masked-runtime", compat)
        self.assertIn("refusing takeover", compat)

    def test_marker_rejects_inconsistent_package_and_repository_ownership(self):
        validator = self.installer.split("validate_falco_ownership_marker() {", 1)[1].split(
            "load_falco_ownership_marker() {", 1
        )[0]
        self.assertIn(
            'data["package_installed_by_herodium"] != data["repository_installed_by_herodium"]',
            validator,
        )
        self.assertIn("inconsistent package/repository ownership", validator)

    def test_managed_repository_trust_material_is_refreshed_on_reenable(self):
        section = self.installer.split("install_pinned_falco() {", 1)[1].split(
            "deactivate_falco_if_disabled() {", 1
        )[0]
        self.assertIn('elif [[ "${FALCO_REPOSITORY_MANAGED}" == "true" ]]', section)
        self.assertGreaterEqual(section.count("install_verified_falco_repository"), 2)

    def test_unclaimed_existing_assets_are_rejected(self):
        section = self.installer.split("assert_unclaimed_falco_asset_slots() {", 1)[1].split(
            "begin_falco_transaction() {", 1
        )[0]
        for variable in (
            "FALCO_CONFIG_PATH",
            "FALCO_RULES_PATH",
            "FALCO_LOGROTATE_PATH",
            "FALCO_SOURCE_LIST",
            "FALCO_KEYRING",
        ):
            self.assertIn(variable, section)
        self.assertIn("Refusing to claim pre-existing Falco asset", section)

    def test_managed_assets_are_installed_from_verified_staged_snapshot(self):
        section = self.installer.split("install_falco_managed_assets() {", 1)[1].split(
            "validate_falco_runtime_state() {", 1
        )[0]
        self.assertIn("install_verified_staging_asset", section)
        self.assertIn("supply-chain/installer/falco/herodium-falco.yaml", section)
        self.assertIn("supply-chain/installer/falco/herodium-falco-rules.yaml", section)
        self.assertIn("supply-chain/installer/logrotate/herodium-falco", section)
        self.assertIn('falco --validate "${FALCO_RULES_PATH}"', section)
        self.assertIn("falco-events.jsonl", section)
        self.assertIn("0600", section)

    def test_runtime_validation_requires_exact_package_and_active_modern_driver(self):
        section = self.installer.split("validate_falco_runtime_state() {", 1)[1].split(
            "install_pinned_falco() {", 1
        )[0]
        self.assertIn('actual_version="$(falco_package_version)"', section)
        self.assertIn('[[ "${actual_version}" != "${FALCO_PACKAGE_VERSION}" ]]', section)
        self.assertIn("falco_package_is_held", section)
        self.assertIn("Falco modern-eBPF service is not enabled", section)
        self.assertIn("Falco automatic artifact updater is not masked", section)
        self.assertIn("require_active_unit falco-modern-bpf.service", section)
        self.assertIn("require_active_unit falco.service", section)
        self.assertIn("require_safe_regular_file", section)
        self.assertIn("falcoctl-artifact-follow.service", section)

    def test_rollback_purges_only_package_created_by_current_transaction(self):
        rollback = self.installer.split("rollback_falco_deployment() {", 1)[1].split(
            "persist_falco_ownership_marker() {", 1
        )[0]
        self.assertIn('"${FALCO_PACKAGE_CHANGED}" == "true"', rollback)
        self.assertIn('"${FALCO_PACKAGE_WAS_INSTALLED}" != "true"', rollback)
        self.assertIn("systemctl disable falco-modern-bpf.service", rollback)
        self.assertIn("systemctl unmask falcoctl-artifact-follow.service", rollback)
        self.assertIn("apt-get purge -y falco", rollback)
        self.assertIn("restore_falco_runtime_state", rollback)
        self.assertIn("restore_activation_file", rollback)

    def test_ownership_marker_is_private_strict_and_committed_atomically(self):
        self.assertIn('FALCO_MARKER_PATH="${FALCO_STATE_DIR}/ownership.json"', self.installer)
        validator = self.installer.split("validate_falco_ownership_marker() {", 1)[1].split(
            "load_falco_ownership_marker() {", 1
        )[0]
        self.assertIn("schema_version", validator)
        self.assertIn("package_installed_by_herodium", validator)
        self.assertIn("repository_installed_by_herodium", validator)
        writer = self.installer.split("persist_falco_ownership_marker() {", 1)[1].split(
            "commit_falco_deployment() {", 1
        )[0]
        self.assertIn("os.fsync(handle.fileno())", writer)
        self.assertIn("os.replace(temporary_name, path)", writer)
        self.assertIn("os.O_DIRECTORY", writer)
        self.assertIn('chmod 0600 "${FALCO_MARKER_PATH}"', writer)
        commit = self.installer.split("commit_herodium_deployment() {", 1)[1].split(
            "validate_existing_maltrail_config() {", 1
        )[0]
        self.assertIn("persist_falco_ownership_marker", commit)
        self.assertIn("commit_falco_deployment", commit)

    def test_marker_rollback_tracking_is_armed_before_atomic_replacement(self):
        writer = self.installer.split("persist_falco_ownership_marker() {", 1)[1].split(
            "commit_falco_deployment() {", 1
        )[0]
        changed = writer.index('FALCO_MARKER_CHANGED="true"')
        atomic_writer = writer.index("python3 -")
        replace = writer.index("os.replace(temporary_name, path)")
        self.assertLess(changed, atomic_writer)
        self.assertLess(atomic_writer, replace)
        self.assertEqual(writer.count('FALCO_MARKER_CHANGED="true"'), 1)

    def test_disabled_policy_removes_only_herodium_integration_assets(self):
        section = self.installer.split("deactivate_falco_if_disabled() {", 1)[1].split(
            "validate_existing_maltrail_config() {", 1
        )[0]
        self.assertIn('rm -f -- \\\n        "${FALCO_CONFIG_PATH}"', section)
        self.assertIn("without purging the Falco package", section)
        self.assertNotIn("apt-get purge", section)

    def test_final_installer_validation_tracks_falco_policy(self):
        section = self.installer.split("validate_final_installer_state() {", 1)[1].split(
            "trigger_installer_test_failpoint() {", 1
        )[0]
        self.assertIn('if [[ "${INSTALL_FALCO}" == "true" ]]', section)
        self.assertIn("validate_falco_runtime_state", section)
        self.assertIn("Herodium Falco assets remained installed after disable", section)

    def test_final_installer_validation_reports_required_component_failures(self):
        helper = self.installer.split("require_active_unit() {", 1)[1].split(
            "require_safe_regular_file() {", 1
        )[0]
        self.assertIn("Required systemd unit is not active", helper)
        self.assertIn('systemctl status "${unit_name}" --no-pager', helper)

        section = self.installer.split("validate_final_installer_state() {", 1)[1].split(
            "trigger_installer_test_failpoint() {", 1
        )[0]
        for unit_name in (
            "herodium.service",
            "clamav-daemon.service",
            "clamav-daemon.socket",
            "herodium-scheduled-scan.timer",
        ):
            self.assertIn(f"require_active_unit {unit_name}", section)
        self.assertIn("Final Falco runtime validation failed", section)
        self.assertIn("Final Herodium virtual-environment dependency check failed", section)
        self.assertIn("Final Herodium deployment manifest verification failed", section)
        self.assertNotIn("systemctl is-active --quiet herodium.service", section)
        self.assertNotIn("systemctl is-active --quiet clamav-daemon.service", section)
        self.assertNotIn("systemctl is-active --quiet clamav-daemon.socket", section)
        self.assertNotIn(
            "systemctl is-active --quiet herodium-scheduled-scan.timer",
            section,
        )

    def test_disabled_managed_package_check_executes_function(self):
        section = self.installer.split("deactivate_falco_if_disabled() {", 1)[1].split(
            "validate_existing_maltrail_config() {", 1
        )[0]
        self.assertIn(
            'if [[ "${FALCO_PACKAGE_MANAGED}" == "true" ]] '
            "&& falco_package_is_installed; then",
            section,
        )
        self.assertNotIn(
            '[[ "${FALCO_PACKAGE_MANAGED}" == "true" '
            "&& falco_package_is_installed ]]",
            section,
        )

    def test_global_failure_handler_rolls_back_falco_before_commit(self):
        section = self.installer.split("handle_install_failure() {", 1)[1].split(
            "trap 'handle_install_failure", 1
        )[0]
        self.assertIn("rollback_falco_deployment", section)


    def test_disabled_first_install_does_not_claim_external_falco_assets(self):
        section = self.installer.split("deactivate_falco_if_disabled() {", 1)[1].split(
            "validate_existing_maltrail_config() {", 1
        )[0]
        marker_check = section.index(
            '[[ ! -e "${FALCO_MARKER_PATH}" && ! -L "${FALCO_MARKER_PATH}" ]]'
        )
        transaction_start = section.index("begin_falco_transaction")
        self.assertLess(marker_check, transaction_start)

    def test_event_log_is_preserved_across_installer_upgrades(self):
        section = self.installer.split("install_falco_managed_assets() {", 1)[1].split(
            "validate_falco_runtime_state() {", 1
        )[0]
        self.assertIn('if [[ ! -e /var/log/herodium/falco-events.jsonl ]]', section)
        self.assertIn("chown root:root /var/log/herodium/falco-events.jsonl", section)
        self.assertIn("chmod 0600 /var/log/herodium/falco-events.jsonl", section)

    def test_uninstaller_requires_valid_marker_before_removing_falco_assets(self):
        section = self.uninstaller.split("cleanup_herodium_falco_integration() {", 1)[1]
        guard = section.index('[[ "${FALCO_MARKER_VALID}" != "true" ]]')
        removal = section.index('"${FALCO_CONFIG_PATH}"')
        self.assertLess(guard, removal)
        self.assertIn("preserving all Falco state", section)

    def test_uninstaller_recognizes_held_managed_falco_as_installed(self):
        helper = self.uninstaller.split(
            "falco_uninstall_package_is_installed() {", 1
        )[1].split("load_falco_uninstall_ownership() {", 1)[0]
        self.assertIn("${db:Status-Status}", helper)
        self.assertIn("grep -Fx 'installed'", helper)
        self.assertNotIn("${Status}", helper)

        cleanup = self.uninstaller.split(
            "cleanup_herodium_falco_integration() {", 1
        )[1]
        self.assertIn("&& falco_uninstall_package_is_installed; then", cleanup)
        self.assertNotIn("grep -Fx 'install ok installed'", cleanup)

    def test_uninstaller_never_blindly_purges_preexisting_falco(self):
        self.assertIn("load_falco_uninstall_ownership() {", self.uninstaller)
        self.assertIn("cleanup_herodium_falco_integration() {", self.uninstaller)
        self.assertIn('"${FALCO_PACKAGE_MANAGED}" == "true"', self.uninstaller)
        self.assertIn("Falco was originally installed by Herodium", self.uninstaller)
        self.assertIn("Choose NO if you now use Falco independently", self.uninstaller)
        self.assertIn("apt-get purge -y falco", self.uninstaller)
        self.assertIn("Pre-existing Falco kept", self.uninstaller)


if __name__ == "__main__":
    unittest.main()
