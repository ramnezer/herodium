import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
INSTALLER = PROJECT_ROOT / "installer/install.sh"
MALTRAIL_SERVICE = PROJECT_ROOT / "installer/systemd/maltrail-sensor.service"
README = PROJECT_ROOT / "README.md"


class InstallerReliabilityContractTests(unittest.TestCase):
    def setUp(self):
        self.content = INSTALLER.read_text(encoding="utf-8")

    def test_timeshift_is_headless_on_demand_and_verified(self):
        self.assertIn('[[ "${name}" == "notify-send" ]] && continue', self.content)
        self.assertIn("/usr/sbin /usr/bin /sbin /bin", self.content)
        self.assertNotIn("/usr/local/sbin /usr/local/bin /usr/sbin", self.content)
        self.assertIn("/usr/bin/timeshift --scripted", self.content)
        self.assertIn("--tags O", self.content)
        self.assertIn("create_verified_timeshift_snapshot", self.content)
        self.assertIn('run_timeshift_headless --list', self.content)
        self.assertIn("Timeshift snapshot verified", self.content)
        self.assertNotIn(
            'timeshift --create --comments "Pre_AppArmor_Change"',
            self.content,
        )

    def test_clamav_socket_service_and_updater_are_one_transaction(self):
        function = self.content.split(
            "configure_clamav_transactionally() {", 1
        )[1].split(
            "# ==============================================================================\n"
            "# MAIN INSTALLATION LOGIC", 1
        )[0]
        capture = function.index("capture_clamav_state")
        stop = function.index("systemctl stop")
        temporary = function.index('set_clamd_option "TemporaryDirectory"')
        reload_units = function.index("systemctl daemon-reload", temporary)
        start_socket = function.index("systemctl start clamav-daemon.socket")
        start_daemon = function.index("systemctl start clamav-daemon.service")

        self.assertLess(capture, stop)
        self.assertLess(stop, temporary)
        self.assertLess(temporary, reload_units)
        self.assertLess(reload_units, start_socket)
        self.assertLess(start_socket, start_daemon)
        self.assertIn("clamav-daemon.socket", function)
        self.assertIn("clamav-freshclam.service", function)
        self.assertIn("CLAMAV_CONFIG_MODE", self.content)
        self.assertIn("CLAMAV_CONFIG_UID", self.content)
        self.assertIn("CLAMAV_CONFIG_GID", self.content)
        self.assertIn("restore_unit_enablement clamav-daemon.socket", self.content)

    def test_maltrail_has_graceful_multiprocess_shutdown(self):
        service = MALTRAIL_SERVICE.read_text(encoding="utf-8")
        self.assertIn("KillSignal=SIGINT", service)
        self.assertIn("KillMode=mixed", service)
        self.assertIn("TimeoutStopSec=60s", service)
        self.assertIn("SuccessExitStatus=130 SIGINT", service)

        installer = self.content.split("install_pinned_maltrail() {", 1)[1]
        unit_install = installer.index(
            '"${APP_DIR}/supply-chain/installer/systemd/maltrail-sensor.service"'
        )
        reload_units = installer.index("systemctl daemon-reload", unit_install)
        stop = installer.index("systemctl stop maltrail-sensor.service", reload_units)
        rotate = installer.index(
            'mv -- "${MALTRAIL_DIR}" "${MALTRAIL_PREVIOUS_DIR}"', stop
        )
        self.assertLess(unit_install, reload_units)
        self.assertLess(reload_units, stop)
        self.assertLess(stop, rotate)

    def test_maltrail_config_environment_marker_and_state_rollback(self):
        for token in (
            "MALTRAIL_CONFIG_BACKUP",
            "MALTRAIL_ENV_BACKUP",
            "MALTRAIL_MARKER_BACKUP",
            "MALTRAIL_PENDING_COMMIT",
            "MALTRAIL_STATE_DIR_EXISTED",
            "rollback_maltrail_deployment",
            "commit_maltrail_deployment",
        ):
            self.assertIn(token, self.content)

        install_function = self.content.split("install_pinned_maltrail() {", 1)[1]
        self.assertNotIn(
            "| install -o root -g root -m 0600 /dev/stdin \n"
            "            /var/lib/herodium/supply-chain/maltrail-commit",
            install_function.split("# WIZARD FUNCTIONS", 1)[0],
        )
        persist_function = self.content.split(
            "persist_maltrail_commit_marker() {", 1
        )[1].split("commit_maltrail_deployment() {", 1)[0]
        self.assertIn(
            "/var/lib/herodium/supply-chain/maltrail-commit",
            persist_function,
        )

    def test_disabled_maltrail_is_stopped_transactionally(self):
        self.assertIn("deactivate_maltrail_if_disabled", self.content)
        self.assertIn("systemctl disable maltrail-sensor.service", self.content)
        self.assertIn(
            "Maltrail remained active after it was disabled by policy",
            self.content,
        )
        selected = self.content.index('if [[ "${INSTALL_MALTRAIL}" == "true" ]]')
        deactivate = self.content.index("deactivate_maltrail_if_disabled", selected)
        self.assertLess(selected, deactivate)

    def test_activation_assets_are_backed_up_before_quiesce(self):
        main = self.content.index("# MAIN INSTALLATION LOGIC")
        stage = self.content.index("prepare_staged_herodium_deployment", main)
        quiesce = self.content.index(
            'echo "[INFO] Quiescing existing Herodium service..."', stage
        )
        for call in (
            "backup_herodium_service_unit",
            "backup_herodium_cli_assets",
            "backup_herodium_auxiliary_assets",
            "backup_scheduled_scan_assets",
        ):
            self.assertLess(self.content.index(call, stage), quiesce)
        self.assertIn("rollback_scheduled_scan_assets", self.content)
        self.assertIn("SCHEDULED_TIMER_ENABLEMENT", self.content)
        self.assertIn("DEPLOYMENT_MANIFEST_BACKUP", self.content)
        self.assertIn("HERODIUM_LOGROTATE_BACKUP", self.content)

    def test_failure_rolls_back_dependencies_before_restarting_old_herodium(self):
        handler = self.content.split("handle_install_failure() {", 1)[1].split(
            "trap 'handle_install_failure", 1
        )[0]
        stop = handler.index("systemctl stop herodium.service")
        scheduled = handler.index("rollback_scheduled_scan_assets")
        maltrail = handler.index("rollback_maltrail_deployment")
        clamav = handler.index("rollback_clamav_configuration")
        herodium = handler.index("rollback_herodium_deployment")
        self.assertLess(stop, scheduled)
        self.assertLess(scheduled, maltrail)
        self.assertLess(maltrail, clamav)
        self.assertLess(clamav, herodium)

    def test_failpoint_is_after_final_validation_and_before_commit(self):
        final = self.content.index("validate_final_installer_state", 1000)
        failpoint = self.content.index(
            "trigger_installer_test_failpoint after_final_validation",
            final,
        )
        commit = self.content.index("commit_herodium_deployment", failpoint)
        self.assertLess(final, failpoint)
        self.assertLess(failpoint, commit)
        self.assertIn("HERODIUM_INSTALLER_TEST_ACKNOWLEDGE", self.content)
        self.assertIn("ROLLBACK-TEST", self.content)

    def test_mutable_configuration_is_excluded_from_manifest(self):
        function = self.content.split("create_staged_deployment_manifest() {", 1)[1].split(
            "validate_staged_python_environment() {", 1
        )[0]
        self.assertIn("! -path './config/herodium.yaml'", function)
        previous = self.content.split("validate_previous_deployment_candidate() {", 1)[1]
        self.assertIn('$2 != "./config/herodium.yaml"', previous)

    def test_firewall_cleanup_occurs_only_after_commit(self):
        commit_call = self.content.index("commit_herodium_deployment", 1000)
        cleanup_call = self.content.index("remove_herodium_firewall_state", commit_call)
        self.assertLess(commit_call, cleanup_call)
        pre_stage = self.content[: self.content.index("prepare_staged_herodium_deployment", 1000)]
        self.assertNotIn("remove_herodium_firewall_state\nfi", pre_stage)

    def test_final_unit_verification_is_dynamic_and_sleep_removed(self):
        self.assertIn("FINAL_UNITS=(", self.content)
        self.assertIn("/etc/systemd/system/maltrail-sensor.service", self.content)
        self.assertIn("/etc/systemd/system/herodium-maltrail-update.service", self.content)
        self.assertIn("/etc/systemd/system/herodium-maltrail-update.timer", self.content)
        self.assertIn('systemd-analyze verify "${FINAL_UNITS[@]}"', self.content)
        self.assertNotIn("sleep 120", self.content)

    def test_readme_documents_reliability_and_rollback_test(self):
        readme = README.read_text(encoding="utf-8")
        self.assertIn("Installer reliability and rollback testing", readme)
        self.assertIn("HERODIUM_INSTALLER_TEST_FAILPOINT", readme)
        self.assertIn("HERODIUM_INSTALLER_TEST_ACKNOWLEDGE", readme)
        self.assertIn("ClamAV configuration and service/socket/updater state", readme)


if __name__ == "__main__":
    unittest.main()
