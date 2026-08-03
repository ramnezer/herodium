import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
INSTALLER = PROJECT_ROOT / "installer/install.sh"
UNINSTALLER = PROJECT_ROOT / "installer/uninstall.sh"


class AppArmorInstallerContractTests(unittest.TestCase):
    def test_migration_runs_before_atomic_activation(self):
        content = INSTALLER.read_text(encoding="utf-8")
        migration = content.index(
            '"${APP_STAGE_DIR}/modules/apparmor_state.py" migrate'
        )
        activation = content.index("activate_staged_herodium_deployment", migration)

        self.assertLess(migration, activation)

    def test_stage_build_precedes_quiesce_but_activation_follows_migration(self):
        content = INSTALLER.read_text(encoding="utf-8")

        stage = content.index("prepare_staged_herodium_deployment", 1000)
        quiesce = content.index(
            'echo "[INFO] Quiescing existing Herodium service..."'
        )
        quiescing_phase = content.index(
            'INSTALL_PHASE="quiescing"',
            quiesce,
        )
        stop_service = content.index(
            "systemctl stop herodium.service",
            quiesce,
        )
        quiesced_phase = content.index(
            'INSTALL_PHASE="quiesced"',
            stop_service,
        )
        migration = content.index(
            '"${APP_STAGE_DIR}/modules/apparmor_state.py" migrate'
        )
        activation = content.index("activate_staged_herodium_deployment", migration)
        service_restart = content.index("systemctl restart herodium.service")
        restarted_phase = content.index(
            'INSTALL_PHASE="service_restarted"',
            service_restart,
        )

        self.assertIn("set -Eeuo pipefail", content)
        self.assertIn("trap 'handle_install_failure $?' ERR", content)
        self.assertLess(stage, quiesce)
        self.assertLess(quiesce, quiescing_phase)
        self.assertLess(quiescing_phase, stop_service)
        self.assertLess(stop_service, quiesced_phase)
        self.assertLess(quiesced_phase, migration)
        self.assertLess(migration, activation)
        self.assertLess(activation, service_restart)
        self.assertLess(service_restart, restarted_phase)
        self.assertIn('INSTALL_PHASE="complete"', content)
        self.assertIn("trap - ERR INT TERM", content)

    def test_uninstall_restores_with_state_tool_and_preserves_state(self):
        content = UNINSTALLER.read_text(encoding="utf-8")

        self.assertIn('python3 "${APPARMOR_STATE_TOOL}" restore', content)
        self.assertIn('python3 "${APPARMOR_STATE_TOOL}" write-level 1', content)
        self.assertNotIn(
            '${APP_DIR}/apparmor_state_data/baseline_force-complain',
            content,
        )
        self.assertNotIn('rm -rf "/var/lib/herodium"', content)
        self.assertNotIn('rm -rf /var/lib/herodium', content)


if __name__ == "__main__":
    unittest.main()
