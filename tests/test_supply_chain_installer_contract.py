import json
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
INSTALLER = PROJECT_ROOT / "installer/install.sh"
LOCK = PROJECT_ROOT / "installer/supply-chain-lock.json"
SERVICE = PROJECT_ROOT / "installer/systemd/maltrail-sensor.service"
README = PROJECT_ROOT / "README.md"


class SupplyChainInstallerContractTests(unittest.TestCase):
    def test_maltrail_lock_is_exact_and_immutable(self):
        lock = json.loads(LOCK.read_text(encoding="utf-8"))

        self.assertEqual(lock["schema_version"], 1)
        self.assertEqual(
            lock["maltrail"],
            {
                "repository": "https://github.com/stamparm/maltrail.git",
                "commit": "32bb71160d0c4305386838a29df67923c2919196",
                "license_sha256": (
                    "36d6d9af4331b4153c4d8dc5e3d92836794bd3bfb44744ed"
                    "24fb4673413d9a0a"
                ),
            },
        )

    def test_installer_never_advances_maltrail_from_a_branch(self):
        content = INSTALLER.read_text(encoding="utf-8")

        self.assertNotIn("git clone --depth 1", content)
        self.assertNotIn("git -C \"${MALTRAIL_DIR}\" pull", content)
        self.assertNotIn("origin master", content)
        self.assertIn(
            'fetch --quiet --depth 1 --no-tags origin "${MALTRAIL_COMMIT}"',
            content,
        )
        self.assertIn(
            '[[ "${actual_commit}" != "${MALTRAIL_COMMIT}" ]]',
            content,
        )
        self.assertIn(
            'run_pinned_git -C "${MALTRAIL_FETCH_DIR}" fsck --full --strict --no-dangling',
            content,
        )
        self.assertIn("GIT_CONFIG_GLOBAL=/dev/null", content)
        self.assertIn("GIT_CONFIG_NOSYSTEM=1", content)
        self.assertIn("GIT_TERMINAL_PROMPT=0", content)

    def test_shell_safe_commit_peeling_and_service_state_ordering(self):
        content = INSTALLER.read_text(encoding="utf-8")

        self.assertIn('rev-parse --verify "FETCH_HEAD^{commit}"', content)
        self.assertIn("symbolic-ref HEAD refs/heads/herodium-pinned", content)
        transaction = content.split("begin_maltrail_transaction() {", 1)[1].split(
            "deactivate_maltrail_if_disabled() {", 1
        )[0]
        installer = content.split("install_pinned_maltrail() {", 1)[1].split(
            "# ==============================================================================\n"
            "# WIZARD FUNCTIONS", 1
        )[0]
        active_probe = transaction.index(
            "systemctl is-active --quiet maltrail-sensor.service"
        )
        unit_install = installer.index(
            '"${APP_DIR}/supply-chain/installer/systemd/maltrail-sensor.service"'
        )
        self.assertGreaterEqual(active_probe, 0)
        self.assertGreaterEqual(unit_install, 0)

    def test_license_hash_and_content_only_extraction_are_required(self):
        content = INSTALLER.read_text(encoding="utf-8")

        self.assertIn('sha256sum "${MALTRAIL_STAGE_DIR}/LICENSE"', content)
        self.assertIn(
            '[[ "${actual_license_sha256}" != "${MALTRAIL_LICENSE_SHA256}" ]]',
            content,
        )
        self.assertIn('run_pinned_git -C "${MALTRAIL_FETCH_DIR}" archive --format=tar', content)
        self.assertNotIn('mv -- "${MALTRAIL_FETCH_DIR}" "${MALTRAIL_DIR}"', content)

    def test_pcap_package_is_selected_without_failed_install_probe(self):
        content = INSTALLER.read_text(encoding="utf-8")

        self.assertIn(
            "for candidate in python3-pcapy-ng python3-pcapy",
            content,
        )
        self.assertIn('apt-cache show "${candidate}"', content)
        self.assertNotIn(
            "apt-get install -y python3-pcapy-ng || apt-get install -y python3-pcapy",
            content,
        )
        self.assertIn("python3 -c 'import pcapy'", content)

    def test_service_is_offline_and_uses_explicit_configuration(self):
        content = SERVICE.read_text(encoding="utf-8")

        self.assertIn(
            "ExecStart=/usr/bin/python3 /opt/maltrail/sensor.py --offline "
            "-c /etc/maltrail/maltrail.conf",
            content,
        )
        self.assertIn(
            "EnvironmentFile=/etc/maltrail/herodium-maltrail.env",
            content,
        )
        self.assertIn("ConditionPathExists=/opt/maltrail/sensor.py", content)
        self.assertIn(
            "ConditionFileNotEmpty=/etc/maltrail/maltrail.conf",
            content,
        )

    def test_state_is_namespaced_and_activation_has_rollback(self):
        content = INSTALLER.read_text(encoding="utf-8")

        self.assertIn(
            'MALTRAIL_STATE_DIR="${MALTRAIL_STATE_BASE}/offline-${MALTRAIL_COMMIT}"',
            content,
        )
        self.assertIn('MALTRAIL_PREVIOUS_DIR="/opt/maltrail.previous"', content)
        self.assertIn(
            "Pinned Maltrail failed health validation; restoring previous deployment",
            content,
        )
        self.assertIn(
            "/var/lib/herodium/supply-chain/maltrail-commit",
            content,
        )
        self.assertIn('"--exclude-dir=^/var/lib/maltrail($|/)"', content)

    def test_readme_documents_the_safe_default(self):
        content = README.read_text(encoding="utf-8")

        self.assertIn("does not install Maltrail from a moving branch", content)
        self.assertIn("upstream feed downloads disabled by default", content)
        self.assertIn("`/opt/maltrail.previous`", content)


if __name__ == "__main__":
    unittest.main()
