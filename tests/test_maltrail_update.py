import os
import runpy
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


PROJECT_ROOT = Path(__file__).resolve().parents[1]
UPDATER = PROJECT_ROOT / "installer/bin/herodium-maltrail-update"
INSTALLER = PROJECT_ROOT / "installer/install.sh"
UNINSTALLER = PROJECT_ROOT / "installer/uninstall.sh"
SERVICE = PROJECT_ROOT / "installer/systemd/herodium-maltrail-update.service"
TIMER = PROJECT_ROOT / "installer/systemd/herodium-maltrail-update.timer"
README = PROJECT_ROOT / "README.md"


class MaltrailUpdateContractTests(unittest.TestCase):
    def setUp(self):
        self.updater = UPDATER.read_text(encoding="utf-8")
        self.installer = INSTALLER.read_text(encoding="utf-8")

    def test_sensor_remains_offline_but_timer_refreshes_daily(self):
        sensor = (
            PROJECT_ROOT / "installer/systemd/maltrail-sensor.service"
        ).read_text(encoding="utf-8")
        timer = TIMER.read_text(encoding="utf-8")

        self.assertIn("sensor.py --offline", sensor)
        self.assertIn("OnActiveSec=20min", timer)
        self.assertIn("OnUnitActiveSec=24h", timer)
        self.assertIn("RandomizedDelaySec=2h", timer)
        self.assertIn("Unit=herodium-maltrail-update.service", timer)

    def test_updater_keeps_code_pinned_and_limits_transport(self):
        self.assertNotIn("git pull", self.updater)
        self.assertNotIn("git clone", self.updater)
        self.assertIn('MALTRAIL_ROOT: Final = Path("/opt/maltrail")', self.updater)
        self.assertIn("https-only-feed-modules", self.updater)
        self.assertIn(
            "ssl._create_default_https_context = ssl.create_default_context",
            self.updater,
        )
        self.assertIn(
            "common_module.retrieve_content = https_only_retrieve_content",
            self.updater,
        )
        self.assertIn(
            "update_module.retrieve_content = https_only_retrieve_content",
            self.updater,
        )
        self.assertIn('scheme != "https"', self.updater)
        self.assertIn('config.UPDATE_SERVER = ""', self.updater)
        self.assertIn('config.CUSTOM_TRAILS_URL = ""', self.updater)
        self.assertIn('config.TRAILS_FILE = os.path.join', self.updater)
        self.assertIn("_disabled_insecure_feeds", self.updater)

    def test_feed_url_parser_accepts_only_literal_https(self):
        namespace = runpy.run_path(str(UPDATER))
        parser = namespace["_extract_literal_url"]

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            secure = root / "secure.py"
            insecure = root / "insecure.py"
            dynamic = root / "dynamic.py"
            secure.write_text(
                '__url__ = "https://example.test/feed"\n'
                '__check__ = "http://"\n',
                encoding="utf-8",
            )
            insecure.write_text('__url__ = "http://example.test/feed"\n', encoding="utf-8")
            dynamic.write_text('__url__ = build_url()\n', encoding="utf-8")
            mixed = root / "mixed.py"
            mixed.write_text(
                '__url__ = "https://example.test/feed"\n'
                'MIRROR_URLS = ("https://safe.test/feed", "http://unsafe.test/feed")\n',
                encoding="utf-8",
            )

            self.assertEqual(parser(secure), "https://example.test/feed")
            self.assertEqual(parser(insecure), "http://example.test/feed")
            self.assertIsNone(parser(dynamic))
            policy = namespace["_feed_module_is_https_only"]
            self.assertTrue(policy(secure))
            self.assertFalse(policy(insecure))
            self.assertFalse(policy(dynamic))
            self.assertFalse(policy(mixed))

    def test_updater_tightens_safe_upstream_state_directory(self):
        namespace = runpy.run_path(str(UPDATER))
        harden = namespace["_harden_private_root_directory"]
        real_fstat = os.fstat

        def root_owned_fstat(descriptor):
            info = real_fstat(descriptor)
            return SimpleNamespace(st_mode=info.st_mode, st_uid=0)

        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / ".maltrail"
            path.mkdir(mode=0o755)
            path.chmod(0o755)

            with patch.object(os, "fstat", side_effect=root_owned_fstat):
                harden(path)

            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)

    def test_updater_rejects_writable_state_directory(self):
        namespace = runpy.run_path(str(UPDATER))
        harden = namespace["_harden_private_root_directory"]
        update_error = namespace["UpdateError"]
        real_fstat = os.fstat

        def root_owned_fstat(descriptor):
            info = real_fstat(descriptor)
            return SimpleNamespace(st_mode=info.st_mode, st_uid=0)

        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / ".maltrail"
            path.mkdir(mode=0o775)
            path.chmod(0o775)

            with patch.object(os, "fstat", side_effect=root_owned_fstat):
                with self.assertRaisesRegex(
                    update_error, "group/world-writable"
                ):
                    harden(path)

            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o775)

    def test_candidate_has_staging_validation_atomic_activation_and_rollback(self):
        for token in (
            "tempfile.mkdtemp",
            "MIN_CURRENT_RATIO",
            "MAX_TRAIL_ROWS",
            "MAX_TRAIL_BYTES",
            "csv.reader",
            "os.replace",
            "trails.csv.previous",
            "_restart_sensor_and_wait",
            "rollback could not restore Maltrail",
            "maltrail-trails.json",
        ):
            self.assertIn(token, self.updater)

    def test_installer_manages_updater_assets_transactionally(self):
        for token in (
            "MALTRAIL_UPDATE_TOOL_BACKUP",
            "MALTRAIL_UPDATE_SERVICE_BACKUP",
            "MALTRAIL_UPDATE_TIMER_BACKUP",
            "/usr/local/sbin/herodium-maltrail-update",
            "/etc/systemd/system/herodium-maltrail-update.service",
            "/etc/systemd/system/herodium-maltrail-update.timer",
            "systemctl enable --now herodium-maltrail-update.timer",
            "restore_unit_enablement",
        ):
            self.assertIn(token, self.installer)

        install_function = self.installer.split("install_pinned_maltrail() {", 1)[1]
        timer_stop = install_function.index(
            "systemctl stop herodium-maltrail-update.timer"
        )
        updater_stop = install_function.index(
            "systemctl stop herodium-maltrail-update.service"
        )
        source_fetch = install_function.index(
            'echo "[INFO] Fetching pinned Maltrail commit:'
        )
        self.assertLess(timer_stop, source_fetch)
        self.assertLess(updater_stop, source_fetch)
        self.assertIn(
            "Controlled Maltrail updater did not stop before deployment",
            install_function[:source_fetch],
        )

        uninstaller = UNINSTALLER.read_text(encoding="utf-8")
        self.assertIn("systemctl stop herodium-maltrail-update.timer", uninstaller)
        self.assertIn("rm -f /usr/local/sbin/herodium-maltrail-update", uninstaller)
        self.assertIn(
            "rm -f /etc/systemd/system/herodium-maltrail-update.timer",
            uninstaller,
        )

    def test_service_is_bounded_and_read_only_outside_state(self):
        service = SERVICE.read_text(encoding="utf-8")
        self.assertIn("Type=oneshot", service)
        self.assertIn("TimeoutStartSec=2100", service)
        self.assertIn("NoNewPrivileges=true", service)
        self.assertIn("PrivateTmp=true", service)
        self.assertIn("ProtectSystem=strict", service)
        self.assertIn("ReadWritePaths=/var/lib/maltrail", service)
        self.assertIn("RuntimeDirectory=herodium-maltrail-update", service)
        self.assertIn("ProtectHome=true", service)
        self.assertIn("ExecStart=/usr/local/sbin/herodium-maltrail-update", service)
        self.assertIn("MemoryHigh=1500M", service)
        self.assertIn("MemoryMax=2G", service)
        self.assertIn("TasksMax=64", service)

    def test_readme_documents_controlled_mutable_trails(self):
        readme = README.read_text(encoding="utf-8")
        self.assertIn("herodium-maltrail-update.timer", readme)
        self.assertIn("per 24 hours", readme)
        self.assertIn("strict UTF-8/CSV validation", readme)
        self.assertIn("previous `trails.csv` is restored automatically", readme)
        self.assertIn("reviewed and", readme)
        self.assertIn("immutable", readme)


if __name__ == "__main__":
    unittest.main()
