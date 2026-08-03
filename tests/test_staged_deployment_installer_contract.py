import contextlib
import io
import re
import runpy
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
INSTALLER = PROJECT_ROOT / "installer/install.sh"
README = PROJECT_ROOT / "README.md"
RUNTIME_LOCK = PROJECT_ROOT / "herodium/requirements.lock"
TOOLS_LOCK = PROJECT_ROOT / "installer/python-tools.lock"


EXPECTED_RUNTIME = {
    "psutil": (
        "7.2.1",
        [
            "5e38404ca2bb30ed7267a46c02f06ff842e92da3bb8c5bfdadbd35a5722314d8",
            "f7583aec590485b43ca601dd9cea0dcd65bd7bb21d30ef4ddbf4ea6b5ed1bdd3",
        ],
    ),
    "pyclamd": (
        "0.4.0",
        ["ddd588577e5db123760b6ddaac46b5c4b1d9044a00b5d9422de59f83a55c20fe"],
    ),
    "pyyaml": (
        "6.0.3",
        [
            "ba1cc08a7ccde2d2ec775841541641e4548226580ab850948cbfda66a1befcdc",
            "d76623373421df22fb4cf8817020cbb7ef15c725b9d5e45f17e189bfc384190f",
        ],
    ),
    "watchdog": (
        "6.0.0",
        [
            "20ffe5b202af80ab4266dcd3e91aae72bf2da48c0d33bdb15c66658e685e94e2",
            "9ddf7c82fda3ae8e24decda1338ede66e1c99883db93711d8fb941eaa2d8c282",
        ],
    ),
}
EXPECTED_TOOLS = {
    "pip": (
        "26.2",
        ["931c303696af6fa3417112103b1cad26890e5a07eccb5b99783700e33f2b8aad"],
    ),
    "setuptools": (
        "82.0.1",
        ["a59e362652f08dcd477c78bb6e7bd9d80a7995bc73ce773050228a348ce2e5bb"],
    ),
    "wheel": (
        "0.47.0",
        ["212281cab4dff978f6cedd499cd893e1f620791ca6ff7107cf270781e587eced"],
    ),
    "packaging": (
        "26.2",
        ["5fc45236b9446107ff2415ce77c807cee2862cb6fac22b8a73826d0693b0980e"],
    ),
}


def parse_lock(path: Path) -> dict[str, tuple[str, list[str]]]:
    packages: dict[str, tuple[str, list[str]]] = {}
    current: str | None = None
    versions: dict[str, str] = {}
    hashes: dict[str, list[str]] = {}
    requirement_re = re.compile(
        r"(?P<name>[A-Za-z0-9_.-]+)==(?P<version>[A-Za-z0-9_.+!-]+)(?: +\\)?"
    )
    hash_re = re.compile(r" +--hash=sha256:(?P<hash>[0-9a-f]{64})(?: +\\)?")

    for raw in path.read_text(encoding="utf-8").splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        requirement = requirement_re.fullmatch(raw)
        if requirement:
            current = requirement.group("name").lower().replace("_", "-")
            if current in versions:
                raise AssertionError(f"duplicate package: {current}")
            versions[current] = requirement.group("version")
            hashes[current] = []
            continue
        digest = hash_re.fullmatch(raw)
        if digest and current:
            hashes[current].append(digest.group("hash"))
            continue
        raise AssertionError(f"unsupported lock line: {raw!r}")

    for name, version in versions.items():
        packages[name] = (version, hashes[name])
    return packages


class StagedDeploymentInstallerContractTests(unittest.TestCase):
    def test_dependency_locks_are_exact_and_fully_hashed(self):
        for path, expected in (
            (RUNTIME_LOCK, EXPECTED_RUNTIME),
            (TOOLS_LOCK, EXPECTED_TOOLS),
        ):
            parsed = parse_lock(path)
            self.assertEqual(set(parsed), set(expected))
            for name, (version, expected_digests) in expected.items():
                actual_version, digests = parsed[name]
                self.assertEqual(actual_version, version)
                self.assertEqual(digests, expected_digests)
                self.assertEqual(len(set(digests)), len(expected_digests))

    def test_embedded_lock_validators_execute_with_their_real_arguments(self):
        content = INSTALLER.read_text(encoding="utf-8")

        dependency_match = re.search(
            r'python3 - "\$\{lock_path\}" "\$\{lock_kind\}" '
            r"<<'PYREQUIREMENTS'\n(?P<script>.*?)\nPYREQUIREMENTS",
            content,
            re.DOTALL,
        )
        self.assertIsNotNone(dependency_match)
        dependency_script = dependency_match.group("script")

        supply_match = re.search(
            r'parsed="\$\(python3 - "\$\{SUPPLY_CHAIN_LOCK\}" '
            r"<<'PYLOCK'\n(?P<script>.*?)\nPYLOCK",
            content,
            re.DOTALL,
        )
        self.assertIsNotNone(supply_match)
        supply_script = supply_match.group("script")
        supply_lock = PROJECT_ROOT / "installer/supply-chain-lock.json"

        original_argv = sys.argv
        output = io.StringIO()
        try:
            with tempfile.TemporaryDirectory() as temporary_directory:
                temporary_root = Path(temporary_directory)
                dependency_path = temporary_root / "dependency_validator.py"
                supply_path = temporary_root / "supply_parser.py"
                dependency_path.write_text(dependency_script, encoding="utf-8")
                supply_path.write_text(supply_script, encoding="utf-8")

                for path, kind in (
                    (TOOLS_LOCK, "tools"),
                    (RUNTIME_LOCK, "runtime"),
                ):
                    sys.argv = [str(dependency_path), str(path), kind]
                    runpy.run_path(str(dependency_path), run_name="__main__")

                sys.argv = [str(supply_path), str(supply_lock)]
                with contextlib.redirect_stdout(output):
                    runpy.run_path(str(supply_path), run_name="__main__")
        finally:
            sys.argv = original_argv

        fields = output.getvalue().strip().split("\t")
        self.assertEqual(len(fields), 3)
        self.assertEqual(fields[0], "https://github.com/stamparm/maltrail.git")

    def test_pip_is_isolated_hashed_and_dependency_closed(self):
        content = INSTALLER.read_text(encoding="utf-8")

        self.assertIn("PIP_CONFIG_FILE=/dev/null", content)
        self.assertIn("PYTHONNOUSERSITE=1", content)
        install_command = content.index("                install \\")
        index_url = content.index(
            "                --index-url https://pypi.org/simple \\",
            install_command,
        )
        self.assertLess(install_command, index_url)
        self.assertGreaterEqual(content.count("--require-hashes"), 2)
        self.assertGreaterEqual(content.count("--no-deps"), 2)
        self.assertIn("--no-build-isolation", content)
        self.assertNotIn("pip install --upgrade", content)
        self.assertNotIn('pip" uninstall', content)
        self.assertNotIn('pip" install -r "${APP_DIR}/requirements.txt"', content)
        self.assertIn('validate_installer_lock_file "${PYTHON_TOOLS_LOCK}" tools', content)
        self.assertIn('validate_installer_lock_file "${RUNTIME_REQUIREMENTS_LOCK}" runtime', content)
        self.assertIn('"pyclamd": "0.4.0"', content)
        self.assertIn('"setuptools": "82.0.1"', content)

    def test_staged_unit_verifier_uses_staged_runtime_on_fresh_install(self):
        content = INSTALLER.read_text(encoding="utf-8")
        renderer_match = re.search(
            r"python3 - \\\n"
            r'        "\$\{source_unit\}" \\\n'
            r'        "\$\{verify_unit\}" \\\n'
            r'        "\$\{APP_DIR\}" \\\n'
            r'        "\$\{APP_STAGE_DIR\}" <<\'PYSYSTEMD\'\n'
            r"(?P<script>.*?)\nPYSYSTEMD",
            content,
            re.DOTALL,
        )
        self.assertIsNotNone(renderer_match)
        renderer_script = renderer_match.group("script")

        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            stage = temporary_root / "herodium.stage"
            source_unit = temporary_root / "herodium.service"
            rendered_unit = temporary_root / "rendered.service"
            renderer_path = temporary_root / "render_unit.py"

            (stage / "venv/bin").mkdir(parents=True)
            (stage / "core").mkdir()
            (stage / "venv/bin/python3").symlink_to(sys.executable)
            (stage / "core/engine.py").write_text(
                "print('fresh-install-stage')\n",
                encoding="utf-8",
            )
            source_unit.write_text(
                (
                    PROJECT_ROOT / "installer/systemd/herodium.service"
                ).read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            renderer_path.write_text(renderer_script, encoding="utf-8")

            original_argv = sys.argv
            try:
                sys.argv = [
                    str(renderer_path),
                    str(source_unit),
                    str(rendered_unit),
                    "/opt/herodium",
                    str(stage),
                ]
                runpy.run_path(str(renderer_path), run_name="__main__")
            finally:
                sys.argv = original_argv

            rendered = rendered_unit.read_text(encoding="utf-8")
            self.assertIn(f"WorkingDirectory={stage}", rendered)
            self.assertIn(
                f"ExecStart={stage}/venv/bin/python3 {stage}/core/engine.py",
                rendered,
            )
            self.assertNotIn(
                "ExecStart=/opt/herodium/venv/bin/python3",
                rendered,
            )
            self.assertEqual(rendered_unit.stat().st_mode & 0o777, 0o600)

        function = content.split(
            "validate_staged_systemd_units() {",
            1,
        )[1].split(
            "run_staged_pip() {",
            1,
        )[0]
        self.assertIn('systemd-analyze verify \\\n        "${verify_unit}"', function)
        self.assertNotIn(
            'systemd-analyze verify \\\n'
            '        "${APP_STAGE_DIR}/supply-chain/installer/systemd/herodium.service"',
            function,
        )

    def test_complete_stage_is_built_before_service_quiesce(self):
        content = INSTALLER.read_text(encoding="utf-8")
        stage = content.index("prepare_staged_herodium_deployment", 1000)
        quiesce = content.index(
            'echo "[INFO] Quiescing existing Herodium service..."'
        )

        self.assertLess(stage, quiesce)
        self.assertIn('APP_STAGE_DIR="/opt/herodium.stage"', content)
        self.assertIn("validate_staged_python_environment", content)
        self.assertIn("create_staged_deployment_manifest", content)
        self.assertIn("verify_herodium_source_snapshot", content)

    def test_active_venv_is_never_modified_in_place(self):
        content = INSTALLER.read_text(encoding="utf-8")

        self.assertIn('python3 -m venv --clear "${APP_STAGE_DIR}/venv"', content)
        self.assertIn('"${APP_STAGE_DIR}/venv/bin/python3" -m pip', content)
        self.assertNotIn('python3 -m venv "${APP_DIR}/venv"', content)
        self.assertNotIn('"${APP_DIR}/venv/bin/pip"', content)

    def test_config_and_quarantine_are_preserved_safely(self):
        content = INSTALLER.read_text(encoding="utf-8")

        self.assertIn("validate_existing_herodium_config", content)
        self.assertIn(
            '"${APP_DIR}/config/herodium.yaml"',
            content,
        )
        quiesce = content.index('INSTALL_PHASE="quiesced"')
        state_copy = content.index("copy_runtime_state_into_stage", quiesce)
        activation = content.index("activate_staged_herodium_deployment", state_copy)
        self.assertLess(quiesce, state_copy)
        self.assertLess(state_copy, activation)
        self.assertIn("Existing quarantine contains an unsupported path", content)
        self.assertIn("Existing quarantine contains a non-root-owned path", content)

    def test_activation_is_atomic_and_keeps_previous_deployment(self):
        content = INSTALLER.read_text(encoding="utf-8")

        self.assertIn('APP_PREVIOUS_DIR="/opt/herodium.previous"', content)
        self.assertIn('mv -- "${APP_DIR}" "${APP_PREVIOUS_DIR}"', content)
        self.assertIn('mv -- "${APP_STAGE_DIR}" "${APP_DIR}"', content)
        self.assertIn('sha256sum -c .herodium-deployment.sha256', content)

    def test_failure_restores_code_unit_and_service_state(self):
        content = INSTALLER.read_text(encoding="utf-8")

        self.assertIn("rollback_herodium_deployment", content)
        self.assertIn('mv -- "${APP_PREVIOUS_DIR}" "${APP_DIR}"', content)
        self.assertIn("HERODIUM_UNIT_BACKUP", content)
        self.assertIn("HERODIUM_ENABLEMENT", content)
        self.assertIn("HERODIUM_WAS_ACTIVE", content)
        self.assertIn("backup_herodium_cli_assets", content)
        self.assertIn("restore_activation_file", content)
        self.assertIn("HERODIUM_CLI_CHANGED", content)
        self.assertIn("HERODIUM_ENABLEMENT", content)
        self.assertIn(
            'restore_unit_enablement herodium.service "${HERODIUM_ENABLEMENT}"',
            content,
        )
        self.assertIn("systemctl start herodium.service", content)

    def test_commit_requires_protected_health_and_retains_manifest(self):
        content = INSTALLER.read_text(encoding="utf-8")
        health = content.index("validate_activated_herodium_service", 1000)
        commit = content.index("commit_herodium_deployment", health)

        self.assertLess(health, commit)
        self.assertIn("System is PROTECTED[.] Monitoring active[.][.][.]", content)
        self.assertIn(
            'DEPLOYMENT_MANIFEST_PATH="${DEPLOYMENT_MANIFEST_DIR}/herodium-deployment.sha256"',
            content,
        )
        self.assertIn('HERODIUM_DEPLOYMENT_COMMITTED="true"', content)


    def test_runtime_installer_assets_are_snapshotted_and_manifested(self):
        content = INSTALLER.read_text(encoding="utf-8")

        self.assertIn("install_verified_staging_asset", content)
        for relative_path in (
            "systemd/herodium.service",
            "systemd/maltrail-sensor.service",
            "bin/herodium-scan",
            "bin/herodium-top",
            "bin/herodium-rkhunter-baseline",
            "supply-chain-lock.json",
        ):
            self.assertIn(
                f"supply-chain/installer/{relative_path}",
                content,
            )
        self.assertIn(
            '"${APP_STAGE_DIR}/modules/apparmor_state.py" migrate',
            content,
        )
        self.assertIn(
            '"${APP_DIR}/supply-chain/installer/systemd/herodium.service"',
            content,
        )

    def test_readme_documents_staging_hashes_and_rollback(self):
        content = README.read_text(encoding="utf-8")

        self.assertIn("`/opt/herodium.stage`", content)
        self.assertIn("`/opt/herodium.previous`", content)
        self.assertIn("`installer/python-tools.lock`", content)
        self.assertIn("`herodium/requirements.lock`", content)
        self.assertIn("restores the previous deployment", content)
        self.assertIn("sudo bash installer/install.sh", content)


if __name__ == "__main__":
    unittest.main()
