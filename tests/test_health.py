import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
HERODIUM_ROOT = PROJECT_ROOT / "herodium"
if str(HERODIUM_ROOT) not in sys.path:
    sys.path.insert(0, str(HERODIUM_ROOT))

from core.health import (  # noqa: E402
    ComponentHealth,
    ComponentState,
    HealthReport,
    SystemHealth,
)


class HealthReportTests(unittest.TestCase):
    def test_required_failure_makes_system_failed(self):
        report = HealthReport.from_components(
            (
                ComponentHealth(
                    "clamav", ComponentState.FAILED, required=True
                ),
                ComponentHealth("apparmor", ComponentState.HEALTHY),
            )
        )

        self.assertIs(report.state, SystemHealth.FAILED)
        self.assertEqual(
            tuple(component.name for component in report.failed_required),
            ("clamav",),
        )

    def test_optional_failure_makes_system_degraded(self):
        report = HealthReport.from_components(
            (
                ComponentHealth(
                    "clamav", ComponentState.HEALTHY, required=True
                ),
                ComponentHealth("maltrail", ComponentState.FAILED),
            )
        )

        self.assertIs(report.state, SystemHealth.DEGRADED)
        self.assertEqual(
            tuple(component.name for component in report.impaired),
            ("maltrail",),
        )

    def test_degraded_component_makes_system_degraded(self):
        report = HealthReport.from_components(
            (
                ComponentHealth(
                    "clamav", ComponentState.HEALTHY, required=True
                ),
                ComponentHealth("apparmor", ComponentState.DEGRADED),
            )
        )

        self.assertIs(report.state, SystemHealth.DEGRADED)

    def test_disabled_components_do_not_degrade_health(self):
        report = HealthReport.from_components(
            (
                ComponentHealth(
                    "clamav", ComponentState.HEALTHY, required=True
                ),
                ComponentHealth(
                    "maltrail", ComponentState.DISABLED_BY_POLICY
                ),
                ComponentHealth(
                    "memory_hunter", ComponentState.DISABLED_BY_POLICY
                ),
            )
        )

        self.assertIs(report.state, SystemHealth.PROTECTED)
        self.assertIs(
            report.component("maltrail").state,
            ComponentState.DISABLED_BY_POLICY,
        )


if __name__ == "__main__":
    unittest.main()
