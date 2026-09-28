import tempfile
import unittest
from pathlib import Path

from cerberus.models import Severity
from cerberus.revenue_abuse import RiskBand, RiskSignal, TrialRiskEngine, scan_repository


class TrialRiskEngineTests(unittest.TestCase):
    def test_ip_alone_never_denies(self):
        decision = TrialRiskEngine().decide([RiskSignal("ip_reuse", 100)])
        self.assertEqual(decision.band, RiskBand.LOW)
        self.assertEqual(decision.score, 15)

    def test_high_requires_independent_signals(self):
        decision = TrialRiskEngine().decide([
            RiskSignal("device_reuse", 50), RiskSignal("payment_reuse", 40)
        ])
        self.assertEqual(decision.band, RiskBand.HIGH)
        self.assertEqual(decision.action, "deny_trial_allow_purchase")

    def test_medium_steps_up(self):
        decision = TrialRiskEngine().decide([RiskSignal("device_reuse", 40)])
        self.assertEqual(decision.band, RiskBand.MEDIUM)
        self.assertEqual(decision.action, "step_up_verification")


class RepositoryScannerTests(unittest.TestCase):
    def test_account_only_trial_is_high(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "api.ts").write_text(
                "server.post('/trial', async user_id => trial_usage(user_id));"
            )
            findings = scan_repository(tmp)
        self.assertTrue(any(f.severity is Severity.HIGH and "Fresh accounts" in f.title
                            for f in findings))

    def test_no_trial_is_info(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "app.ts").write_text("export const hello = 'world';")
            findings = scan_repository(tmp)
        self.assertEqual(findings[0].severity, Severity.INFO)


if __name__ == "__main__":
    unittest.main()
