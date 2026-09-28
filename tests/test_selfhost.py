import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cerberus import persistence, reporting
from cerberus.auth_gate import AuthorizationError, AuthorizationGate
from cerberus.models import AuthRecord, Finding, Head, ScanResult, Severity


class SQLitePersistenceTests(unittest.TestCase):
    def test_round_trip_without_hosted_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = str(Path(tmp) / "cerberus.db")
            env = {
                "CERBERUS_DB_PATH": db_path,
                "SUPABASE_URL": "",
                "SUPABASE_SERVICE_KEY": "",
            }
            with patch.dict(os.environ, env, clear=False):
                result = ScanResult(
                    target="https://example.com",
                    client="selfhost",
                    findings=[
                        Finding(
                            Head.FRONTEND,
                            "Missing header",
                            Severity.LOW,
                            "A header is missing.",
                            remediation="Add it.",
                        )
                    ],
                    heads_run=["frontend"],
                )
                scan_id = persistence.save(result, log="done")

                self.assertIsNotNone(scan_id)
                self.assertEqual(persistence.get_scan(scan_id)["target"],
                                 "https://example.com")
                self.assertEqual(persistence.list_scans()[0]["id"], scan_id)
                self.assertEqual(persistence.get_findings(scan_id)[0]["severity"], "low")


class ActiveScanGateTests(unittest.TestCase):
    def test_unverified_authorization_is_blocked_by_default(self):
        auth = AuthRecord(
            client="selfhost",
            scope_hosts=["example.com"],
            signed_authorization_ref="unverified-reference",
        )
        with patch.dict(os.environ, {
            "SIGNWELL_API_KEY": "",
            "CERBERUS_ALLOW_UNVERIFIED_AUTH": "",
        }, clear=False):
            with self.assertRaises(AuthorizationError):
                AuthorizationGate(auth).authorize(Head.BACKEND)


class ReportSupportLinkTests(unittest.TestCase):
    def test_client_report_includes_optional_support_link(self):
        report = reporting.render_client(
            ScanResult(target="https://example.com", client="selfhost"))
        self.assertIn("https://buymeacoffee.com/romanvaxman", report)


if __name__ == "__main__":
    unittest.main()
