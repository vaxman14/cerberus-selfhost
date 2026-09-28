import os
import base64
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from cerberus import api, backupctl, llm, local_auth, persistence, reporting, runner, tools_api, vault
from cerberus.cancellation import ScanCancelled
from cerberus.auth_gate import AuthorizationError, AuthorizationGate
from cerberus.heads import backend, nose
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
                bundle = persistence.get_scan_bundle(scan_id)
                self.assertEqual(bundle["scan_id"], scan_id)
                self.assertEqual(bundle["target"], "https://example.com")
                self.assertEqual(bundle["count"], 1)
                self.assertEqual(bundle["findings"][0]["title"], "Missing header")
                self.assertIsNone(bundle["analysis"])
                self.assertIsNone(persistence.get_scan_bundle("missing"))
                self.assertEqual(persistence.schema_version(), persistence.SCHEMA_VERSION)

    def test_backup_round_trip_and_key_proof(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source.db"
            destination = root / "restored.db"
            archive = root / "backup.tar.gz"
            key_file = root / "master_key"
            key_file.write_text(base64.b64encode(b"k" * 32).decode(), encoding="utf-8")
            key_file.chmod(0o600)
            with patch.dict(os.environ, {
                "CERBERUS_DB_PATH": str(source),
                "CERBERUS_MASTER_KEY_FILE": str(key_file),
                "SUPABASE_URL": "", "SUPABASE_SERVICE_KEY": "",
            }, clear=False):
                owner = local_auth.create_owner("owner", "a sufficiently long password")
                result = ScanResult(target="https://example.com", client=owner["username"])
                persistence.save(result, log="verified")
                with archive.open("wb") as output:
                    backupctl.export_archive(output)

            manifest = backupctl.verify_archive(archive)
            self.assertEqual(manifest["format"], "cerberus-backup-v1")
            backupctl.restore_archive(archive, destination)
            proof = backupctl.prove_database(destination, key_file)
            self.assertEqual(proof["users"], 1)
            self.assertEqual(proof["scans"], 1)
            self.assertEqual(proof["schema_version"], persistence.SCHEMA_VERSION)


class ActiveScanGateTests(unittest.TestCase):
    def test_only_one_scan_can_hold_the_shared_scanner_stack(self):
        with api.LOCK:
            old = dict(api.JOBS)
            api.JOBS.clear()
            api.JOBS["running-job"] = {"status": "running"}
            try:
                self.assertEqual(api._active_job_id(), "running-job")
                api.JOBS["running-job"]["status"] = "done"
                self.assertIsNone(api._active_job_id())
            finally:
                api.JOBS.clear()
                api.JOBS.update(old)

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

    def test_stopped_scan_does_not_run_or_persist(self):
        stopped = threading.Event()
        stopped.set()
        with self.assertRaises(ScanCancelled):
            runner.run_scan(
                "https://example.com", heads=("frontend",), cancel_event=stopped)


class ActiveToolResultTests(unittest.TestCase):
    def test_sqlmap_negative_sentence_is_not_a_vulnerability(self):
        completed = unittest.mock.MagicMock(
            returncode=0,
            stdout="all tested parameters do not appear to be injectable",
            stderr="",
        )
        with patch.object(tools_api, "_run", return_value=completed):
            self.assertFalse(tools_api.sqlmap("https://example.com")["vulnerable"])

    def test_sqlmap_requires_a_positive_injection_signature(self):
        completed = unittest.mock.MagicMock(
            returncode=0,
            stdout="sqlmap identified the following injection point\nType: boolean-based blind",
            stderr="",
        )
        with patch.object(tools_api, "_run", return_value=completed):
            self.assertTrue(tools_api.sqlmap("https://example.com")["vulnerable"])

    def test_duplicate_nuclei_findings_are_collapsed(self):
        item = {
            "title": "nuclei: Weak Cipher Suites Detection", "severity": "low",
            "detail": "weak cipher", "evidence": "example.com:443", "remediation": "",
        }
        with patch.object(backend.tool_client, "run", return_value={"findings": [item, item]}):
            self.assertEqual(len(backend._nuclei("https://example.com")), 1)

    def test_nuclei_failure_is_not_reported_as_a_vulnerability(self):
        with patch.object(
            backend.tool_client, "run",
            side_effect=backend.tool_client.ToolServiceError("timed out"),
        ):
            with self.assertRaisesRegex(RuntimeError, "did not complete"):
                backend._nuclei("https://example.com")

    def test_zap_duplicate_alerts_are_collapsed_with_affected_url_count(self):
        alerts = [
            {
                "alert": "CSP warning", "risk": "Medium", "description": "same",
                "solution": "fix it", "url": "https://example.com/one",
            },
            {
                "alert": "CSP warning", "risk": "Medium", "description": "same",
                "solution": "fix it", "url": "https://example.com/two",
            },
        ]

        payloads = iter([
            {"version": "test"}, {}, {}, {"scan": "1"}, {"status": "100"},
            {"scan": "2"}, {"status": "100"}, {"alerts": alerts},
        ])
        with patch("urllib.request.urlopen") as urlopen:
            urlopen.return_value.__enter__.return_value.read.side_effect = (
                lambda: __import__("json").dumps(next(payloads)).encode())
            findings = backend._zap("https://example.com")
        self.assertEqual(len(findings), 1)
        self.assertIn("+1 more URL", findings[0].evidence)


class PassiveMailPolicyTests(unittest.TestCase):
    def test_mail_policy_uses_registrable_domain_for_subdomain_target(self):
        self.assertEqual(nose._mail_domain("ce.heyjosi.com"), "heyjosi.com")
        self.assertEqual(nose._mail_domain("app.example.co.uk"), "example.co.uk")

    def test_spf_and_dmarc_queries_use_registrable_domain(self):
        with patch.object(nose, "_doh_txt", side_effect=[
            ["v=spf1 include:example.test ~all"], ["v=DMARC1; p=none"],
        ]) as lookup:
            findings = []
            nose._spf("ce.heyjosi.com", findings)
            nose._dmarc("ce.heyjosi.com", findings)
        self.assertEqual(findings, [])
        self.assertEqual(
            [call.args[0] for call in lookup.call_args_list],
            ["heyjosi.com", "_dmarc.heyjosi.com"],
        )


class ReportSupportLinkTests(unittest.TestCase):
    def test_client_report_includes_optional_support_link(self):
        report = reporting.render_client(
            ScanResult(target="https://example.com", client="selfhost"))
        self.assertIn("https://buymeacoffee.com/romanvaxman", report)
        self.assertIn("Print / Save as PDF", report)
        self.assertIn("window.print()", report)


class LocalAuthTests(unittest.TestCase):
    def test_first_owner_login_session_and_csrf(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {
            "CERBERUS_DB_PATH": str(Path(tmp) / "cerberus.db"),
            "SUPABASE_URL": "", "SUPABASE_SERVICE_KEY": "",
        }, clear=False):
            self.assertTrue(local_auth.setup_required())
            owner = local_auth.create_owner("owner", "a sufficiently long password")
            self.assertEqual(owner["role"], "owner")
            self.assertFalse(local_auth.setup_required())
            user, token, csrf = local_auth.login(
                "OWNER", "a sufficiently long password")
            authed, _ = local_auth.authenticate(
                f"{local_auth.COOKIE_NAME}={token}; {local_auth.CSRF_COOKIE_NAME}={csrf}")
            self.assertEqual(authed["id"], user["id"])
            self.assertTrue(local_auth.csrf_valid(authed, csrf))
            self.assertFalse(local_auth.csrf_valid(authed, "wrong"))

            local_auth.reset_password("owner", "a different long password")
            self.assertIsNone(local_auth.authenticate(
                f"{local_auth.COOKIE_NAME}={token}")[0])
            with self.assertRaises(local_auth.LocalAuthError):
                local_auth.login("owner", "a sufficiently long password")
            self.assertEqual(
                local_auth.login("owner", "a different long password")[0]["username"],
                "owner",
            )

    def test_second_owner_setup_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {
            "CERBERUS_DB_PATH": str(Path(tmp) / "cerberus.db"),
        }, clear=False):
            local_auth.create_owner("owner", "a sufficiently long password")
            with self.assertRaises(local_auth.LocalAuthError):
                local_auth.create_owner("other", "another sufficiently long password")


class CredentialVaultTests(unittest.TestCase):
    def _key_file(self, root: str, value: bytes) -> str:
        path = Path(root) / "master-key"
        path.write_text(base64.b64encode(value).decode(), encoding="utf-8")
        path.chmod(0o600)
        return str(path)

    def test_round_trip_is_authenticated_and_redacted(self):
        with tempfile.TemporaryDirectory() as tmp:
            key = vault.load_master_key(self._key_file(tmp, b"a" * 32))
            sealed = vault.seal(key, {"api_key": "fixture-secret"})
            self.assertTrue(vault.looks_sealed(sealed))
            self.assertNotIn("fixture-secret", sealed)
            self.assertEqual(vault.open_sealed(key, sealed)["api_key"], "fixture-secret")
            self.assertEqual(str(key), "[master key redacted]")
            with self.assertRaises(vault.VaultError):
                vault.open_sealed(vault.MasterKey(b"b" * 32), sealed)

    def test_environment_master_key_is_refused(self):
        with patch.dict(os.environ, {"CERBERUS_MASTER_KEY": "not-allowed"}, clear=False):
            with self.assertRaises(vault.VaultError):
                vault.load_master_key("/does/not/matter")



class LLMProfileTests(unittest.TestCase):
    def test_full_josi_picker_catalog_includes_api_and_subscription_paths(self):
        providers = {item["kind"]: item for item in llm.provider_catalog()}
        self.assertEqual(len(providers), 19)
        for required in (
            "openai_compatible", "openai", "anthropic", "xai", "gemini", "deepseek",
            "qwen", "mistral", "moonshot", "zhipu", "cohere", "openrouter", "minimax",
            "baidu", "hunyuan", "azure_openai", "aws_bedrock", "vertex_ai",
            "openai_subscription",
        ):
            self.assertIn(required, providers)
        self.assertEqual(providers["openai_subscription"]["wire"], "codex")
        self.assertNotIn("anthropic_subscription", providers)

    def test_gemini_discovery_uses_native_header_and_filters_non_generate_models(self):
        response = unittest.mock.MagicMock()
        response.ok = True
        response.status_code = 200
        response.json.return_value = {"models": [
            {"name": "models/gemini-test", "displayName": "Gemini Test",
             "supportedGenerationMethods": ["generateContent"]},
            {"name": "models/embed-test", "supportedGenerationMethods": ["embedContent"]},
        ]}
        with patch("socket.getaddrinfo", return_value=[(2, 1, 6, "", ("8.8.8.8", 443))]), patch(
            "requests.get", return_value=response
        ) as get:
            result = llm.discover_connection({
                "provider": "gemini", "api_key": "fixture", "external_acknowledged": True,
            })
        self.assertEqual(result["models"][0]["id"], "gemini-test")
        self.assertEqual(get.call_args.kwargs["headers"]["x-goog-api-key"], "fixture")
        self.assertNotIn("Authorization", get.call_args.kwargs["headers"])

    def test_subscription_profile_never_accepts_an_api_key(self):
        with patch.object(llm, "subscription_status", return_value={"signed_in": True}):
            with self.assertRaises(llm.LLMError) as raised:
                llm.save_profile({
                    "provider": "openai_subscription", "api_key": "must-not-be-used",
                    "external_acknowledged": True,
                })
        self.assertIn("do not accept API keys", str(raised.exception))

    def test_provider_key_is_ciphertext_only_and_api_is_masked(self):
        with tempfile.TemporaryDirectory() as tmp:
            key_path = CredentialVaultTests()._key_file(tmp, b"c" * 32)
            db_path = str(Path(tmp) / "cerberus.db")
            env = {
                "CERBERUS_DB_PATH": db_path,
                "CERBERUS_MASTER_KEY_FILE": key_path,
                "CERBERUS_MASTER_KEY": "",
                "CREDENTIALS_KEY": "",
            }
            with patch.dict(os.environ, env, clear=False), patch(
                "socket.getaddrinfo",
                return_value=[(2, 1, 6, "", ("127.0.0.1", 11434))],
            ):
                profile = llm.save_profile({
                    "provider": "openai_compatible",
                    "label": "Local model",
                    "model": "qwen-test",
                    "base_url": "http://model.internal:11434/v1",
                    "api_key": "fixture-provider-secret",
                    "external_acknowledged": False,
                })
            self.assertTrue(profile["has_api_key"])
            self.assertNotIn("api_key_enc", profile)
            self.assertNotIn("fixture-provider-secret", str(profile))
            with sqlite3.connect(db_path) as conn:
                stored = conn.execute(
                    "SELECT api_key_enc FROM llm_profiles WHERE id=?", (profile["id"],)
                ).fetchone()[0]
            self.assertTrue(vault.looks_sealed(stored))
            self.assertNotIn("fixture-provider-secret", stored)

    def test_hosted_provider_requires_external_acknowledgement(self):
        with tempfile.TemporaryDirectory() as tmp:
            key_path = CredentialVaultTests()._key_file(tmp, b"d" * 32)
            with patch.dict(os.environ, {
                "CERBERUS_DB_PATH": str(Path(tmp) / "cerberus.db"),
                "CERBERUS_MASTER_KEY_FILE": key_path,
                "CERBERUS_MASTER_KEY": "",
                "CREDENTIALS_KEY": "",
            }, clear=False), patch(
                "socket.getaddrinfo",
                return_value=[(2, 1, 6, "", ("8.8.8.8", 443))],
            ):
                with self.assertRaises(llm.LLMError) as raised:
                    llm.save_profile({
                        "provider": "openai", "model": "gpt-test",
                        "api_key": "fixture", "external_acknowledged": False,
                    })
            self.assertIn("acknowledge", str(raised.exception))

    def test_metadata_endpoint_is_refused_but_loopback_is_allowed(self):
        with patch("socket.getaddrinfo", return_value=[(2, 1, 6, "", ("169.254.169.254", 80))]):
            with self.assertRaises(llm.LLMError):
                llm.validate_endpoint("http://metadata.invalid")
        with patch("socket.getaddrinfo", return_value=[(2, 1, 6, "", ("127.0.0.1", 11434))]):
            self.assertTrue(llm.validate_endpoint("http://ollama.local:11434/v1")["local"])
        with patch("socket.getaddrinfo", return_value=[(10, 1, 6, "", ("::ffff:169.254.169.254", 80))]):
            with self.assertRaises(llm.LLMError):
                llm.validate_endpoint("http://mapped-metadata.invalid")

    def test_switching_provider_does_not_carry_the_old_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            key_path = CredentialVaultTests()._key_file(tmp, b"f" * 32)
            with patch.dict(os.environ, {
                "CERBERUS_DB_PATH": str(Path(tmp) / "cerberus.db"),
                "CERBERUS_MASTER_KEY_FILE": key_path,
                "CERBERUS_MASTER_KEY": "",
                "CREDENTIALS_KEY": "",
            }, clear=False), patch(
                "socket.getaddrinfo", return_value=[(2, 1, 6, "", ("8.8.8.8", 443))]
            ):
                profile = llm.save_profile({
                    "provider": "openai", "model": "first", "api_key": "first-key",
                    "external_acknowledged": True,
                })
                with self.assertRaises(llm.LLMError):
                    llm.save_profile({
                        "id": profile["id"], "provider": "xai", "model": "second",
                        "external_acknowledged": True,
                    })

    def test_bridge_token_is_random_scoped_hashed_and_expiring(self):
        with tempfile.TemporaryDirectory() as tmp:
            key_path = CredentialVaultTests()._key_file(tmp, b"e" * 32)
            with patch.dict(os.environ, {
                "CERBERUS_DB_PATH": str(Path(tmp) / "cerberus.db"),
                "CERBERUS_MASTER_KEY_FILE": key_path,
                "CERBERUS_MASTER_KEY": "",
                "CREDENTIALS_KEY": "",
            }, clear=False), patch(
                "socket.getaddrinfo",
                return_value=[(2, 1, 6, "", ("127.0.0.1", 11434))],
            ):
                profile = llm.save_profile({
                    "provider": "openai_compatible", "model": "local-test",
                    "base_url": "http://model.internal:11434/v1",
                })
                persistence.save_llm_probe(
                    profile["id"],
                    {"chat": True, "structured_output": True, "tool_calling": True},
                    [], active=True,
                )
                token = persistence.issue_llm_bridge_token(profile["id"])
                self.assertEqual(llm.authenticate_bridge(f"Bearer {token}"), profile["id"])
                self.assertIsNone(llm.authenticate_bridge("Bearer wrong"))
                with sqlite3.connect(os.environ["CERBERUS_DB_PATH"]) as conn:
                    stored = conn.execute("SELECT token_hash FROM llm_bridge_tokens").fetchone()[0]
                    conn.execute(
                        "UPDATE llm_bridge_tokens SET expires_at='2000-01-01T00:00:00+00:00'"
                    )
                    conn.commit()
                self.assertNotEqual(stored, token)
                self.assertIsNone(llm.authenticate_bridge(f"Bearer {token}"))

    def test_deleting_profile_removes_sealed_key_and_bridge_tokens(self):
        with tempfile.TemporaryDirectory() as tmp:
            key_path = CredentialVaultTests()._key_file(tmp, b"g" * 32)
            db_path = str(Path(tmp) / "cerberus.db")
            with patch.dict(os.environ, {
                "CERBERUS_DB_PATH": db_path,
                "CERBERUS_MASTER_KEY_FILE": key_path,
                "CERBERUS_MASTER_KEY": "",
                "CREDENTIALS_KEY": "",
            }, clear=False), patch(
                "socket.getaddrinfo",
                return_value=[(2, 1, 6, "", ("127.0.0.1", 11434))],
            ):
                profile = llm.save_profile({
                    "provider": "openai_compatible", "model": "local-test",
                    "base_url": "http://model.internal:11434/v1",
                    "api_key": "delete-me",
                })
                persistence.issue_llm_bridge_token(profile["id"])
                self.assertTrue(persistence.delete_llm_profile(profile["id"]))
                self.assertIsNone(persistence.get_llm_profile(profile["id"]))
                with sqlite3.connect(db_path) as conn:
                    self.assertEqual(
                        conn.execute("SELECT COUNT(*) FROM llm_bridge_tokens").fetchone()[0], 0
                    )
                self.assertFalse(persistence.delete_llm_profile(profile["id"]))

    def test_transient_discovery_returns_models_without_storing_the_key(self):
        response = unittest.mock.MagicMock()
        response.ok = True
        response.status_code = 200
        response.json.return_value = {
            "data": [{"id": "chat-model"}, {"id": "text-embedding-3-small"}]
        }
        with patch("socket.getaddrinfo", return_value=[(2, 1, 6, "", ("8.8.8.8", 443))]), patch(
            "requests.get", return_value=response
        ) as get:
            result = llm.discover_connection({
                "provider": "openai", "api_key": "transient-fixture",
                "external_acknowledged": True,
            })
        self.assertEqual(result["models"][0]["id"], "chat-model")
        self.assertTrue(result["models"][1]["likely_non_chat"])
        self.assertEqual(get.call_args.kwargs["headers"]["Authorization"], "Bearer transient-fixture")
        self.assertNotIn("transient-fixture", str(result))


if __name__ == "__main__":
    unittest.main()
