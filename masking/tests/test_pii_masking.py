"""Unit and integration tests for the API-Sentinel PII masking module."""

from __future__ import annotations

import unittest

from masking.pii import MaskingConfig, PIIMasker
from masking.server import OWASP_CATALOG, TelemetryStore, create_app


class TestPIIMasker(unittest.TestCase):
    def setUp(self) -> None:
        self.masker = PIIMasker(MaskingConfig())

    def test_masks_finding_secrets_emails_cards_ssns_and_preserves_input(self) -> None:
        raw_finding = {
            "type": "BOLA",
            "owasp": "API1",
            "user": "attacker@crapi.local",
            "src_ip": "10.0.0.7",
            "endpoint": "GET /workshop/api/shop/orders/1002",
            "severity": "critical",
            "action": "block",
            "reason": "Accessed victim@crapi.local with Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyXzIifQ.sig12345",
            "ts": 1731312000.1,
            "evidence": {
                "email": "victim@crapi.local",
                "ssn": "123-45-6789",
                "credit_card": "4111-1111-1111-1111",
                "password": "SuperSecretPassword!",
                "phone": "+1-555-234-5678",
                "object_id": "1002",
            },
        }

        res = self.masker.mask_finding(raw_finding)
        masked = res.data

        # Never mutate caller's original dict
        self.assertEqual(raw_finding["evidence"]["password"], "SuperSecretPassword!")

        self.assertTrue(masked["pii_masked"])
        self.assertGreaterEqual(res.redactions, 6)
        self.assertEqual(masked["user"], "a***@crapi.local")
        self.assertEqual(masked["src_ip"], "10.0.0.7")
        self.assertIn("[REDACTED_JWT]", masked["reason"])
        self.assertIn("v***@crapi.local", masked["reason"])
        self.assertEqual(masked["evidence"]["email"], "v***@crapi.local")
        self.assertEqual(masked["evidence"]["ssn"], "[REDACTED_SSN]")
        self.assertEqual(masked["evidence"]["credit_card"], "****-****-****-1111")
        self.assertEqual(masked["evidence"]["password"], "[REDACTED_SECRET]")
        self.assertEqual(masked["evidence"]["phone"], "[REDACTED_PHONE]")
        self.assertEqual(masked["evidence"]["object_id"], "1002")

    def test_luhn_avoids_false_positive_on_numeric_order_ids(self) -> None:
        payload = {
            "order_id": "1000000000002",  # 13 digits, invalid Luhn
            "note": "Order 1000000000002 shipped to +1 415-555-0199",
        }
        res = self.masker.mask_any(payload)
        self.assertIn("1000000000002", res.data["note"])
        self.assertIn("[REDACTED_PHONE]", res.data["note"])

    def test_masks_record_bodies_and_inline_api_keys(self) -> None:
        record = {
            "ts": 1731312000.5,
            "user": "user_55",
            "method": "POST",
            "path": "/identity/api/auth/login",
            "status": 200,
            "req_body": {"email": "alice@corp.io", "password": "hunter2"},
            "resp_body": {
                "token": "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWxpY2UifQ.abc123def",
                "api_key": "sk_live_abcdefghijklmnop",
            },
            "latency_ms": 2.4,
            "src_ip": "10.0.0.5",
            "role": "user",
        }
        res = self.masker.mask_record(record)
        self.assertEqual(res.data["req_body"]["email"], "a***@corp.io")
        self.assertEqual(res.data["req_body"]["password"], "[REDACTED_SECRET]")
        self.assertEqual(res.data["resp_body"]["token"], "[REDACTED_SECRET]")
        self.assertEqual(res.data["resp_body"]["api_key"], "[REDACTED_SECRET]")


class TestTelemetryStoreAndRoutes(unittest.TestCase):
    def test_store_masks_findings_and_updates_inventory(self) -> None:
        store = TelemetryStore()
        masked = store.ingest_finding(
            {
                "type": "BOLA",
                "owasp": "API1",
                "user": "bob@example.com",
                "src_ip": "192.168.1.50",
                "endpoint": "GET /workshop/api/shop/orders/1005",
                "severity": "high",
                "action": "alert",
                "reason": "Enumeration on 1005",
                "evidence": {"email": "target@example.com", "token": "secret-jwt"},
            }
        )
        self.assertEqual(masked["user"], "b***@example.com")
        self.assertEqual(masked["evidence"]["email"], "t***@example.com")
        self.assertEqual(masked["evidence"]["token"], "[REDACTED_SECRET]")
        self.assertEqual(len(store.findings), 1)
        self.assertIn("GET /workshop/api/shop/orders/1005", store.inventory)
        self.assertEqual(len(OWASP_CATALOG), 10)

    def test_fastapi_app_routes_registered(self) -> None:
        app = create_app(seed=False)
        paths = {route.path for route in app.routes}
        for expected in (
            "/health",
            "/api/findings",
            "/api/ingest/finding",
            "/api/ingest/record",
            "/api/inventory",
            "/api/owasp",
            "/api/stats",
            "/api/mask/preview",
            "/ws/findings",
        ):
            self.assertIn(expected, paths)


if __name__ == "__main__":
    unittest.main()
