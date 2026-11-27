"""Tests for crAPI-compatible testbed, OpenAPI spec, attack scripts, and benchmarks."""

from __future__ import annotations

import unittest
from pathlib import Path

import yaml

from masking.pii import PIIMasker
from testbed.app.server import create_testbed_app
from testbed.attacks.bfla_and_shadow import run_bfla_shadow_and_rate_attacks
from testbed.attacks.bola_enum import run_bola_enumeration
from testbed.attacks.common import TrafficSession
from testbed.benchmarks.latency_audit import run_latency_audit


class TestCrapiTestbed(unittest.TestCase):
    def setUp(self) -> None:
        self.client = create_testbed_app().test_client()

    def test_openapi_omits_shadow_and_zombie_routes(self) -> None:
        spec_path = Path(__file__).resolve().parent.parent / "openapi.yaml"
        spec = yaml.safe_load(spec_path.read_text(encoding="utf-8"))
        paths = spec["paths"]
        self.assertIn("/workshop/api/shop/orders/{order_id}", paths)
        self.assertNotIn("/api/v1/debug/users", paths)
        self.assertNotIn("/api/v1/orders/export-legacy", paths)

    def test_intentional_bola_and_bfla_vulnerabilities_respond(self) -> None:
        login = self.client.post(
            "/identity/api/auth/login",
            json={"email": "alice@crapi.local", "password": "alice-password-123"},
        )
        self.assertEqual(login.status_code, 200)
        token = login.get_json()["token"]
        headers = {"Authorization": f"Bearer {token}"}

        # BOLA: Alice reads Bob's order 1002
        order = self.client.get("/workshop/api/shop/orders/1002", headers=headers)
        self.assertEqual(order.status_code, 200)
        self.assertEqual(order.get_json()["owner"], "user_102")

        # BFLA: regular user reads admin users directory
        admin_users = self.client.get("/identity/api/v2/admin/users", headers=headers)
        self.assertEqual(admin_users.status_code, 200)
        self.assertGreaterEqual(len(admin_users.get_json()["users"]), 3)

    def test_attack_scripts_and_masking_pipeline(self) -> None:
        session = TrafficSession()
        bola_findings = run_bola_enumeration(session)
        other_findings = run_bfla_shadow_and_rate_attacks(session)
        all_findings = bola_findings + other_findings

        types = {f["type"] for f in all_findings}
        self.assertIn("BOLA", types)
        self.assertIn("BFLA", types)
        self.assertIn("SHADOW_API", types)
        self.assertIn("ZOMBIE_API", types)
        self.assertIn("RATE_LIMIT", types)

        masker = PIIMasker()
        masked, totals = masker.mask_batch(all_findings, kind="finding")
        self.assertGreater(sum(totals.values()), 0)
        for f in masked:
            self.assertTrue(f["pii_masked"])
            self.assertNotIn("4111-1111-1111-1111", str(f))
            self.assertNotIn("alice-password-123", str(f))

    def test_latency_audit_under_5ms_sla(self) -> None:
        report = run_latency_audit(iterations=100, sla_ms=5.0)
        self.assertTrue(report["sla_passed"], f"Latency SLA exceeded: {report}")


if __name__ == "__main__":
    unittest.main()
