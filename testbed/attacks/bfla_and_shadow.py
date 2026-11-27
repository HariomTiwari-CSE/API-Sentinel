"""Scripted BFLA, Shadow/Zombie API, and Rate-Limit attack simulations."""

from __future__ import annotations

from typing import Any

from .common import TrafficSession


def run_bfla_shadow_and_rate_attacks(
    session: TrafficSession, attacker_ip: str = "10.0.0.88"
) -> list[dict[str, Any]]:
    """Probe privileged endpoints, undocumented routes, and unthrottled coupon endpoints."""
    attacker = session.login("carol@crapi.local", "carol-password-789", src_ip=attacker_ip)
    findings: list[dict[str, Any]] = []

    # 1. BFLA (OWASP API5): regular user calling admin endpoints
    for admin_path in ("/identity/api/v2/admin/users", "/identity/api/v2/admin/videos"):
        rec = session.call("GET", admin_path, user=attacker, src_ip=attacker_ip, label="attack_bfla")
        if rec["status"] == 200:
            findings.append(
                {
                    "type": "BFLA",
                    "owasp": "API5",
                    "user": attacker,
                    "src_ip": attacker_ip,
                    "endpoint": f"GET {admin_path}",
                    "severity": "critical" if "users" in admin_path else "high",
                    "action": "block",
                    "reason": f"Non-admin role='user' accessed privileged route {admin_path}",
                    "ts": rec["ts"],
                    "evidence": {
                        "role": "user",
                        "status": rec["status"],
                        "sample_response": rec["resp_body"],
                    },
                }
            )

    # 2. Shadow API (OWASP API9): undocumented debug endpoint
    shadow_rec = session.call(
        "GET", "/api/v1/debug/users", user=attacker, src_ip=attacker_ip, label="attack_shadow"
    )
    if shadow_rec["status"] == 200:
        findings.append(
            {
                "type": "SHADOW_API",
                "owasp": "API9",
                "user": attacker,
                "src_ip": attacker_ip,
                "endpoint": "GET /api/v1/debug/users",
                "severity": "critical",
                "action": "alert",
                "reason": "Undocumented endpoint absent from openapi.yaml leaked user directory",
                "ts": shadow_rec["ts"],
                "evidence": {
                    "in_openapi_spec": False,
                    "status": shadow_rec["status"],
                    "sample_response": shadow_rec["resp_body"],
                },
            }
        )

    # 3. Zombie API (OWASP API9): deprecated v1 export endpoint still serving traffic
    zombie_rec = session.call(
        "GET", "/api/v1/orders/export-legacy", user=attacker, src_ip=attacker_ip, label="attack_zombie"
    )
    if zombie_rec["status"] == 200:
        findings.append(
            {
                "type": "ZOMBIE_API",
                "owasp": "API9",
                "user": attacker,
                "src_ip": attacker_ip,
                "endpoint": "GET /api/v1/orders/export-legacy",
                "severity": "high",
                "action": "alert",
                "reason": "Deprecated v1 export API still active outside OpenAPI specification",
                "ts": zombie_rec["ts"],
                "evidence": {
                    "in_openapi_spec": False,
                    "deprecated": True,
                    "status": zombie_rec["status"],
                },
            }
        )

    # 4. Unrestricted Resource Consumption (OWASP API4): rapid coupon brute-force
    burst_codes = [f"GUESS{i:03d}" for i in range(12)] + ["SENTINEL20"]
    last_rec = None
    for code in burst_codes:
        last_rec = session.call(
            "POST",
            "/workshop/api/shop/coupons/validate",
            user=attacker,
            src_ip=attacker_ip,
            json_body={"code": code},
            label="attack_ratelimit",
        )
    if last_rec is not None:
        findings.append(
            {
                "type": "RATE_LIMIT",
                "owasp": "API4",
                "user": attacker,
                "src_ip": attacker_ip,
                "endpoint": "POST /workshop/api/shop/coupons/validate",
                "severity": "medium",
                "action": "block",
                "reason": f"Automated burst ({len(burst_codes)} requests) with no rate limiting",
                "ts": last_rec["ts"],
                "evidence": {
                    "requests_in_burst": len(burst_codes),
                    "last_status": last_rec["status"],
                    "matched_coupon": "SENTINEL20",
                },
            }
        )

    return findings
