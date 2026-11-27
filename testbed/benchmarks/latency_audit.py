"""Latency & performance audit for the API-Sentinel testbed and PII masking pipeline.

Mid-Project Review SLA: added processing overhead must remain under 5.0 ms per request.
"""

from __future__ import annotations

import argparse
import json
import statistics
import time
from pathlib import Path
from typing import Any

from masking.pii import PIIMasker
from testbed.app.server import create_testbed_app


def _percentile(sorted_vals: list[float], pct: float) -> float:
    if not sorted_vals:
        return 0.0
    idx = min(len(sorted_vals) - 1, max(0, int(round((pct / 100.0) * (len(sorted_vals) - 1)))))
    return round(sorted_vals[idx], 4)


def run_latency_audit(iterations: int = 300, sla_ms: float = 5.0) -> dict[str, Any]:
    client = create_testbed_app().test_client()
    login_resp = client.post(
        "/identity/api/auth/login",
        json={"email": "alice@crapi.local", "password": "alice-password-123"},
    )
    token = login_resp.get_json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    masker = PIIMasker()

    baseline_ms: list[float] = []
    pipeline_overhead_ms: list[float] = []

    for i in range(iterations):
        order_id = 1001 + (i % 5)
        t0 = time.perf_counter()
        resp = client.get(f"/workshop/api/shop/orders/{order_id}", headers=headers)
        t1 = time.perf_counter()
        baseline_ms.append((t1 - t0) * 1000.0)

        payload = resp.get_json()
        p0 = time.perf_counter()
        rec = {
            "ts": time.time(),
            "user": "user_101",
            "method": "GET",
            "path": f"/workshop/api/shop/orders/{order_id}",
            "status": resp.status_code,
            "req_body": None,
            "resp_body": payload,
            "latency_ms": (t1 - t0) * 1000.0,
            "src_ip": "10.0.0.11",
            "role": "user",
        }
        masker.mask_record(rec)
        p1 = time.perf_counter()
        pipeline_overhead_ms.append((p1 - p0) * 1000.0)

    baseline_sorted = sorted(baseline_ms)
    overhead_sorted = sorted(pipeline_overhead_ms)
    p95_overhead = _percentile(overhead_sorted, 95)

    return {
        "iterations": iterations,
        "sla_ms": sla_ms,
        "sla_passed": p95_overhead < sla_ms,
        "baseline_ms": {
            "mean": round(statistics.mean(baseline_sorted), 4),
            "p50": _percentile(baseline_sorted, 50),
            "p95": _percentile(baseline_sorted, 95),
            "p99": _percentile(baseline_sorted, 99),
        },
        "masking_overhead_ms": {
            "mean": round(statistics.mean(overhead_sorted), 4),
            "p50": _percentile(overhead_sorted, 50),
            "p95": p95_overhead,
            "p99": _percentile(overhead_sorted, 99),
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run API-Sentinel <5ms latency audit.")
    parser.add_argument("--iterations", type=int, default=300)
    parser.add_argument("--out", default="testbed/data/latency_report.json")
    args = parser.parse_args()

    report = run_latency_audit(iterations=args.iterations)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
