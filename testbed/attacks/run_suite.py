"""End-to-end testbed simulation: generates normal + attack traffic and masked findings."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import yaml

from masking.pii import PIIMasker

from .bfla_and_shadow import run_bfla_shadow_and_rate_attacks
from .bola_enum import run_bola_enumeration
from .common import TrafficSession


def _load_openapi_paths(spec_path: Path) -> set[str]:
    if not spec_path.exists():
        return set()
    data = yaml.safe_load(spec_path.read_text(encoding="utf-8")) or {}
    return set((data.get("paths") or {}).keys())


def _normalize_path(path: str) -> str:
    base = path.split("?", 1)[0]
    out = []
    for seg in base.split("/"):
        if seg.isdigit():
            out.append("{id}")
        else:
            out.append(seg)
    return "/".join(out) or "/"


def _build_inventory(
    records: list[dict[str, Any]], findings: list[dict[str, Any]], spec_paths: set[str]
) -> list[dict[str, Any]]:
    # Match parameterized OpenAPI keys cleanly regardless of parameter name
    normalized_spec = {_normalize_path(p.replace("{vehicle_id}", "1").replace("{order_id}", "1").replace("{product_id}", "1").replace("{post_id}", "1")) for p in spec_paths}

    by_ep: dict[str, dict[str, Any]] = {}
    for rec in records:
        norm = _normalize_path(rec["path"])
        key = f"{rec['method']} {norm}"
        entry = by_ep.setdefault(
            key,
            {
                "endpoint": norm,
                "method": rec["method"],
                "status": "documented" if norm in normalized_spec else "shadow",
                "hits": 0,
                "avg_latency_ms": 0.0,
                "owasp_tags": [],
                "last_seen": rec["ts"],
            },
        )
        prev = entry["hits"]
        entry["hits"] = prev + 1
        entry["avg_latency_ms"] = round(
            ((entry["avg_latency_ms"] * prev) + float(rec.get("latency_ms", 0.0))) / entry["hits"], 2
        )
        entry["last_seen"] = max(entry["last_seen"], rec["ts"])

    for f in findings:
        ep = f.get("endpoint", "")
        parts = ep.split(" ", 1)
        if len(parts) == 2:
            norm = _normalize_path(parts[1])
            key = f"{parts[0]} {norm}"
            if key in by_ep:
                if f["owasp"] not in by_ep[key]["owasp_tags"]:
                    by_ep[key]["owasp_tags"].append(f["owasp"])
                if f["type"] == "ZOMBIE_API":
                    by_ep[key]["status"] = "zombie"
                elif f["type"] == "SHADOW_API":
                    by_ep[key]["status"] = "shadow"

    return sorted(by_ep.values(), key=lambda x: x["hits"], reverse=True)


def run_all(base_url: str | None = None, out_dir: str | Path = "testbed/data") -> dict[str, Any]:
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    session = TrafficSession(base_url=base_url)

    # Normal baseline traffic
    alice = session.login("alice@crapi.local", "alice-password-123", src_ip="10.0.0.11")
    session.call("GET", "/workshop/api/shop/products", user=alice, src_ip="10.0.0.11", label="benign")
    session.call("GET", "/workshop/api/shop/products/1", user=alice, src_ip="10.0.0.11", label="benign")
    session.call("GET", "/identity/api/v2/user/dashboard", user=alice, src_ip="10.0.0.11", label="benign")
    session.call("GET", "/identity/api/v2/vehicle/2001/location", user=alice, src_ip="10.0.0.11", label="benign")
    session.call("GET", "/community/api/v2/posts/3001", user=alice, src_ip="10.0.0.11", label="benign")

    admin = session.login("secops@crapi.local", "admin-super-secret", src_ip="10.0.0.5")
    session.call("GET", "/identity/api/v2/admin/videos", user=admin, role="admin", src_ip="10.0.0.5", label="benign")

    # Attack traffic
    bola_findings = run_bola_enumeration(session)
    other_findings = run_bfla_shadow_and_rate_attacks(session)
    raw_findings = bola_findings + other_findings

    # Mask all records & findings through Meet's PII masker before persisting
    masker = PIIMasker()
    masked_records, rec_redactions = masker.mask_batch(session.records, kind="record")
    masked_findings, finding_redactions = masker.mask_batch(raw_findings, kind="finding")

    spec_paths = _load_openapi_paths(Path(__file__).resolve().parent.parent / "openapi.yaml")
    inventory = _build_inventory(masked_records, masked_findings, spec_paths)

    records_file = out_path / "traffic_records.jsonl"
    findings_file = out_path / "sample_findings.jsonl"
    inventory_file = out_path / "sample_inventory.json"

    with records_file.open("w", encoding="utf-8") as fh:
        for row in masked_records:
            fh.write(json.dumps(row) + "\n")

    with findings_file.open("w", encoding="utf-8") as fh:
        for row in masked_findings:
            fh.write(json.dumps(row) + "\n")

    inventory_file.write_text(json.dumps(inventory, indent=2), encoding="utf-8")

    return {
        "requests": len(masked_records),
        "findings": len(masked_findings),
        "endpoints": len(inventory),
        "record_pii_redactions": rec_redactions,
        "finding_pii_redactions": finding_redactions,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run full crAPI testbed suite and emit masked telemetry.")
    parser.add_argument("--base-url", default=None)
    parser.add_argument("--out-dir", default="testbed/data")
    args = parser.parse_args()
    summary = run_all(base_url=args.base_url, out_dir=args.out_dir)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
