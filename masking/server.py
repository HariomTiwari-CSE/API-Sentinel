"""FastAPI telemetry & PII-masking gateway serving the API-Sentinel React dashboard.

Run with:
    uvicorn masking.server:app --host 0.0.0.0 --port 8000
"""

from __future__ import annotations

import json
import time
from collections import Counter
from pathlib import Path
from typing import Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from .pii import MaskingConfig, PIIMasker

OWASP_CATALOG: list[dict[str, str]] = [
    {
        "id": "API1",
        "code": "API1:2023",
        "name": "Broken Object Level Authorization (BOLA)",
        "description": "Endpoints expose object IDs without validating that the caller owns the requested resource.",
    },
    {
        "id": "API2",
        "code": "API2:2023",
        "name": "Broken Authentication",
        "description": "Weak token validation, credential stuffing exposure, or missing session safeguards.",
    },
    {
        "id": "API3",
        "code": "API3:2023",
        "name": "Broken Object Property Level Authorization",
        "description": "Excessive data exposure or mass-assignment on sensitive object properties.",
    },
    {
        "id": "API4",
        "code": "API4:2023",
        "name": "Unrestricted Resource Consumption",
        "description": "Missing rate limits, pagination caps, or bot throttling allowing abuse.",
    },
    {
        "id": "API5",
        "code": "API5:2023",
        "name": "Broken Function Level Authorization (BFLA)",
        "description": "Regular users invoke administrative or internal functions due to missing role checks.",
    },
    {
        "id": "API6",
        "code": "API6:2023",
        "name": "Unrestricted Access to Sensitive Business Flows",
        "description": "Automated abuse of checkout, coupon redemption, or account creation workflows.",
    },
    {
        "id": "API7",
        "code": "API7:2023",
        "name": "Server Side Request Forgery (SSRF)",
        "description": "API fetches user-supplied remote URLs without allowlist validation.",
    },
    {
        "id": "API8",
        "code": "API8:2023",
        "name": "Security Misconfiguration",
        "description": "Verbose stack traces, permissive CORS, or unhardened headers.",
    },
    {
        "id": "API9",
        "code": "API9:2023",
        "name": "Improper Inventory Management",
        "description": "Undocumented Shadow APIs or deprecated Zombie APIs left exposed in production.",
    },
    {
        "id": "API10",
        "code": "API10:2023",
        "name": "Unsafe Consumption of APIs",
        "description": "Blindly trusting third-party API payloads without validation or sanitization.",
    },
]

_DEFAULT_SEED_DIR = Path(__file__).resolve().parent.parent / "testbed" / "data"


class FindingIn(BaseModel):
    type: str
    owasp: str
    user: str
    src_ip: str = ""
    endpoint: str
    severity: str = "medium"
    action: str = "alert"
    reason: str = ""
    ts: float = Field(default_factory=time.time)
    evidence: dict[str, Any] = Field(default_factory=dict)


class RecordIn(BaseModel):
    ts: float = Field(default_factory=time.time)
    user: str
    method: str
    path: str
    status: int
    req_body: Any = None
    resp_body: Any = None
    latency_ms: float = 0.0
    src_ip: str = ""
    role: str = "user"


class MaskPreviewIn(BaseModel):
    payload: Any


class EndpointEntry(BaseModel):
    endpoint: str
    method: str
    status: str = "documented"  # documented | shadow | zombie
    hits: int = 1
    avg_latency_ms: float = 0.0
    owasp_tags: list[str] = Field(default_factory=list)
    last_seen: float = Field(default_factory=time.time)


class TelemetryStore:
    """In-memory masked store for findings, endpoint inventory, and PII stats."""

    def __init__(self, masker: PIIMasker | None = None) -> None:
        self.masker = masker or PIIMasker(MaskingConfig())
        self.findings: list[dict[str, Any]] = []
        self.records: list[dict[str, Any]] = []
        self.inventory: dict[str, dict[str, Any]] = {}
        self.redaction_totals: Counter[str] = Counter()
        self.clients: list[WebSocket] = []

    def ingest_finding(self, raw: dict[str, Any]) -> dict[str, Any]:
        result = self.masker.mask_finding(raw)
        masked = result.data
        self.findings.insert(0, masked)
        self.findings = self.findings[:1000]
        for cat, count in result.categories.items():
            self.redaction_totals[cat] += count

        ep_key = masked.get("endpoint", "")
        if ep_key:
            parts = ep_key.split(" ", 1)
            method, path = (parts[0], parts[1]) if len(parts) == 2 else ("GET", ep_key)
            entry = self.inventory.setdefault(
                ep_key,
                {
                    "endpoint": path,
                    "method": method,
                    "status": self._classify_from_finding(masked),
                    "hits": 0,
                    "avg_latency_ms": 0.0,
                    "owasp_tags": [],
                    "last_seen": masked.get("ts", time.time()),
                },
            )
            entry["hits"] += 1
            entry["last_seen"] = max(entry["last_seen"], masked.get("ts", time.time()))
            if masked.get("owasp") and masked["owasp"] not in entry["owasp_tags"]:
                entry["owasp_tags"].append(masked["owasp"])
            if masked.get("type") == "SHADOW_API":
                entry["status"] = "shadow"
            elif masked.get("type") == "ZOMBIE_API":
                entry["status"] = "zombie"
        return masked

    def ingest_record(self, raw: dict[str, Any]) -> dict[str, Any]:
        result = self.masker.mask_record(raw)
        masked = result.data
        self.records.insert(0, masked)
        self.records = self.records[:1000]
        for cat, count in result.categories.items():
            self.redaction_totals[cat] += count

        ep_key = f"{masked.get('method', 'GET')} {self._normalize_path(masked.get('path', '/'))}"
        entry = self.inventory.setdefault(
            ep_key,
            {
                "endpoint": self._normalize_path(masked.get("path", "/")),
                "method": masked.get("method", "GET"),
                "status": "documented",
                "hits": 0,
                "avg_latency_ms": 0.0,
                "owasp_tags": [],
                "last_seen": masked.get("ts", time.time()),
            },
        )
        prev_hits = entry["hits"]
        new_hits = prev_hits + 1
        entry["avg_latency_ms"] = round(
            ((entry["avg_latency_ms"] * prev_hits) + float(masked.get("latency_ms", 0.0))) / new_hits,
            2,
        )
        entry["hits"] = new_hits
        entry["last_seen"] = max(entry["last_seen"], masked.get("ts", time.time()))
        return masked

    def load_seed_dir(self, directory: Path | None = None) -> None:
        target = directory or _DEFAULT_SEED_DIR
        findings_file = target / "sample_findings.jsonl"
        inventory_file = target / "sample_inventory.json"
        if inventory_file.exists():
            for item in json.loads(inventory_file.read_text(encoding="utf-8")):
                key = f"{item['method']} {item['endpoint']}"
                self.inventory[key] = item
        if findings_file.exists():
            for line in findings_file.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line:
                    self.ingest_finding(json.loads(line))

    @staticmethod
    def _classify_from_finding(finding: dict[str, Any]) -> str:
        ftype = finding.get("type", "").upper()
        if ftype == "SHADOW_API":
            return "shadow"
        if ftype == "ZOMBIE_API":
            return "zombie"
        return "documented"

    @staticmethod
    def _normalize_path(path: str) -> str:
        base = path.split("?", 1)[0]
        segments = []
        for seg in base.split("/"):
            if seg.isdigit():
                segments.append("{id}")
            elif len(seg) >= 32 and "-" in seg:
                segments.append("{uuid}")
            else:
                segments.append(seg)
        return "/".join(segments) or "/"


def create_app(seed: bool = True) -> FastAPI:
    app = FastAPI(title="API-Sentinel Masking & Telemetry API", version="1.0.0")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    store = TelemetryStore()
    if seed:
        store.load_seed_dir()
    app.state.store = store

    async def _broadcast(event: dict[str, Any]) -> None:
        dead: list[WebSocket] = []
        for ws in store.clients:
            try:
                await ws.send_json(event)
            except Exception:
                dead.append(ws)
        for ws in dead:
            if ws in store.clients:
                store.clients.remove(ws)

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "findings_count": len(store.findings),
            "inventory_count": len(store.inventory),
            "redactions_total": sum(store.redaction_totals.values()),
        }

    @app.get("/api/findings")
    def list_findings(
        owasp: str | None = None,
        severity: str | None = None,
        action: str | None = None,
    ) -> dict[str, Any]:
        items = store.findings
        if owasp:
            items = [f for f in items if f.get("owasp", "").upper() == owasp.upper()]
        if severity:
            items = [f for f in items if f.get("severity", "").lower() == severity.lower()]
        if action:
            items = [f for f in items if f.get("action", "").lower() == action.lower()]
        return {"findings": items, "total": len(items)}

    @app.post("/api/ingest/finding")
    async def ingest_finding(finding: FindingIn) -> dict[str, Any]:
        masked = store.ingest_finding(finding.model_dump())
        await _broadcast({"event": "finding", "data": masked})
        return {"status": "masked_and_stored", "finding": masked}

    @app.post("/api/ingest/record")
    async def ingest_record(record: RecordIn) -> dict[str, Any]:
        masked = store.ingest_record(record.model_dump())
        return {"status": "masked_and_stored", "record": masked}

    @app.get("/api/records")
    def list_records(limit: int = 50) -> dict[str, Any]:
        return {"records": store.records[:limit], "total": len(store.records)}

    @app.get("/api/inventory")
    def list_inventory() -> dict[str, Any]:
        items = sorted(store.inventory.values(), key=lambda x: x.get("hits", 0), reverse=True)
        return {"endpoints": items, "total": len(items)}

    @app.get("/api/owasp")
    def owasp_summary() -> dict[str, Any]:
        by_cat: dict[str, list[dict[str, Any]]] = {c["id"]: [] for c in OWASP_CATALOG}
        for f in store.findings:
            cat = f.get("owasp", "").upper()
            if cat in by_cat:
                by_cat[cat].append(f)
        summary = []
        for cat in OWASP_CATALOG:
            matches = by_cat[cat["id"]]
            sev_counts = Counter(m.get("severity", "low") for m in matches)
            summary.append(
                {
                    **cat,
                    "count": len(matches),
                    "blocked": sum(1 for m in matches if m.get("action") == "block"),
                    "severities": dict(sev_counts),
                    "endpoints": sorted({m.get("endpoint", "") for m in matches}),
                }
            )
        return {"categories": summary}

    @app.get("/api/stats")
    def stats() -> dict[str, Any]:
        sev = Counter(f.get("severity", "low") for f in store.findings)
        types = Counter(f.get("type", "UNKNOWN") for f in store.findings)
        inv_status = Counter(e.get("status", "documented") for e in store.inventory.values())
        return {
            "findings_total": len(store.findings),
            "blocked_total": sum(1 for f in store.findings if f.get("action") == "block"),
            "severity_breakdown": dict(sev),
            "type_breakdown": dict(types),
            "inventory_breakdown": dict(inv_status),
            "pii_redactions_total": sum(store.redaction_totals.values()),
            "pii_categories": dict(store.redaction_totals),
        }

    @app.post("/api/mask/preview")
    def mask_preview(body: MaskPreviewIn) -> dict[str, Any]:
        return store.masker.mask_any(body.payload).to_dict()

    @app.websocket("/ws/findings")
    async def ws_findings(websocket: WebSocket) -> None:
        await websocket.accept()
        store.clients.append(websocket)
        try:
            await websocket.send_json({"event": "snapshot", "data": store.findings[:100]})
            while True:
                await websocket.receive_text()
        except WebSocketDisconnect:
            if websocket in store.clients:
                store.clients.remove(websocket)

    return app


app = create_app()
