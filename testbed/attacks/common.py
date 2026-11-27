"""Shared HTTP traffic runner producing Parser/Detector-compatible Record JSONL."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import httpx

from testbed.app.server import create_testbed_app


class TrafficSession:
    """Executes HTTP calls against either a live URL or in-process Flask crAPI testbed."""

    def __init__(self, base_url: str | None = None) -> None:
        self.base_url = base_url
        if base_url:
            self._http_client = httpx.Client(base_url=base_url, timeout=5.0)
            self._flask_client = None
        else:
            self._http_client = None
            self._flask_client = create_testbed_app().test_client()
        self.records: list[dict[str, Any]] = []
        self._tokens: dict[str, tuple[str, str]] = {}

    def login(self, email: str, password: str, src_ip: str = "10.0.0.10") -> str:
        rec = self.call(
            "POST",
            "/identity/api/auth/login",
            user=email,
            role="user",
            src_ip=src_ip,
            json_body={"email": email, "password": password},
            label="benign",
        )
        body = rec["resp_body"] or {}
        token = body.get("token", "")
        user_id = body.get("user", email)
        role = body.get("role", "user")
        self._tokens[user_id] = (token, role)
        return str(user_id)

    def call(
        self,
        method: str,
        path: str,
        *,
        user: str = "anonymous",
        role: str | None = None,
        src_ip: str = "10.0.0.10",
        json_body: dict[str, Any] | None = None,
        label: str = "benign",
    ) -> dict[str, Any]:
        headers: dict[str, str] = {}
        resolved_role = role or "user"
        if user in self._tokens:
            token, token_role = self._tokens[user]
            headers["Authorization"] = f"Bearer {token}"
            if role is None:
                resolved_role = token_role

        t0 = time.perf_counter()
        if self._http_client is not None:
            resp = self._http_client.request(method, path, json=json_body, headers=headers)
            status = resp.status_code
            try:
                resp_body: Any = resp.json()
            except Exception:
                resp_body = resp.text
        else:
            assert self._flask_client is not None
            resp = self._flask_client.open(path, method=method, json=json_body, headers=headers)
            status = resp.status_code
            resp_body = resp.get_json(silent=True)
            if resp_body is None:
                resp_body = resp.get_data(as_text=True)
        latency_ms = round((time.perf_counter() - t0) * 1000.0, 3)

        record = {
            "ts": round(time.time(), 4),
            "user": user,
            "method": method.upper(),
            "path": path,
            "status": status,
            "req_body": json_body,
            "resp_body": resp_body,
            "latency_ms": latency_ms,
            "src_ip": src_ip,
            "role": resolved_role,
            "label": label,
        }
        self.records.append(record)
        return record

    def dump_jsonl(self, path: str | Path) -> None:
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("w", encoding="utf-8") as fh:
            for row in self.records:
                fh.write(json.dumps(row) + "\n")
