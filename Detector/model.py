from __future__ import annotations

from dataclasses import asdict, dataclass, field, fields
from typing import Any

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(frozen=True)
class Record:
    ts: float
    user: str
    method: str
    path: str
    status: int
    req_body: Any = None
    resp_body: Any = None
    latency_ms: float = 0.0
    # Optional extensions to the agreed contract. Confirm with the parser owner.
    src_ip: str = ""
    role: str = "user"  # from the JWT role claim; BFLA needs it

    @classmethod
    def from_dict(cls, data: dict) -> "Record":
        known = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in known})

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300
