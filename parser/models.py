"""Data models and contract specifications for the API-Sentinel HTTP Parser module."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field, fields
from enum import Enum
from typing import Any, Optional


class TrafficDirection(str, Enum):
    """Direction of traffic relative to the monitored service."""

    INGRESS = "ingress"   # Client -> Service (Request)
    EGRESS = "egress"     # Service -> Client (Response)

    @classmethod
    def from_str(cls, value: str) -> "TrafficDirection":
        """Normalize various directional string indicators."""
        v = value.strip().lower()
        if v in ("ingress", "request", "req", "in", "incoming", "0"):
            return cls.INGRESS
        elif v in ("egress", "response", "resp", "out", "outgoing", "1"):
            return cls.EGRESS
        raise ValueError(f"Unknown traffic direction: {value}")


@dataclass(frozen=True)
class ConnectionKey:
    """Represents a 4-tuple identifying a network connection."""

    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str = "tcp"

    @property
    def connection_id(self) -> str:
        """Normalized string representation of the connection."""
        return f"{self.src_ip}:{self.src_port}->{self.dst_ip}:{self.dst_port}"

    @property
    def reverse_id(self) -> str:
        """Reverse 4-tuple for matching the return direction."""
        return f"{self.dst_ip}:{self.dst_port}->{self.src_ip}:{self.src_port}"

    @property
    def bidirectional_id(self) -> str:
        """Canonical identifier that is invariant to direction."""
        endpoint_a = (self.src_ip, self.src_port)
        endpoint_b = (self.dst_ip, self.dst_port)
        if endpoint_a <= endpoint_b:
            return f"{self.src_ip}:{self.src_port}<->{self.dst_ip}:{self.dst_port}"
        return f"{self.dst_ip}:{self.dst_port}<->{self.src_ip}:{self.src_port}"


@dataclass(frozen=True)
class RawFragment:
    """Represents a raw payload fragment captured from the socket ring buffer by the Rust agent."""

    connection_id: str
    ts: float
    direction: TrafficDirection
    payload: bytes

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RawFragment":
        direction_val = data["direction"]
        direction = (
            direction_val
            if isinstance(direction_val, TrafficDirection)
            else TrafficDirection.from_str(str(direction_val))
        )
        payload = data["payload"]
        if isinstance(payload, str):
            payload = payload.encode("utf-8", errors="replace")
        return cls(
            connection_id=str(data["connection_id"]),
            ts=float(data["ts"]),
            direction=direction,
            payload=payload,
        )


@dataclass
class ParsedHTTPRequest:
    """Intermediate representation of an assembled HTTP Request."""

    method: str
    path: str
    http_version: str = "HTTP/1.1"
    headers: dict[str, str] = field(default_factory=dict)
    body: Any = None
    ts: float = 0.0
    src_ip: str = ""
    src_port: int = 0
    dst_ip: str = ""
    dst_port: int = 0


@dataclass
class ParsedHTTPResponse:
    """Intermediate representation of an assembled HTTP Response."""

    status: int
    status_text: str = ""
    http_version: str = "HTTP/1.1"
    headers: dict[str, str] = field(default_factory=dict)
    body: Any = None
    ts: float = 0.0


@dataclass(frozen=True)
class Record:
    """Standardized output record produced by the HTTP Parser.

    This record conforms to the project-wide contract consumed in parallel
    by Agam's Shadow API Discovery engine and Hariom's BOLA/BFLA Detection engine.
    """

    ts: float
    user: str
    method: str
    path: str
    status: int
    req_body: Any = None
    resp_body: Any = None
    latency_ms: float = 0.0
    src_ip: str = ""
    role: str = "user"

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Record":
        """Instantiate a Record from a dictionary, safely ignoring extraneous fields."""
        known = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in known})

    def to_dict(self) -> dict[str, Any]:
        """Convert the record to a standard dictionary."""
        return asdict(self)

    def to_json(self) -> str:
        """Serialize the record to a compact JSON string."""
        return json.dumps(self.to_dict(), separators=(",", ":"))

    @property
    def ok(self) -> bool:
        """Check if the HTTP response indicates success (2xx)."""
        return 200 <= self.status < 300
