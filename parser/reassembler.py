"""Connection state and stream reassembly foundation."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional

from parser.models import ParsedHTTPRequest, ParsedHTTPResponse


@dataclass
class ConnectionState:
    """Maintains stream buffers and in-flight HTTP transactions for a single connection."""

    connection_id: str
    created_at: float = field(default_factory=time.time)
    last_activity: float = field(default_factory=time.time)
    
    # Raw stream byte buffers
    ingress_buffer: bytearray = field(default_factory=bytearray)
    egress_buffer: bytearray = field(default_factory=bytearray)

    # In-flight parsed requests awaiting responses
    pending_requests: list[ParsedHTTPRequest] = field(default_factory=list)

    def append_ingress(self, chunk: bytes, ts: float) -> None:
        """Append incoming request bytes to the ingress buffer."""
        self.ingress_buffer.extend(chunk)
        self.last_activity = ts

    def append_egress(self, chunk: bytes, ts: float) -> None:
        """Append incoming response bytes to the egress buffer."""
        self.egress_buffer.extend(chunk)
        self.last_activity = ts

    def calculate_latency_ms(self, req: ParsedHTTPRequest, resp: ParsedHTTPResponse) -> float:
        """Calculate duration between request timestamp and response timestamp in milliseconds."""
        if req.ts > 0 and resp.ts >= req.ts:
            return round((resp.ts - req.ts) * 1000.0, 2)
        return 0.0

    def clear(self) -> None:
        """Reset buffers and pending state."""
        self.ingress_buffer.clear()
        self.egress_buffer.clear()
        self.pending_requests.clear()
