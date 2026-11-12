# HTTP Parser Module (`parser/`) — API-Sentinel

**Owner:** Prince Kumar (Contributor 2)  
**Module:** `parser/`  
**Downstream Consumers:** `discovery/` (Agam), `detector/` (Hariom)  
**Upstream Provider:** `sensor/` (Pranav's eBPF sensor + Rust user-space agent)

---

## 1. Module Overview & Architectural Placement

In the **API-Sentinel** architecture, the HTTP Parser is the bridge between raw kernel traffic capture and user-space security detection engines:

```
[ Linux Kernel ]
       │ eBPF Syscall Probes (send, recv, read, write)
       ▼
[ Ring Buffer ]
       │ Raw socket bytes & 4-tuple events
       ▼
[ Rust Agent (sensor/) ]
       │ RawFragment stream (connection_id, direction, payload, ts)
       ▼
[ HTTP Parser (parser/) ] ◄── (This Module)
  - Reassembles fragmented TCP streams per connection
  - Reconstructs complete HTTP/1.x requests and responses
  - Matches requests to responses (FIFO / pipelining)
  - Extracts caller identity (JWT claims, API keys) & role
  - Computes request-response latency (latency_ms)
       │
       ├───────────────────────────────┐
       ▼                               ▼
[ discovery/ (Agam) ]         [ detector/ (Hariom) ]
- Shadow/Zombie API engine    - BOLA / BFLA engine
- Path normalization          - User ownership map
- Schema inference            - Kernel block verdicts
```

---

## 2. Interface Contracts

### 2.1 Upstream Input (`RawFragment`)

Received from the Rust user-space agent:

```python
RawFragment(
    connection_id="10.0.0.7:54321->10.0.0.1:8000",
    ts=1731312000.1,
    direction=TrafficDirection.INGRESS,  # INGRESS (request) or EGRESS (response)
    payload=b"GET /api/orders/1002 HTTP/1.1\r\nHost: api.crapi.local\r\n..."
)
```

### 2.2 Downstream Output (`Record`)

Standardized dataclass published onto the event bus for `discovery/` and `detector/`:

```python
@dataclass(frozen=True)
class Record:
    ts: float                # Request timestamp (epoch seconds)
    user: str                # Identified user ID / subject (e.g., "user_55" or "anonymous")
    method: str              # HTTP method (e.g., "GET", "POST", "PUT", "DELETE")
    path: str                # Request URI / path (e.g., "/api/orders/1002")
    status: int              # Response HTTP status code (e.g., 200, 403, 404)
    req_body: Any = None     # Parsed request body (dict/list for JSON, str, or None)
    resp_body: Any = None    # Parsed response body (dict/list for JSON, str, or None)
    latency_ms: float = 0.0  # Duration between request and response in milliseconds
    src_ip: str = ""         # Client IP address (for rate limiting, bot & blocklist rules)
    role: str = "user"       # Caller role from JWT claims (for BFLA detection)
```

JSON Representation:
```json
{
  "ts": 1731312000.1,
  "user": "user_55",
  "method": "GET",
  "path": "/api/orders/1002",
  "status": 200,
  "req_body": null,
  "resp_body": {"id": 1002},
  "latency_ms": 12.4,
  "src_ip": "10.0.0.7",
  "role": "user"
}
```

---

## 3. Module Structure

```
parser/
├── __init__.py         # Package exports and version metadata
├── models.py           # Record, RawFragment, ConnectionKey, ParsedHTTPRequest/Response
├── base.py             # BaseHTTPParser abstract interface
├── reassembler.py      # ConnectionState buffer management and latency calculation
├── auth.py             # JWT claims extraction and API key identification
└── README.md           # Module architecture and documentation
```

---

## 4. Week 1 Implementation Roadmap

| Day | Goal & Tasks | Status |
|:---:|:---|:---:|
| **Day 1** | **Foundation & Contracts:** Architecture analysis, module skeleton, data models, base parser interface, auth helper, foundation unit tests. | ✅ Completed |
| **Day 2** | **HTTP Request Parsing:** Implement HTTP/1.x request line parsing, headers extraction, Content-Length & chunked body decoding. | ⏳ Planned |
| **Day 3** | **HTTP Response Parsing:** Implement response status line, response headers, body decoding, and error response handling. | ⏳ Planned |
| **Day 4** | **Stream Reassembly & Matching:** Implement FIFO transaction pairing, connection buffer flush, and accurate `latency_ms` calculation. | ⏳ Planned |
| **Day 5** | **Robustness & Edge Cases:** Malformed HTTP handling, fragmented packets, boundary split tests, large payload handling. | ⏳ Planned |
| **Day 6** | **Integration Verification:** Feed sample crAPI traffic dumps, verify `Record` emission against Hariom's detector and Agam's discovery engine. | ⏳ Planned |
| **Day 7** | **Mid-Review Preparation:** Code cleanup, performance verification, PR review, and documentation finalization. | ⏳ Planned |
