# 🧩 HTTP Parser Module (`parser/`)

> **Assigned to:** Prince Kumar (Contributor 2)  
> **Upstream input:** Raw socket chunks from Pranav's Rust agent (`sensor/`)  
> **Downstream output:** Clean HTTP records for Agam (`discovery/`) and Hariom (`detector/`)

---

## 💡 What Does This Module Do?

When network traffic is captured in the Linux kernel by eBPF, it comes out as messy, raw bytes. Packets can be split in half, arrive out of order, or have partial headers.

The **HTTP Parser** module takes care of all that heavy lifting:

1. **Reassembles fragments:** Glues broken TCP chunks back into complete HTTP/1.x requests and responses.
2. **Identifies the caller:** Decodes JWT Bearer tokens or API keys without third-party bloat to find out *who* made the call (e.g. `user_55`) and their role (`admin` or `user`).
3. **Pairs requests & responses:** Matches each outgoing request with its incoming response so we know the HTTP status code (200, 403, 404, etc.) and calculate how many milliseconds it took (`latency_ms`).
4. **Hands off clean data:** Produces a standardized `Record` object that the BOLA detector and Shadow API engine can evaluate immediately.

---

## 📦 How the Code is Organized

```text
parser/
├── __init__.py         # Package exports (models, base parser, auth helper)
├── models.py           # Record, RawFragment, ConnectionKey, ParsedHTTPRequest/Response
├── base.py             # BaseHTTPParser abstract interface (so we can swap engines or mock in tests)
├── reassembler.py      # ConnectionState buffer management & latency timing
├── auth.py             # Safe, zero-dependency JWT and API-key extractor
└── README.md           # This guide
```

---

## 📜 The Data Contracts

### 1. What comes in (`RawFragment` from Rust agent):
```python
RawFragment(
    connection_id="10.0.0.7:54321->10.0.0.1:8000",
    ts=1731312000.1,
    direction=TrafficDirection.INGRESS,  # INGRESS for request, EGRESS for response
    payload=b"GET /api/orders/1002 HTTP/1.1\r\nHost: api.crapi.local\r\n..."
)
```

### 2. What goes out (`Record` to Detector & Discovery):
```python
@dataclass(frozen=True)
class Record:
    ts: float                # Request timestamp (epoch seconds)
    user: str                # Identified user ID (e.g. "user_55" or "anonymous")
    method: str              # HTTP method ("GET", "POST", "PUT", "DELETE")
    path: str                # URL path (e.g. "/api/orders/1002")
    status: int              # Response status code (e.g. 200, 403, 404)
    req_body: Any = None     # Request body (parsed JSON dict, string, or None)
    resp_body: Any = None    # Response body (parsed JSON dict, string, or None)
    latency_ms: float = 0.0  # Round-trip duration in milliseconds
    src_ip: str = ""         # Client IP address (for rate limiting & blocklists)
    role: str = "user"       # Role from JWT claims (for BFLA privilege checks)
```

JSON representation:
```json
{
  "ts": 1731312000.1,
  "user": "user_55",
  "role": "user",
  "method": "GET",
  "path": "/api/orders/1002",
  "status": 200,
  "req_body": null,
  "resp_body": {"id": 1002, "item": "Keyboard"},
  "latency_ms": 12.4,
  "src_ip": "10.0.0.7"
}
```

---

## 🧪 Testing

We keep things lightweight with zero required third-party packages.

Run all tests:
```bash
python -m pytest tests/ -v
```

All 17 tests verify:
* Record creation, default values, and `.ok` (2xx check) property
* Fast JSON and dictionary serialization
* Connection 4-tuple normalization
* JWT claim decoding without PyJWT
* Connection buffer state and latency calculation
