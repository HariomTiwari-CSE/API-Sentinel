# 🧩 HTTP Parser Module (`parser/`)

> **Assigned to:** Prince Kumar (Contributor 2)  
> **Language:** Rust (Rust 2021 edition)  
> **Crate Name:** `api-sentinel-parser`  
> **Upstream input:** Raw socket chunks from Pranav's eBPF sensor & Rust ingestion agent (`sensor/`)  
> **Downstream output:** Clean, structured `Record`s for Agam (`discovery/`) and Hariom (`detector/`)

---

## 💡 What Does This Module Do?

When network traffic is captured in the Linux kernel by eBPF, it comes out as raw, fragmented byte slices from socket syscalls (`send`, `recv`, `read`, `write`).

The **Rust HTTP Parser** module delivers zero-copy, wire-speed parsing:

1. **Reassembles TCP Streams:** Buffers in-flight TCP slices across socket 4-tuples (`ConnectionKey`) to reassemble fragmented HTTP/1.x messages.
2. **Parses Requests & Bodies:** Extracts request line (`method`, `path`, `http_version`), case-insensitive headers, chunked transfer-encoding, `Content-Length`, and JSON payloads into structured `ParsedHTTPRequest` instances.
3. **Extracts Identity & Roles:** Safe, zero-dependency JWT Bearer payload decoder and API key extractor to resolve `user` (e.g. `user_55`) and `role` (`admin` / `user`) for BFLA/BOLA detection.
4. **Pairs Requests & Responses:** Correlates transactions in FIFO order, computing high-precision sub-millisecond round-trip latency (`latency_ms`).
5. **Emits Standard Records:** Produces normalized `Record` structs serializable directly to JSON for downstream consumption.

---

## 📦 Rust Crate Structure

```text
parser/
├── Cargo.toml                  # Rust package manifest & dependencies (serde, serde_json)
├── src/
│   ├── lib.rs                  # Crate root & public exports
│   ├── models.rs               # Record, RawFragment, ConnectionKey, ParsedHTTPRequest/Response
│   ├── request.rs              # Core HTTP/1.x request-line, header, and body parser
│   ├── auth.rs                 # Zero-dependency JWT base64url decoding & API-key parser
│   ├── base.rs                 # HttpParser trait interface
│   └── reassembler.rs          # Stateful connection tracking & latency timers
├── tests/
│   └── foundation_tests.rs     # Integration & unit test suite (Cargo tests)
└── README.md                   # This documentation
```

---

## 📜 The Data Contracts

### 1. Ingest Contract (`RawFragment`):
```rust
pub struct RawFragment {
    pub connection_id: String,
    pub ts: f64,
    pub direction: TrafficDirection, // Ingress (request) or Egress (response)
    pub payload: Vec<u8>,
}
```

### 2. Output Contract (`Record`):
```rust
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Record {
    pub ts: f64,
    pub user: String,
    pub method: String,
    pub path: String,
    pub status: u16,
    pub req_body: Option<serde_json::Value>,
    pub resp_body: Option<serde_json::Value>,
    pub latency_ms: f64,
    pub src_ip: String,
    pub role: String,
}
```

JSON Output:
```json
{
  "ts": 1731312000.104,
  "user": "user_55",
  "role": "user",
  "method": "GET",
  "path": "/api/orders/1002",
  "status": 200,
  "req_body": null,
  "resp_body": {"id": 1002, "item": "Keyboard"},
  "latency_ms": 14.25,
  "src_ip": "10.0.0.7"
}
```

---

## 🧪 Testing

Execute tests via Cargo:
```bash
cargo test --manifest-path parser/Cargo.toml
```

Tests cover:
* `Record` instantiation, defaults, `.ok()` 2xx checks, and JSON roundtrip serialization
* `TrafficDirection` string normalization
* `ConnectionKey` forward, reverse, and bidirectional identifier invariance
* JWT payload claim decoding and role extraction
* Connection state stream buffering and latency calculation
* HTTP request-line, headers, and JSON body parsing
* Pipelined request parsing
