# 🧩 HTTP Parser Module (`parser/`)

> **Assigned to:** Prince Kumar (Contributor 2)  
> **Language:** Rust (Rust 2021 edition)  
> **Crate Name:** `api-sentinel-parser`  
> **Upstream input:** Raw socket chunks from Pranav's eBPF sensor & Rust agent (`sensor/`)  
> **Downstream output:** Clean, structured `Record`s for Agam (`discovery/`) and Hariom (`detector/`)

---

## 💡 What Does This Module Do?

When network traffic is captured in the Linux kernel by eBPF, it comes out as messy, broken byte slices. A single HTTP call might be split across several packets.

The **Rust HTTP Parser** module turns those messy bytes into clean, structured data:

1. **Glues Broken Packets Together:** Buffers and rebuilds fragmented TCP network streams so that partial pieces become full HTTP messages.
2. **Parses HTTP Requests:** Extracts the method (`GET`, `POST`, etc.), the path, case-insensitive headers, and unpacks JSON request bodies safely.
3. **Identifies the Caller:** Reads `Authorization: Bearer <JWT>` tokens or API keys to know *who* made the call (e.g. `user_55`) and their *role* (`admin` or `user`) with zero external crypto libraries.
4. **Times the Response:** Pairs every request with its matching response to calculate exact round-trip time in milliseconds (`latency_ms`).
5. **Outputs Clean Records:** Emits a standardized `Record` struct that can be serialized directly to JSON for downstream detection engines.

---

## 📦 How the Code is Organized

```text
parser/
├── Cargo.toml                  # Rust package setup and dependencies (serde, serde_json)
├── src/
│   ├── lib.rs                  # Module exports
│   ├── models.rs               # Data structures (Record, RawFragment, ConnectionKey)
│   ├── request.rs              # HTTP request-line, header, and body parser
│   ├── response.rs             # HTTP response status-line, header, and body parser
│   ├── auth.rs                 # Zero-dependency JWT and API-key identity reader
│   ├── base.rs                 # HttpParser trait interface
│   └── reassembler.rs          # TCP stream reassembly, request-response matching, latency
├── tests/
│   └── foundation_tests.rs     # Integration and unit test suite
└── README.md                   # This documentation
```

---

## 📜 The Data Contracts

### 1. What Comes In (`RawFragment` from Rust agent):
```rust
pub struct RawFragment {
    pub connection_id: String,
    pub ts: f64,
    pub direction: TrafficDirection, // Ingress (request) or Egress (response)
    pub payload: Vec<u8>,
}
```

### 2. What Goes Out (`Record` to Detector & Discovery):
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

Run all unit tests via Cargo:
```bash
cargo test --manifest-path parser/Cargo.toml
```

Tests cover:
* `Record` creation, default values, `.ok()` 2xx checks, and JSON roundtrip serialization
* `TrafficDirection` string parsing and normalization
* `ConnectionKey` forward, reverse, and bidirectional ID invariance
* JWT claim decoding and role extraction
* Connection buffer state and latency calculation
* HTTP request-line, headers, chunked encoding, and JSON body parsing
* Pipelined request parsing
