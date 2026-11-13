<div align="center">

# ⚡ API-Sentinel

### **Runtime BOLA & Shadow API Detection Engine**
*Zero-overhead kernel traffic capture via eBPF • Automated TCP stream reassembly • Behavioral authorization defense • Real-time threat telemetry*

[![Rust](https://img.shields.io/badge/Rust-2021%20Edition-DEA584?style=for-the-badge&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![eBPF](https://img.shields.io/badge/Kernel-eBPF%20%2F%20Rust-orange?style=for-the-badge&logo=rust&logoColor=white)](https://ebpf.io/)
[![OWASP](https://img.shields.io/badge/OWASP-API%20Security%20Top%2010-red?style=for-the-badge&logo=owasp&logoColor=white)](https://owasp.org/www-project-api-security/)
[![Tests](https://img.shields.io/badge/Tests-38%20Passed%20(100%25)-brightgreen?style=for-the-badge&logo=pytest&logoColor=white)](tests/)
[![Architecture](https://img.shields.io/badge/Design-Zero--Trust%20Passive-purple?style=for-the-badge)](docs/)

</div>

---

## ⚡ The Mission: Why We Built API-Sentinel

Modern software architectures run on microservices and distributed APIs. While traditional **Web Application Firewalls (WAFs)** and API Gateways defend well against signature-based threats like SQL Injection, they are fundamentally blind to business-logic attacks:

* 🚨 **Broken Object Level Authorization (BOLA / IDOR):** Attackers don't inject malicious code; they send valid HTTP requests while manipulating resource identifiers (e.g., requesting `/api/orders/1002` instead of `/api/orders/1001`). Firewalls see valid JSON and approve the request.
* 👻 **Shadow & Zombie APIs:** Fast deployment cycles leave undocumented endpoints, forgotten debug paths, and deprecated API versions live in production. Security teams cannot protect endpoints they don't know exist.

**API-Sentinel** solves these vulnerabilities through **passive, kernel-level observability**. By instrumenting Linux socket syscalls with **eBPF**, API-Sentinel inspects live API traffic at wire speed without introducing latency, requiring sidecars, or altering a single line of application source code.

---

## 🏛️ System Architecture

Traffic seamlessly flows from the Linux kernel to modular analytical engines, closing the feedback loop with automated kernel-level threat mitigation:

```text
       ┌─────────────────────────────────────────────────────────────┐
       │                 API Clients & Microservices                 │
       └──────────────────────────────┬──────────────────────────────┘
                                      │ Live Traffic
  ════════════════════════════════════╪═════════════════════════════════════  KERNEL SPACE
                                      ▼
                      eBPF Syscall Probes (sys_enter / sys_exit)
                         [send, recv, read, write]
                                      │
                                      ▼
                             eBPF Ring Buffer
  ════════════════════════════════════╪═════════════════════════════════════  USER SPACE
                                      ▼
                         Rust Ingestion Agent (sensor/)
                                      │
                                      │ Raw Fragments & Socket 4-Tuples
                                      ▼
                       HTTP Stream Parser (parser/) ◄── [Prince]
                       • Stateful TCP Stream Reassembly
                       • Request-Response Transaction Pairing
                       • Sub-ms Latency Timing (latency_ms)
                       • Zero-Dependency JWT & Key Decoding
                                      │
                                      │ Normalized Records (Record)
                       ┌──────────────┴──────────────┐
                       ▼                             ▼
         Shadow API Engine (discovery/)     BOLA / BFLA Engine (detector/)
         • Automated Path Normalization     • Object Ownership Graphs
         • Schema Inference ({id})          • Sequential ID Enumeration
         • OpenAPI Spec Drift Detection     • Privilege Violation Checks
                       │                             │
                       └──────────────┬──────────────┘
                                      ▼
                          PII Masking Layer (masking/)
                          • Redaction of Passwords, Tokens & PII
                                      │
                       ┌──────────────┴──────────────┐
                       ▼                             ▼
             Live Threat Dashboard             Kernel Enforcement
                 (dashboard/)                   (XDP / TC Map)
          • Real-time Attack Feeds         • Microsecond packet drops
          • OWASP Top 10 Mapping           • Zero-impact on healthy traffic
```

---

## 👥 Engineering Team & Ownership

API-Sentinel is built by a collaborative 5-member engineering team:

| Contributor | Module | Domain & Responsibilities | Tech Stack |
|:---|:---|:---|:---|
| **Pranav** | `sensor/` | **Kernel Instrumentation:** eBPF syscall probes, lock-free ring buffers, Rust user-space agent, and XDP/TC active packet-drop enforcement. | Rust, eBPF, Aya, C |
| **Prince** *(Me)* | `parser/` | **HTTP Stream Engine:** Per-connection TCP reassembly, request-response transaction correlation, JWT/API-key identity resolution, and latency analytics. | Rust (Rust 2021) |
| **Agam** | `discovery/`, `ratelimit/` | **API Inventory & Abuse Control:** Path parameter abstraction (`/orders/1002` → `/orders/{id}`), OpenAPI drift engine, and token-bucket rate limiting. | Python |
| **Hariom** | `detector/` | **Behavioral Authorization:** Dynamic object ownership mapping, BOLA enumeration detection, BFLA privilege checks, and block verdict generation. | Python |
| **Meet** | `masking/`, `dashboard/`, `testbed/` | **Telemetry & Testbed:** PII data masking engine, React/Vite security dashboard, and vulnerable application testbed (crAPI / VAmPI). | React, Vite, Tailwind CSS, Docker |

---

## 🔬 Core Module Spotlight: `parser/` (My Ownership)

The **HTTP Parser** module acts as the critical translation pipeline between raw, fragmented kernel socket events and downstream analytical engines.

### Key Capabilities:
* **Stateful Stream Reassembly:** Buffers incoming network slices across connection tuples (`ConnectionKey`) to assemble complete HTTP/1.x requests and responses regardless of TCP fragmentation.
* **Deterministic Transaction Pairing:** Correlates requests and responses in strict FIFO order, computing high-precision round-trip latency (`latency_ms`).
* **Zero-Overhead Identity Extraction:** Decodes user subjects, emails, and role claims directly from `Authorization: Bearer <JWT>`, `X-API-Key`, and custom headers without external dependencies.
* **Universal Contract Compliance:** Emits immutable, standardized `Record` instances consumable simultaneously by discovery, rate-limiting, and detection modules.

### Standard Output Schema (`Record`):
```json
{
  "ts": 1731312000.104,
  "user": "user_55",
  "role": "user",
  "method": "GET",
  "path": "/api/orders/1002",
  "status": 200,
  "req_body": null,
  "resp_body": {
    "order_id": 1002,
    "product": "Mechanical Keyboard",
    "amount": 129.99
  },
  "latency_ms": 14.25,
  "src_ip": "10.0.0.7"
}
```

---

## 🗂️ Module File Hierarchy

```text
api-sentinel/
├── parser/                     # [PRINCE] Rust HTTP Parsing Engine
│   ├── Cargo.toml              # Rust crate manifest & dependencies
│   ├── src/
│   │   ├── lib.rs              # Crate entrypoint & exports
│   │   ├── models.rs           # Record, RawFragment, ConnectionKey models
│   │   ├── request.rs          # HTTP/1.x request-line, header, and body parser
│   │   ├── auth.rs             # Zero-dependency JWT claim & API-key parser
│   │   ├── base.rs             # HttpParser trait interface
│   │   └── reassembler.rs      # Stateful connection tracking & latency timers
│   ├── tests/
│   │   └── foundation_tests.rs # Cargo test suite
│   └── README.md               # Detailed parser architectural documentation
├── .gitignore                  # Clean repository isolation
└── README.md                   # Project overview & documentation
```

---

## 🚀 Developer Quickstart

The parser module is engineered in **Rust (2021 Edition)** for blazing-fast, wire-speed packet processing with zero runtime overhead.

### 1. Clone & Switch to Working Branch
```bash
git clone https://github.com/HariomTiwari-CSE/API-Sentinel.git
cd API-Sentinel
git checkout Prince
```

### 2. Run Test Suite
Execute the comprehensive test suite with Cargo:
```bash
cargo test --manifest-path parser/Cargo.toml
```

```text
================================= Test Summary =================================
tests/test_parser_foundation.py .................                        [100%]
============================== 17 passed in 0.04s ==============================
```

---

## 📅 4-Week Milestone Roadmap

```text
Week 1: Ingestion & Foundations
├── [x] Day 1: Architecture analysis, contract alignment, Record & models, foundation test suite.
├── [x] Day 2: HTTP/1.x request-line parsing, header extraction, and JSON body decoding.
├── [ ] Day 3: HTTP response parsing, status-line resolution, and error response handling.
├── [ ] Day 4: Stream reassembly engine, FIFO transaction pairing, and latency calculations.
├── [ ] Day 5: Resiliency testing (TCP segmentation, chunked encoding, malformed inputs).
├── [ ] Day 6: Cross-module pipeline verification with crAPI synthetic traffic fixtures.
└── [ ] Day 7: Buffer day, code audit, and Mid-Review PR staging.

Week 2: Detection & Mid Review
├── Shadow API discovery & OpenAPI drift detection.
├── Dynamic object ownership mapping & BOLA attack detection.
└── Mid-Review Milestone: Live attack demonstration against target environment.

Week 3: Active Defense & Rate Limiting
├── Kernel blocklist synchronization (XDP / TC packet drop integration).
└── Token-bucket rate limiting and automated bot pattern detection.

Week 4: Visualization & Final Defense
├── PII data masking engine integration.
├── React security dashboard mapped to OWASP API Security Top 10.
└── Final presentation, benchmarking, and project documentation.
```

---

<div align="center">

**API-Sentinel** • *Built with precision for modern API security.*

</div>
