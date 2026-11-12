# API-Sentinel

> **Runtime BOLA & Shadow API Detection Engine**  
> *Zero-overhead kernel traffic capture with eBPF, automated stream reassembly, behavioral authorization defense, and real-time threat visibility.*

---

## 💡 Why We're Building This

Modern microservices rely almost entirely on REST and HTTP APIs. While traditional perimeter security tools (like Web Application Firewalls or API Gateways) do a decent job catching SQL injection or signature-based exploits, they have two glaring blind spots:

1. **Broken Object Level Authorization (BOLA / IDOR):** Attackers don't inject malicious syntax; they send perfectly valid HTTP requests while swapping out IDs (`/api/orders/1002` vs `/api/orders/1003`) to access data belonging to someone else. Standard firewalls see valid JSON and let it pass straight through.
2. **Shadow & Zombie APIs:** Microservices evolve fast. Developers deploy staging routes, legacy endpoints, or undocumented debug paths that never make it into the official OpenAPI/Swagger documentation. If a security team doesn't know an endpoint exists, they can't defend it.

**API-Sentinel** solves these challenges using a **Zero-Trust, passive-observability** approach. Instead of forcing developers to install heavy middleware or configure intrusive reverse proxies, we observe socket traffic directly from the Linux kernel using **eBPF**. That raw traffic is reassembled, correlated with caller identity, analyzed against live behavioral baselines and OpenAPI specs, and surfaced in real time on an interactive dashboard.

---

## 🏗️ System Architecture & Workflow

Traffic flows seamlessly from kernel space to user-space analytical engines and back down to the kernel for active defense:

```text
       [ API Clients & Microservices ]
                      │
  ════════════════════╪═════════════════════════════════════════  Kernel Space
                      ▼
             eBPF Syscall Probes  (send / recv / read / write)
                      │
                 Ring Buffer
  ════════════════════╪═════════════════════════════════════════  User Space
                      ▼
            Rust Ingestion Agent  (sensor/)
                      │
                      │ Raw TCP Fragments & Socket 4-tuples
                      ▼
            HTTP Stream Parser  (parser/) ◄── [Prince]
                      │
                      │ Normalized Structured Records:
                      │ {ts, user, role, method, path, status, latency_ms, bodies...}
                      ├─────────────────────────────────┐
                      ▼                                 ▼
        Shadow API Engine (discovery/)        BOLA / BFLA Engine (detector/)
        - Path Normalization ({id})           - User Ownership Mapping
        - Schema Inference                    - Sequential Enumeration
        - OpenAPI Spec Drift                  - Role-Based Access Violations
                      │                                 │
                      └────────────────┬────────────────┘
                                       ▼
                              PII Masking (masking/)
                                       │
                      ┌────────────────┴────────────────┐
                      ▼                                 ▼
           Threat Dashboard (dashboard/)     Kernel Blocklist Map (XDP/TC)
           - Real-time alerts & inventory     - Drops attacker packets at NIC
```

---

## 👥 Team Module Ownership

API-Sentinel is developed as a collaborative 4-week project under Axlero Solutions:

| Contributor | Module | Domain & Responsibilities | Tech Stack |
|:---|:---|:---|:---|
| **Pranav** | `sensor/` | **Kernel-Level Capture:** eBPF syscall probes, socket ring buffer, Rust user-space agent, and XDP/TC active packet dropper. | Rust, eBPF, Aya / libbpf |
| **Prince** | `parser/` | **HTTP Stream Engine:** TCP fragment reassembly, request-response pairing, caller identity (JWT / API key) & role extraction, and latency calculation. | Python |
| **Agam** | `discovery/`, `ratelimit/` | **API Inventory & Abuse Defense:** Path normalization (`/orders/1002` → `/orders/{id}`), OpenAPI spec diffing for Shadow/Zombie APIs, and token-bucket rate limiting. | Python |
| **Hariom** | `detector/` | **Behavioral Authorization:** Dynamic object ownership mapping, BOLA enumeration detection, BFLA privilege violation checks, and block verdict generation. | Python |
| **Meet** | `masking/`, `dashboard/`, `testbed/` | **Privacy, UI & Benchmarking:** PII redaction on sensitive payloads, React telemetry dashboard, and vulnerable application testbed (crAPI / VAmPI). | React, Vite, Tailwind CSS, Docker |

---

## 🔍 Module Spotlight: `parser/` (My Assignment)

As the owner of `parser/`, my responsibility is turning raw, out-of-order socket packet chunks emitted from the kernel into clean, structured HTTP records that the security engines can reliably evaluate.

### The Pipeline Responsibilities:
* **Stream Reassembly:** Buffers fragmented TCP data per connection (`ConnectionKey`) and reconstructs complete HTTP/1.x request and response frames.
* **Transaction Correlation:** Matches each outgoing request with its corresponding response in FIFO/pipelined order to compute accurate transaction latency (`latency_ms`).
* **Identity & Role Extraction:** Safely decodes caller identity and role claims from `Authorization: Bearer <JWT>`, `X-API-Key`, and custom header fields without adding heavyweight third-party dependencies.
* **Universal Record Output:** Emits normalized `Record` dataclasses consumed by both the Shadow API engine and the BOLA detector:

```json
{
  "ts": 1731312000.1,
  "user": "user_55",
  "role": "user",
  "method": "GET",
  "path": "/api/orders/1002",
  "status": 200,
  "req_body": null,
  "resp_body": {"id": 1002, "item": "Widget"},
  "latency_ms": 12.4,
  "src_ip": "10.0.0.7"
}
```

---

## 📅 4-Week Project Roadmap

### **Week 1: Foundations & Core Ingestion**
- [x] **Day 1:** System architecture analysis, repository setup, data models, base parser interface, and foundation test suite.
- [ ] **Day 2:** HTTP request-line and header parsing (Content-Length, transfer encoding, JSON extraction).
- [ ] **Day 3:** HTTP response parsing and status code evaluation.
- [ ] **Day 4:** Per-connection stream reassembly and request-response transaction pairing.
- [ ] **Day 5:** Edge-case handling (partial chunks, pipelining, malformed traffic).
- [ ] **Day 6:** End-to-end integration with mock fixtures and downstream contracts.
- [ ] **Day 7:** Mid-Week review prep and code cleanup.

### **Week 2: Detection, Discovery & Mid Review**
- Automatic endpoint cataloging and schema inference (`discovery/`).
- Shadow and Zombie API drift detection against OpenAPI specifications.
- Dynamic object ownership tracking and BOLA attack detection (`detector/`).
- **Mid Review Milestone:** Live demonstration of simulated BOLA attack detection against crAPI.

### **Week 3: Active Defense & Rate Limiting**
- Dynamic kernel blocklist integration via eBPF XDP/TC hooks to drop hostile IPs.
- Token-bucket rate limiting and automated bot/enumeration detection.

### **Week 4: Privacy, Visualization & Polish**
- PII masking on sensitive response parameters before reaching the UI.
- Finalizing the React security dashboard mapped to OWASP API Security Top 10.
- Performance benchmarking and final review submission.

---

## 🚀 Getting Started with the Parser Module

### Prerequisites
* Python 3.10+
* `pytest` (optional, for test execution)

### Running Tests Locally
The parser module is built entirely using Python's standard library to maintain maximum speed and zero external dependency baggage.

Run the test suite using either `pytest` or Python's built-in `unittest`:

```bash
# Using pytest
python -m pytest tests/ -v

# Or using standard unittest
python -m unittest discover -s tests -v
```

All 17 foundation tests currently pass with 100% test coverage across model contracts, JWT claim decoding, connection state management, and serialization.

---

## 🛡️ Key Security Concepts Covered

* **OWASP API1:2023 — Broken Object Level Authorization (BOLA):** Flawed access control where endpoints don't verify whether the requesting user actually owns the target resource ID.
* **OWASP API5:2023 — Broken Function Level Authorization (BFLA):** Regular users executing administrative or privileged endpoints due to missing role checks.
* **OWASP API9:2023 — Improper Inventory Management (Shadow APIs):** Exposing unmonitored, undocumented endpoints to production traffic without security scrutiny.
* **eBPF (Extended Berkeley Packet Filter):** In-kernel sandboxed programs that inspect network syscalls at wire speed without instrumenting application source code.
