<div align="center">

# ⚡ API-Sentinel

### **Real-Time API Threat & Shadow API Detection Engine**
*Watching live API traffic in the Linux kernel • Rebuilding network packets into clean HTTP requests • Catching BOLA attacks before damage is done*

[![Rust](https://img.shields.io/badge/Rust-2021%20Edition-DEA584?style=for-the-badge&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![eBPF](https://img.shields.io/badge/Kernel-eBPF%20%2F%20Rust-orange?style=for-the-badge&logo=rust&logoColor=white)](https://ebpf.io/)
[![OWASP](https://img.shields.io/badge/OWASP-API%20Security%20Top%2010-red?style=for-the-badge&logo=owasp&logoColor=white)](https://owasp.org/www-project-api-security/)
[![Tests](https://img.shields.io/badge/Tests-All%20Passing-brightgreen?style=for-the-badge&logo=pytest&logoColor=white)](parser/tests/)
[![Architecture](https://img.shields.io/badge/Design-Zero--Overhead%20Passive-purple?style=for-the-badge)](docs/)

</div>

---

## 💡 What is API-Sentinel and Why Did We Build It?

Almost every app on your phone or laptop talks to backend servers using **APIs**.

Traditional security tools (like Web Application Firewalls) look for obvious bad code, like someone typing SQL commands into a search box. But the most dangerous modern API attacks don't look like code bugs at all:

1. **BOLA (Broken Object Level Authorization):**  
   Suppose you log in and see your receipt at `/api/orders/1001`. If you change the URL number to `/api/orders/1002` and the app shows you someone else's private order, that is a BOLA attack! Firewalls can't spot this because the request looks like a completely normal, valid HTTP call.
2. **Shadow APIs (Forgotten & Hidden Endpoints):**  
   Developers often create quick test routes or leave old versions running (like `/v1/debug_users`). Because these endpoints are not in the official documentation, security teams don't even know they exist to protect them.

**API-Sentinel** fixes this without slowing down the app or forcing developers to change a single line of code. We watch network calls directly inside the Linux kernel using **eBPF**, stitch the traffic back together, figure out who is calling what, and stop attackers on the fly.

---

## 🏛️ How Traffic Moves Through the System

Here is the simple, step-by-step path traffic takes through our project:

```text
       ┌─────────────────────────────────────────────────────────────┐
       │                 API Clients & Microservices                 │
       └──────────────────────────────┬──────────────────────────────┘
                                      │ Live Traffic
  ════════════════════════════════════╪═════════════════════════════════════  KERNEL SPACE
                                      ▼
                      eBPF Kernel Probes (send / recv)
                      • Listens to socket traffic quietly
                                      │
                                      ▼
                             eBPF Ring Buffer
  ════════════════════════════════════╪═════════════════════════════════════  USER SPACE
                                      ▼
                         Rust Ingestion Agent (sensor/)
                         • Pulls raw packet bytes out of the kernel
                                      │
                                      ▼ (Raw Byte Chunks)
                       HTTP Stream Parser (parser/) ◄── [Prince's Module]
                       • Glues broken TCP chunks back together
                       • Reads the HTTP method, path, and headers
                       • Unpacks JSON request bodies safely
                       • Extracts caller ID & role from JWT tokens
                       • Measures response time in milliseconds
                                      │
                                      ▼ (Clean, Structured Records)
                       ┌──────────────┴──────────────┐
                       ▼                             ▼
         Shadow API Engine (discovery/)     BOLA / BFLA Engine (detector/)
         (Agam)                             (Hariom)
         • Finds hidden/undocumented routes • Checks if a user really owns that ID
         • Compares against OpenAPI specs   • Flags suspicious ID guessing
         • Blocks high-speed bots           • Sends block orders back to kernel
                       │                             │
                       └──────────────┬──────────────┘
                                      ▼
                          PII Masking Layer (masking/)
                          (Meet)
                          • Hides passwords, tokens, and personal info
                                      │
                       ┌──────────────┴──────────────┐
                       ▼                             ▼
             Live Threat Dashboard             Kernel Blocklist
             (Meet - dashboard/)               (Pranav - sensor/)
             • Clean React dashboard           • Drops attacker packets instantly
             • Real-time alerts & maps           right at the network card (XDP)
```

---

## 👥 Who is Building What?

We are a 5-person engineering team:

| Teammate | Folder | What They Build | Tech Stack |
|:---|:---|:---|:---|
| **Pranav** | `sensor/` | **Kernel Sniffer:** Writes eBPF programs to capture live traffic from the kernel without delays, and uses XDP to drop blocked IPs. | Rust, eBPF, Aya, C |
| **Prince** *(Me)* | `parser/` | **HTTP Stream Engine:** Reassembles fragmented TCP packets, parses HTTP requests/responses, extracts user identity from JWTs, and measures latency. | Rust (Rust 2021) |
| **Agam** | `discovery/`, `ratelimit/` | **Shadow APIs & Rate Limits:** Spots undocumented endpoints, checks them against OpenAPI documentation, and stops spammers. | Python |
| **Hariom** | `detector/` | **BOLA & BFLA Detection:** Tracks which user owns which data ID, catches unauthorized access attempts, and issues block decisions. | Python |
| **Meet** | `masking/`, `dashboard/`, `testbed/` | **Privacy & UI:** Strips sensitive user data (passwords, emails), builds the React web dashboard, and runs test attacks against crAPI. | React, Vite, Docker |

---

## 🔬 Deep Dive: My Module (`parser/`)

My module is the **bridge** between the kernel capture and the detection brains.

When the kernel grabs network packets, they come out in messy, broken byte slices. My parser:
1. **Stitches Broken Chunks Together:** TCP often splits a single HTTP request across multiple packets. We buffer and reassemble them into complete messages.
2. **Parses HTTP Requests:** Reads the method (`GET`, `POST`, etc.), the URL path, the headers (case-insensitively), and decodes JSON bodies safely.
3. **Pulls User Identity:** Decodes `Authorization: Bearer <JWT>` tokens and API keys to find out *who* made the call (e.g. `user_55`) and what *role* they have (`admin` or `user`).
4. **Times the Request:** Matches each request with its response to calculate exact round-trip latency in milliseconds (`latency_ms`).
5. **Hands Off Clean Data:** Produces a standardized, easy-to-read `Record` for our teammates to analyze:

### What the output record looks like:
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

## 🗂️ How the Files are Organized

```text
api-sentinel/
├── parser/                     # [PRINCE] Rust HTTP Parsing Engine
│   ├── Cargo.toml              # Rust crate setup and dependencies (serde, serde_json)
│   ├── src/
│   │   ├── lib.rs              # Main module exports
│   │   ├── models.rs           # Core data structures (Record, RawFragment, ConnectionKey)
│   │   ├── request.rs          # HTTP request-line, header, and JSON body parser
│   │   ├── auth.rs             # Safe JWT and API-key identity reader (zero dependencies)
│   │   ├── base.rs             # HttpParser trait definition
│   │   └── reassembler.rs      # Connection buffer tracking and latency stopwatch
│   ├── tests/
│   │   └── foundation_tests.rs # Complete test suite
│   └── README.md               # Detailed parser module notes
├── .gitignore                  # Keeps temporary build files out of Git
└── README.md                   # This overview guide
```

---

## 🚀 How to Run the Tests

The parser is written in **Rust** for maximum speed and security.

### 1. Clone the Repo & Switch to the Branch
```bash
git clone https://github.com/HariomTiwari-CSE/API-Sentinel.git
cd API-Sentinel
git checkout Prince
```

### 2. Run All Tests
```bash
cargo test --manifest-path parser/Cargo.toml
```

All tests pass cleanly:
* Request-line parsing (`GET`, `POST`, `PUT`, `DELETE`, etc.)
* Case-insensitive header lookups
* Content-Length and chunked transfer decoding
* Safe JSON body decoding and graceful fallback
* JWT token claim decoding without third-party bloat
* Connection state tracking and latency calculation
* Multiple pipelined requests in a single stream

---

## 📅 4-Week Project Roadmap

```text
Week 1: Getting the Basics Working
├── [x] Day 1: Project setup, architecture analysis, data models, and foundation tests.
├── [x] Day 2: HTTP request parsing, headers, chunked bodies, and JSON decoding.
├── [ ] Day 3: HTTP response parsing, status codes, and error responses.
├── [ ] Day 4: Stream reassembly engine, request-response pairing, and latency timing.
├── [ ] Day 5: Handling edge cases (broken packets, weird headers, huge bodies).
├── [ ] Day 6: Testing the pipeline with realistic traffic dumps.
└── [ ] Day 7: Buffer day, code cleanup, and review preparation.

Week 2: Detecting Attacks & Mid Review
├── Automatically map all discovered API endpoints.
├── Spot shadow APIs missing from the OpenAPI documentation.
├── Track object ownership and catch BOLA attacks.
└── Mid-Review Milestone: Live demo catching a simulated BOLA attack!

Week 3: Active Defense
├── Tell the eBPF kernel layer to block hostile IPs instantly.
└── Add rate limiting and bot detection.

Week 4: Dashboard & Final Presentation
├── Mask passwords and emails before sending data to the screen.
├── Polish the React web dashboard.
└── Final presentation, benchmarks, and report submission.
```

---

<div align="center">

**API-Sentinel** • *Built with precision for modern API security.*

</div>
