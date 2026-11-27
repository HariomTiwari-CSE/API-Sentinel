# API-Sentinel — Privacy Masking, Threat Dashboard & crAPI Testbed

> **Contributor:** Meet (Contributor 5)  
> **Branch:** `Meet`  
> **Owned Modules:** `masking/`, `dashboard/`, `testbed/`

---

## Overview

**API-Sentinel** is a runtime eBPF-powered API security and Zero-Trust posture management engine that detects Broken Object Level Authorization (**BOLA**), Broken Function Level Authorization (**BFLA**), **Shadow/Zombie APIs**, and rate-limit abuse without modifying target microservice code.

This branch implements Meet's end of the pipeline:

1. **`masking/` — PII Masking & Telemetry Bridge**  
   Strips Personally Identifiable Information (emails, passwords, JWTs, API keys, credit card numbers, SSNs, phone numbers, and street addresses) from captured `Record` payloads and detection `Finding` alerts before any telemetry reaches the dashboard. Includes a FastAPI + WebSocket gateway (`masking/server.py`).
2. **`dashboard/` — React Threat Dashboard (React + Vite)**  
   SOC-ready dark-mode dashboard visualizing active alerts, kernel XDP block verdicts, discovered API endpoint inventory (`documented`, `shadow`, `zombie`), **OWASP API Security Top 10** mappings, live PII redaction stats, and `< 5 ms` pipeline latency metrics.
3. **`testbed/` — crAPI Target App, OpenAPI Spec, Attack Suite & Benchmarks**  
   Provides both a Docker Compose setup for full OWASP crAPI (`testbed/docker-compose.crapi.yml`) and a lightweight crAPI-compatible local Flask testbed (`testbed/app/server.py`) with intentional OWASP API1, API4, API5, and API9 vulnerabilities, paired with scripted attack simulations (`testbed/attacks/`) and a latency SLA audit (`testbed/benchmarks/latency_audit.py`).

---

## Architecture & Team Integration

```text
  API Clients (Users & Attackers)
        │
        ▼
  testbed/ (Meet) ──► crAPI Microservice Target + testbed/openapi.yaml
        │
        ▼ (Kernel Syscalls + Ring Buffer / XDP Blocklist)
  sensor/ (Pranav) ──► parser/ (Prince: Record JSON)
                             │
        ┌────────────────────┼────────────────────┐
        ▼                    ▼                    ▼
  discovery/ (Agam)    detector/ (Hariom)   ratelimit/ (Agam)
        │                    │                    │
        └────────────────────┼────────────────────┘
                             ▼ (Raw Findings)
                    masking/ (Meet)
                    • PIIMasker strips emails, JWTs, cards, SSNs, secrets
                    • FastAPI + WebSocket telemetry gateway
                             │
                             ▼ (Sanitized Findings & Inventory)
                    dashboard/ (Meet)
                    • Endpoint Inventory (Documented / Shadow / Zombie)
                    • Live Threat Alerts & Evidence Drawer
                    • OWASP API Security Top 10 Mapping
```

### Fixed Data Contracts Supported

- **Upstream `Record` (from `parser/`):**  
  `ts`, `user`, `method`, `path`, `status`, `req_body`, `resp_body`, `latency_ms`, `src_ip`, `role`
- **Upstream `Finding` (from `detector/` / `discovery/` / `ratelimit/`):**  
  `type` (`BOLA | BFLA | SHADOW_API | ZOMBIE_API | RATE_LIMIT`), `owasp` (`API1 | API4 | API5 | API9`), `user`, `src_ip`, `endpoint`, `severity`, `action` (`alert | block`), `reason`, `ts`, `evidence`

---

## Repository Structure (Meet's Modules)

```text
.
├── README.md                              # Project & contributor documentation
├── .gitignore
├── masking/
│   ├── README.md                          # Masking module docs
│   ├── __init__.py
│   ├── pii.py                             # PIIMasker, MaskingConfig, Luhn card check & redaction stats
│   ├── server.py                          # FastAPI REST + WebSocket telemetry bridge (port 8000)
│   └── tests/
│       └── test_pii_masking.py            # Unit & route tests (5 tests)
├── testbed/
│   ├── README.md                          # Testbed & attack simulation docs
│   ├── docker-compose.crapi.yml           # Full containerized OWASP crAPI stack
│   ├── openapi.yaml                       # Official API contract (omits Shadow/Zombie routes)
│   ├── app/
│   │   └── server.py                      # Local crAPI-compatible Flask target (port 8888)
│   ├── attacks/
│   │   ├── common.py                      # TrafficSession emitting Parser/Detector Record JSONL
│   │   ├── bola_enum.py                   # Scripted BOLA sequential enumeration & vehicle GPS probe
│   │   ├── bfla_and_shadow.py             # BFLA, Shadow API, Zombie API & rate-limit burst probes
│   │   └── run_suite.py                   # End-to-end traffic + masked findings generator
│   ├── benchmarks/
│   │   └── latency_audit.py               # < 5 ms overhead SLA verification benchmark
│   ├── data/
│   │   ├── traffic_records.jsonl          # Masked Record stream from crAPI simulation
│   │   ├── sample_findings.jsonl          # Masked Finding stream (API1, API4, API5, API9)
│   │   ├── sample_inventory.json          # Discovered endpoint inventory snapshot
│   │   └── latency_report.json            # Measured p50 / p95 / p99 benchmark output
│   └── tests/
│       └── test_testbed.py                # Testbed, OpenAPI, attack & SLA tests (4 tests)
└── dashboard/
    ├── README.md                          # React dashboard docs
    ├── package.json
    ├── vite.config.js                     # Proxies /api and /ws to masking/server.py
    ├── index.html
    └── src/
        ├── main.jsx
        ├── index.css
        ├── App.jsx                        # Overview, Alerts, Inventory, OWASP Top 10 & PII Sandbox
        └── data/
            └── seedData.js                # Offline crAPI telemetry seed fallback
```

---

## Quick Start

### 1. Run Unit Tests & Simulations (Python)

```bash
# Run PII masking unit tests (5 tests)
python -m unittest discover -s masking/tests -v

# Run crAPI testbed, OpenAPI & latency SLA tests (4 tests)
python -m unittest discover -s testbed/tests -v

# Generate fresh masked traffic & findings from the crAPI testbed
python -m testbed.attacks.run_suite

# Run the < 5 ms latency SLA audit
python -m testbed.benchmarks.latency_audit
```

### 2. Start the Masking Telemetry Gateway + React Dashboard

```bash
# Terminal 1: Start the PII-masking telemetry API (port 8000)
uvicorn masking.server:app --host 0.0.0.0 --port 8000

# Terminal 2: Start the React Threat Dashboard (port 5173)
cd dashboard
npm install
npm run dev
```

*(Optional) Terminal 3: Run the standalone local crAPI target on port 8888:*
```bash
python -m testbed.app.server
```

---

## Verified Test & Benchmark Results

| Check | Scope | Result |
|---|---|---|
| `masking/tests/test_pii_masking.py` | PII redaction (emails, JWTs, Luhn cards, SSNs, secrets), non-mutation, store & routes | **5 / 5 passed** |
| `testbed/tests/test_testbed.py` | OpenAPI spec shadow omission, BOLA/BFLA endpoints, attack suite, `< 5 ms` SLA | **4 / 4 passed** |
| `testbed.attacks.run_suite` | Baseline + BOLA + BFLA + Shadow + Zombie + Coupon burst | **41 requests, 11 findings, 13 endpoints** |
| `testbed.benchmarks.latency_audit` | 300 iterations (`p95` overhead vs `5.0 ms` SLA) | **p95 = 0.0584 ms (SLA Passed)** |
| `dashboard` (`npm run build`) | Production Vite + React bundle (`dist/`) | **Built cleanly in 3.04s** |
