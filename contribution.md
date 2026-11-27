# Contribution: Testbed, PII Masking & Dashboard — Weeks 1-3

**Project:** API-Sentinel, Runtime BOLA and Shadow API Detection Engine  
**Contributor:** Meet (Contributor 5)  
**Modules:** `testbed/`, `masking/`, `dashboard/`  
**Languages:** Python, JavaScript (React)  
**Branch:** `Meet`

---

## 1. Week 1 — Testbed Setup & OpenAPI Contract

### Goal
Stand up the crAPI-compatible target application so the entire team has a shared vulnerable API to test against.

### Deliverables
- Flask crAPI testbed (`testbed/app/server.py`) with 4 user accounts, 5 orders, 3 vehicles, 3 products, and 2 community posts.
- Intentional OWASP vulnerabilities planted:
  - **API1 (BOLA):** `/workshop/api/shop/orders/{id}` and `/identity/api/v2/vehicle/{id}/location` skip ownership checks.
  - **API5 (BFLA):** `/identity/api/v2/admin/users` and `/identity/api/v2/admin/videos` missing role verification.
  - **API4:** `/workshop/api/shop/coupons/validate` has no rate limiting.
  - **API9:** `/api/v1/debug/users` (Shadow) and `/api/v1/orders/export-legacy` (Zombie) are undocumented.
- Official `openapi.yaml` contract intentionally omitting Shadow/Zombie routes for Agam's discovery engine.
- `docker-compose.crapi.yml` for full containerized OWASP crAPI deployment on Linux.

### Exit Criteria
- [x] Testbed responds on port 8888 with all endpoints functional
- [x] OpenAPI spec includes all documented routes, omits shadow/zombie
- [x] BOLA and BFLA vulnerabilities confirmed exploitable

---

## 2. Week 2 — PII Masking Engine & Attack Simulations

### Goal
Build the privacy layer between detectors and dashboard, plus scripted attack proofs against the testbed.

### Deliverables
- `PIIMasker` engine (`masking/pii.py`) redacting emails (`a***@domain`), JWTs, API keys, passwords, Luhn-validated credit cards, SSNs, phones, and addresses.
- Scripted BOLA enumeration attack (`testbed/attacks/bola_enum.py`) — sequential ID sweep + vehicle GPS probe.
- BFLA, Shadow API, Zombie API, and coupon brute-force simulations (`testbed/attacks/bfla_and_shadow.py`).
- End-to-end `run_suite.py` generating 41 requests → 11 findings across 13 endpoints.
- Latency benchmark (`testbed/benchmarks/latency_audit.py`) proving `< 5 ms` SLA (**p95 = 0.058 ms**).
- 9 unit tests (5 masking + 4 testbed), all passing.

### Exit Criteria
- [x] BOLA attack flagged with OWASP API1 category
- [x] BFLA flagged with API5, Shadow/Zombie with API9
- [x] False positives on normal traffic: 0 (Luhn validation prevents order ID masking)
- [x] Masking overhead under 5 ms SLA at p95

---

## 3. Week 3 — React Dashboard & Telemetry Integration

### Goal
Build the SOC-ready React dashboard and FastAPI telemetry gateway connecting all upstream modules.

### Deliverables
- FastAPI + WebSocket gateway (`masking/server.py`) with REST endpoints and real-time finding broadcast.
- `TelemetryStore` with in-memory masked storage and endpoint inventory auto-classification.
- React + Vite dashboard (`dashboard/`) with 5 tabs:
  - **Overview:** KPI cards, OWASP distribution bars, shadow surface snapshot
  - **Live Alerts:** Filterable table with severity/OWASP/verdict filters and evidence drawer
  - **Endpoint Inventory:** Documented / Shadow / Zombie classification with hit counts and latency
  - **OWASP Top 10:** All 10 categories with active counts and remediation guidance
  - **PII Masking & SLA:** Interactive sandbox and latency benchmark results
- Full `README.md` with architecture, contracts, quick start, and verified results.

### Exit Criteria
- [x] Dashboard production build clean (3.04s)
- [x] All 9 tests passing
- [x] Simulate Attack button works in both live and seed modes
- [x] README documents all contracts and test results

---

## 4. Dependencies and Fallbacks

| Needed from | For | Fallback |
|---|---|---|
| Prince (parser/) | Structured Record stream | Local Flask testbed generating Records directly |
| Hariom (detector/) | BOLA/BFLA Finding stream | Scripted attack findings from testbed/attacks/ |
| Agam (discovery/) | Shadow API findings | Hardcoded seed data in dashboard |
| Pranav (sensor/) | Kernel eBPF ring buffer | Docker Compose crAPI stack |
