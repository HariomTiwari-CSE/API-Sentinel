# `testbed/` — crAPI Target Application, Attacks & Benchmarks

Provides the vulnerable API target, official OpenAPI contract, scripted attack simulations, and `< 5 ms` latency audit for API-Sentinel.

## Key Files
- `app/server.py`: Lightweight crAPI-compatible Flask microservice (`python -m testbed.app.server`, port `8888`) with intentional OWASP API1 (BOLA), API4 (unthrottled coupons), API5 (BFLA admin routes), and API9 (Shadow & Zombie APIs).
- `docker-compose.crapi.yml`: Containerized OWASP crAPI stack for Linux/eBPF integration testing.
- `openapi.yaml`: Official OpenAPI 3.0 contract used by `discovery/` (intentionally omits Shadow & Zombie routes).
- `attacks/`: `bola_enum.py`, `bfla_and_shadow.py`, and `run_suite.py` generating Parser/Detector-compatible JSONL traffic and masked findings.
- `benchmarks/latency_audit.py`: Verifies added masking/pipeline overhead remains below `5.0 ms` (`p95`).
