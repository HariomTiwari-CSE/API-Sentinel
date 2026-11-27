# `dashboard/` — React Threat & OWASP Dashboard

React + Vite security operations dashboard for API-Sentinel.

## Features
- **Overview**: Real-time KPIs (active alerts, XDP block verdicts, API surface, PII fields masked, `p95` overhead) and OWASP risk distribution.
- **Live Alerts**: Filterable table with severity, OWASP category, verdict (`alert`/`block`), and inspectable masked evidence drawer.
- **Endpoint Inventory**: Tracks `documented`, `shadow`, and `zombie` APIs with hit counts and average latency.
- **OWASP Top 10 Matrix**: Maps active detections to OWASP API Security Top 10 (2023/2026) with remediation guidance.
- **PII Masking Sandbox & SLA**: Interactive payload masker tester and latency benchmark table.

## Run
```bash
npm install
npm run dev
```
