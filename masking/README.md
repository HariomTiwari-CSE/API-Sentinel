# `masking/` — PII Masking & Telemetry Bridge

Strips sensitive user data and credentials from API-Sentinel `Record` payloads and `Finding` alerts before storage or dashboard rendering.

## Key Files
- `pii.py`: `PIIMasker` and `MaskingConfig` supporting email partial masking (`a***@domain`), Luhn-validated credit card masking (`****-****-****-1234`), SSNs, JWTs (`[REDACTED_JWT]`), API keys, passwords, phones, and addresses without mutating caller objects.
- `server.py`: FastAPI REST & WebSocket service (`uvicorn masking.server:app --port 8000`) exposing `/api/findings`, `/api/ingest/finding`, `/api/ingest/record`, `/api/inventory`, `/api/owasp`, `/api/stats`, `/api/mask/preview`, and `/ws/findings`.
- `tests/test_pii_masking.py`: Unit and FastAPI route verification tests.
