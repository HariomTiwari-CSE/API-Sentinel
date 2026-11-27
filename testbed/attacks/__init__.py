"""Attack simulation and baseline traffic generators for API-Sentinel testbed.

Modules:
- common         : TrafficSession helper emitting Record-compatible JSONL
- bola_enum      : Scripted BOLA sequential ID enumeration (OWASP API1)
- bfla_and_shadow: BFLA privilege escalation, Shadow/Zombie API, coupon brute-force
- run_suite      : End-to-end pipeline combining all attacks with PII masking
"""
