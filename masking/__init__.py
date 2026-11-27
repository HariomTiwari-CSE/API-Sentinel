"""API-Sentinel PII Masking & Telemetry Bridge (`masking/`).

Owned by Meet (Contributor 5).
Strips Personally Identifiable Information (PII) and credentials from
detection findings and captured traffic records before they reach the dashboard.
"""

from .pii import MaskingConfig, MaskingResult, PIIMasker

__all__ = ["MaskingConfig", "MaskingResult", "PIIMasker"]
