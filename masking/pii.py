"""PII & credential redaction engine for API-Sentinel findings and records."""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass, field
from typing import Any

_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b")
_BEARER_RE = re.compile(r"\b(Bearer\s+)[A-Za-z0-9._~+/=-]{10,}", re.IGNORECASE)
_API_KEY_RE = re.compile(r"\b(?:sk|pk|rk|ghp|gho|glpat|AKIA)[A-Za-z0-9_-]{12,}\b")
_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_EMAIL_RE = re.compile(r"\b([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
_CARD_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
_PHONE_RE = re.compile(
    r"(?<!\w)(?:\+?\d{1,3}[-.\s])?(?:\(\d{3}\)|\d{3})[-.\s]\d{3}[-.\s]\d{4}(?!\w)"
)
_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)

_SECRET_KEYS = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "passphrase",
        "secret",
        "client_secret",
        "token",
        "access_token",
        "refresh_token",
        "id_token",
        "jwt",
        "authorization",
        "auth_header",
        "api_key",
        "apikey",
        "x-api-key",
        "cookie",
        "set-cookie",
        "session_id",
        "private_key",
        "pin",
        "otp",
        "cvv",
        "cvc",
    }
)

_CARD_KEYS = frozenset({"credit_card", "card_number", "cc_number", "pan", "card"})
_SSN_KEYS = frozenset({"ssn", "social_security", "social_security_number", "vin"})
_EMAIL_KEYS = frozenset({"email", "user_email", "mail", "contact_email"})
_PHONE_KEYS = frozenset({"phone", "phone_number", "mobile", "number", "tel"})
_ADDRESS_KEYS = frozenset({"address", "home_address", "street", "street_address"})


def _luhn_valid(digits: str) -> bool:
    """Validate candidate card numbers with Luhn to avoid masking normal IDs."""
    if not (13 <= len(digits) <= 19) or not digits.isdigit():
        return False
    total = 0
    reverse_digits = digits[::-1]
    for idx, ch in enumerate(reverse_digits):
        n = int(ch)
        if idx % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def _mask_email_match(match: re.Match[str]) -> str:
    local, domain = match.group(1), match.group(2)
    prefix = local[0] if local else "*"
    return f"{prefix}***@{domain}"


@dataclass(frozen=True)
class MaskingConfig:
    """Controls which PII and credential classes are redacted."""

    mask_emails: bool = True
    mask_phones: bool = True
    mask_cards: bool = True
    mask_ssns: bool = True
    mask_jwts: bool = True
    mask_secrets: bool = True
    mask_addresses: bool = True
    mask_ips_in_payloads: bool = False
    mask_user_emails: bool = True


@dataclass
class MaskingResult:
    """Sanitized output alongside redaction audit counts (no raw PII stored)."""

    data: Any
    redactions: int = 0
    categories: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "data": self.data,
            "redactions": self.redactions,
            "categories": dict(self.categories),
        }


class PIIMasker:
    """Redacts PII and credentials from API-Sentinel records and findings."""

    def __init__(self, config: MaskingConfig | None = None) -> None:
        self.config = config or MaskingConfig()

    def mask_record(self, record: dict[str, Any]) -> MaskingResult:
        """Return a sanitized copy of a Parser `Record` dictionary."""
        cloned = copy.deepcopy(record)
        counts: dict[str, int] = {}

        if self.config.mask_user_emails and isinstance(cloned.get("user"), str):
            cloned["user"] = self._mask_text(cloned["user"], counts, allow_ip=False)

        for field_name in ("path", "req_body", "resp_body"):
            if field_name in cloned and cloned[field_name] is not None:
                cloned[field_name] = self._walk(cloned[field_name], counts)

        return MaskingResult(
            data=cloned,
            redactions=sum(counts.values()),
            categories=counts,
        )

    def mask_finding(self, finding: dict[str, Any]) -> MaskingResult:
        """Return a sanitized copy of a Detector/Discovery `Finding` dictionary."""
        cloned = copy.deepcopy(finding)
        counts: dict[str, int] = {}

        if self.config.mask_user_emails and isinstance(cloned.get("user"), str):
            cloned["user"] = self._mask_text(cloned["user"], counts, allow_ip=False)

        for field_name in ("endpoint", "reason", "evidence", "payload", "req_body", "resp_body"):
            if field_name in cloned and cloned[field_name] is not None:
                cloned[field_name] = self._walk(cloned[field_name], counts)

        if self.config.mask_ips_in_payloads and isinstance(cloned.get("src_ip"), str):
            cloned["src_ip"] = self._mask_ip(cloned["src_ip"], counts)

        cloned["pii_masked"] = True
        cloned["redacted_fields"] = sum(counts.values())
        return MaskingResult(
            data=cloned,
            redactions=sum(counts.values()),
            categories=counts,
        )

    def mask_any(self, payload: Any) -> MaskingResult:
        """Sanitize an arbitrary nested structure (dict, list, or string)."""
        counts: dict[str, int] = {}
        sanitized = self._walk(copy.deepcopy(payload), counts)
        return MaskingResult(
            data=sanitized,
            redactions=sum(counts.values()),
            categories=counts,
        )

    def mask_batch(
        self, items: list[dict[str, Any]], kind: str = "finding"
    ) -> tuple[list[dict[str, Any]], dict[str, int]]:
        """Sanitize a list of findings or records and aggregate category counts."""
        out: list[dict[str, Any]] = []
        totals: dict[str, int] = {}
        fn = self.mask_finding if kind == "finding" else self.mask_record
        for item in items:
            res = fn(item)
            out.append(res.data)
            for cat, n in res.categories.items():
                totals[cat] = totals.get(cat, 0) + n
        return out, totals

    # -- internals -------------------------------------------------------

    def _bump(self, counts: dict[str, int], category: str, n: int = 1) -> None:
        if n > 0:
            counts[category] = counts.get(category, 0) + n

    def _walk(self, value: Any, counts: dict[str, int], key_hint: str | None = None) -> Any:
        if isinstance(value, dict):
            return {
                k: self._walk(v, counts, key_hint=str(k).lower().strip())
                for k, v in value.items()
            }
        if isinstance(value, list):
            return [self._walk(item, counts, key_hint=key_hint) for item in value]

        if key_hint:
            if self.config.mask_secrets and key_hint in _SECRET_KEYS and value is not None:
                self._bump(counts, "secret")
                return "[REDACTED_SECRET]"
            if self.config.mask_cards and key_hint in _CARD_KEYS and value is not None:
                text = str(value)
                digits = re.sub(r"\D", "", text)
                self._bump(counts, "credit_card")
                if len(digits) >= 4:
                    return f"****-****-****-{digits[-4:]}"
                return "[REDACTED_CARD]"
            if self.config.mask_ssns and key_hint in _SSN_KEYS and value is not None:
                self._bump(counts, "ssn")
                return "[REDACTED_SSN]"
            if self.config.mask_addresses and key_hint in _ADDRESS_KEYS and isinstance(value, str):
                self._bump(counts, "address")
                return "[REDACTED_ADDRESS]"
            if self.config.mask_phones and key_hint in _PHONE_KEYS and isinstance(value, str):
                self._bump(counts, "phone")
                return "[REDACTED_PHONE]"
            if self.config.mask_emails and key_hint in _EMAIL_KEYS and isinstance(value, str):
                masked = _EMAIL_RE.sub(_mask_email_match, value)
                if masked != value:
                    self._bump(counts, "email")
                    return masked
                self._bump(counts, "email")
                return "[REDACTED_EMAIL]"

        if isinstance(value, str):
            return self._mask_text(value, counts, allow_ip=self.config.mask_ips_in_payloads)
        return value

    def _mask_ip(self, text: str, counts: dict[str, int]) -> str:
        def _repl(match: re.Match[str]) -> str:
            parts = match.group(0).split(".")
            self._bump(counts, "ip_address")
            return f"{parts[0]}.{parts[1]}.x.x"

        return _IPV4_RE.sub(_repl, text)

    def _mask_text(self, text: str, counts: dict[str, int], *, allow_ip: bool) -> str:
        out = text
        if self.config.mask_jwts:
            out, n = _JWT_RE.subn("[REDACTED_JWT]", out)
            self._bump(counts, "jwt", n)
        if self.config.mask_secrets:
            out, n_bearer = _BEARER_RE.subn(r"\1[REDACTED_TOKEN]", out)
            self._bump(counts, "secret", n_bearer)
            out, n_key = _API_KEY_RE.subn("[REDACTED_API_KEY]", out)
            self._bump(counts, "api_key", n_key)
        if self.config.mask_ssns:
            out, n = _SSN_RE.subn("***-**-****", out)
            self._bump(counts, "ssn", n)
        if self.config.mask_cards:
            def _card_repl(match: re.Match[str]) -> str:
                raw = match.group(0)
                digits = re.sub(r"\D", "", raw)
                if _luhn_valid(digits):
                    self._bump(counts, "credit_card")
                    return f"****-****-****-{digits[-4:]}"
                return raw

            out = _CARD_RE.sub(_card_repl, out)
        if self.config.mask_emails:
            out, n = _EMAIL_RE.subn(_mask_email_match, out)
            self._bump(counts, "email", n)
        if self.config.mask_phones:
            out, n = _PHONE_RE.subn("[REDACTED_PHONE]", out)
            self._bump(counts, "phone", n)
        if allow_ip:
            out = self._mask_ip(out, counts)
        return out
