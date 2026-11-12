"""Authentication and user identity extraction utilities.

The HTTP parser extracts identity information (user identifier and role claim)
from HTTP headers (such as JWT Bearer tokens or API keys) to populate the
`user` and `role` fields of the output `Record`.
"""

from __future__ import annotations

import base64
import json
import logging
from typing import Any

logger = logging.getLogger(__name__)

DEFAULT_ANONYMOUS_USER = "anonymous"
DEFAULT_USER_ROLE = "user"


def _decode_jwt_payload(token: str) -> dict[str, Any]:
    """Safely decode the JSON payload from an unverified JWT string.

    Note: Signature verification is out of scope for the traffic parser;
    we inspect the claims (e.g. sub, user, role) for behavioral telemetry.
    """
    parts = token.strip().split(".")
    if len(parts) < 2:
        return {}
    payload_b64 = parts[1]
    # Add base64 padding if needed
    remainder = len(payload_b64) % 4
    if remainder > 0:
        payload_b64 += "=" * (4 - remainder)
    try:
        decoded_bytes = base64.urlsafe_b64decode(payload_b64)
        return json.loads(decoded_bytes.decode("utf-8", errors="replace"))
    except Exception as exc:
        logger.debug("Failed to decode JWT payload: %s", exc)
        return {}


def extract_identity_and_role(
    headers: dict[str, str],
    default_user: str = DEFAULT_ANONYMOUS_USER,
    default_role: str = DEFAULT_USER_ROLE,
) -> tuple[str, str]:
    """Extract user identifier and role from HTTP headers.

    Inspects:
    1. 'Authorization' header: Bearer JWT tokens.
    2. 'X-API-Key', 'API-Key', 'X-User-ID', 'X-Auth-Token' headers.

    Returns:
        tuple[str, str]: (user_id, role)
    """
    if not headers:
        return default_user, default_role

    # Normalize header keys to lowercase
    norm_headers = {k.lower(): v for k, v in headers.items()}

    # 1. Check Authorization Bearer JWT
    auth_header = norm_headers.get("authorization", "")
    if auth_header.lower().startswith("bearer "):
        token = auth_header[7:].strip()
        claims = _decode_jwt_payload(token)
        if claims:
            user = (
                claims.get("sub")
                or claims.get("user")
                or claims.get("username")
                or claims.get("user_id")
                or claims.get("email")
                or default_user
            )
            role = (
                claims.get("role")
                or claims.get("roles")
                or claims.get("scope")
                or default_role
            )
            if isinstance(role, list):
                role = role[0] if role else default_role
            return str(user), str(role)

    # 2. Check direct user ID headers
    for user_header in ("x-user-id", "x-user", "x-username"):
        if user_header in norm_headers and norm_headers[user_header].strip():
            user = norm_headers[user_header].strip()
            role = norm_headers.get("x-user-role", norm_headers.get("x-role", default_role))
            return user, role

    # 3. Check API Key headers
    for key_header in ("x-api-key", "api-key", "x-auth-token"):
        if key_header in norm_headers and norm_headers[key_header].strip():
            api_key = norm_headers[key_header].strip()
            # Return truncated/sanitized key identifier as the user identity
            key_id = f"key_{api_key[:8]}" if len(api_key) > 8 else f"key_{api_key}"
            role = norm_headers.get("x-role", default_role)
            return key_id, role

    return default_user, default_role
