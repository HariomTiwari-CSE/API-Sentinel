"""Core HTTP/1.x Request Parsing Engine.

Handles:
- Request-line parsing: method, URI/path, HTTP version.
- Case-insensitive HTTP header parsing.
- Content-Length and chunked Transfer-Encoding request body parsing.
- Safe JSON body decoding.
- Fault-tolerant handling of incomplete, malformed, and empty requests.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from typing import Any, Iterator, Optional

from parser.models import ParsedHTTPRequest

logger = logging.getLogger(__name__)

# Valid standard HTTP methods conforming to RFC 7231 / 5789
STANDARD_HTTP_METHODS = {
    "GET", "POST", "PUT", "DELETE", "PATCH",
    "HEAD", "OPTIONS", "TRACE", "CONNECT"
}

# Regex to validate HTTP method token characters
METHOD_TOKEN_REGEX = re.compile(r"^[A-Za-z0-9!#$%&'*+\-.^_`|~]+$")


class CaseInsensitiveDict(dict):
    """A dictionary with case-insensitive string keys that preserves original casing."""

    def __init__(self, *args, **kwargs):
        super().__init__()
        self._keys: dict[str, str] = {}
        self.update(*args, **kwargs)

    def __setitem__(self, key: str, value: Any) -> None:
        key_str = str(key)
        lower = key_str.lower()
        self._keys[lower] = key_str
        super().__setitem__(lower, value)

    def __getitem__(self, key: str) -> Any:
        return super().__getitem__(str(key).lower())

    def __contains__(self, key: object) -> bool:
        if isinstance(key, str):
            return super().__contains__(key.lower())
        return False

    def get(self, key: str, default: Any = None) -> Any:
        return super().get(str(key).lower(), default)

    def __delitem__(self, key: str) -> None:
        lower = str(key).lower()
        if lower in self._keys:
            del self._keys[lower]
        super().__delitem__(lower)

    def pop(self, key: str, default: Any = ...) -> Any:
        lower = str(key).lower()
        if lower in self._keys:
            del self._keys[lower]
        if default is ...:
            return super().pop(lower)
        return super().pop(lower, default)

    def update(self, *args, **kwargs) -> None:
        if args:
            other = args[0]
            if isinstance(other, dict):
                for k, v in other.items():
                    self[k] = v
            else:
                for k, v in other:
                    self[k] = v
        for k, v in kwargs.items():
            self[k] = v

    def items(self):
        for lower_k, v in super().items():
            orig_k = self._keys.get(lower_k, lower_k)
            yield orig_k, v

    def keys(self):
        for lower_k in super().keys():
            yield self._keys.get(lower_k, lower_k)

    def __iter__(self):
        for lower_k in super().__iter__():
            yield self._keys.get(lower_k, lower_k)

    def copy(self) -> "CaseInsensitiveDict":
        new_dict = CaseInsensitiveDict()
        for k, v in self.items():
            orig_k = self._keys.get(k, k)
            new_dict[orig_k] = v
        return new_dict


@dataclass(frozen=True)
class RequestParseResult:
    """Result of attempting to parse an HTTP request from a byte buffer."""

    request: Optional[ParsedHTTPRequest]
    bytes_consumed: int
    is_complete: bool
    error: Optional[str] = None

    def __iter__(self) -> Iterator[Any]:
        """Support unpacking like a tuple: request, bytes_consumed = parse_http_request(buf)."""
        yield self.request
        yield self.bytes_consumed


def _find_header_boundary(buf: bytes) -> tuple[int, int]:
    """Find the boundary between HTTP headers and body.

    Returns:
        tuple[int, int]: (header_end_offset, body_start_offset).
        If not found, returns (-1, -1).
    """
    crlf_pos = buf.find(b"\r\n\r\n")
    if crlf_pos != -1:
        return crlf_pos, crlf_pos + 4

    lf_pos = buf.find(b"\n\n")
    if lf_pos != -1:
        return lf_pos, lf_pos + 2

    return -1, -1


def _decode_chunked_body(payload: bytes) -> tuple[Optional[bytes], int, bool, Optional[str]]:
    """Decode a chunked transfer encoded payload.

    Returns:
        tuple: (decoded_bytes, wire_bytes_consumed, is_complete, error_str)
    """
    offset = 0
    body_chunks: list[bytes] = []

    while offset < len(payload):
        line_end = payload.find(b"\r\n", offset)
        delim_len = 2
        if line_end == -1:
            line_end = payload.find(b"\n", offset)
            delim_len = 1
            if line_end == -1:
                return None, 0, False, None  # Incomplete chunk header

        size_line = payload[offset:line_end].strip()
        if b";" in size_line:
            size_line = size_line.split(b";", 1)[0].strip()

        try:
            chunk_size = int(size_line, 16)
        except ValueError:
            return None, 0, False, f"Invalid chunk size hex: {size_line!r}"

        offset = line_end + delim_len

        # Final chunk of size 0 marks completion
        if chunk_size == 0:
            if offset + delim_len <= len(payload):
                end_pos = payload.find(b"\r\n\r\n", line_end)
                if end_pos != -1:
                    return b"".join(body_chunks), end_pos + 4, True, None
                lf_end = payload.find(b"\n\n", line_end)
                if lf_end != -1:
                    return b"".join(body_chunks), lf_end + 2, True, None
                if payload[offset:].startswith(b"\r\n"):
                    return b"".join(body_chunks), offset + 2, True, None
                if payload[offset:].startswith(b"\n"):
                    return b"".join(body_chunks), offset + 1, True, None
            return None, 0, False, None

        if len(payload) < offset + chunk_size:
            return None, 0, False, None  # Incomplete chunk body

        body_chunks.append(payload[offset : offset + chunk_size])
        offset += chunk_size

        if offset + 2 <= len(payload) and payload[offset : offset + 2] == b"\r\n":
            offset += 2
        elif offset + 1 <= len(payload) and payload[offset : offset + 1] == b"\n":
            offset += 1
        else:
            return None, 0, False, None

    return None, 0, False, None


def _decode_body_content(raw_bytes: bytes, content_type: str) -> Any:
    """Decode raw request body bytes into JSON, text, or keep raw."""
    if not raw_bytes:
        return None

    ct = content_type.lower()
    text = None
    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = raw_bytes.decode("latin-1")
        except Exception:
            return raw_bytes

    is_json_type = (
        "application/json" in ct
        or "+json" in ct
        or "application/problem+json" in ct
    )
    should_try_json = is_json_type or (text and text.lstrip().startswith(("{", "[")))

    if should_try_json and text:
        try:
            return json.loads(text.strip())
        except (json.JSONDecodeError, ValueError):
            return text

    return text if text is not None else raw_bytes


def parse_http_request(
    data: bytes | str | bytearray,
    ts: float = 0.0,
    src_ip: str = "",
    src_port: int = 0,
    dst_ip: str = "",
    dst_port: int = 0,
) -> RequestParseResult:
    """Parse a single HTTP/1.x request from a raw byte buffer."""
    if not data:
        return RequestParseResult(request=None, bytes_consumed=0, is_complete=False)

    if isinstance(data, str):
        buf = data.encode("utf-8", errors="replace")
    elif isinstance(data, bytearray):
        buf = bytes(data)
    else:
        buf = data

    # 1. Find end of headers
    header_end, body_start = _find_header_boundary(buf)
    if header_end == -1:
        first_line_end = buf.find(b"\r\n")
        if first_line_end == -1:
            first_line_end = buf.find(b"\n")

        if first_line_end != -1:
            first_line = buf[:first_line_end].decode("latin-1", errors="replace").strip()
            parts = first_line.split()
            if not parts or parts[0].upper() not in STANDARD_HTTP_METHODS:
                if not any(buf.startswith(m.encode()) for m in STANDARD_HTTP_METHODS):
                    return RequestParseResult(
                        request=None,
                        bytes_consumed=len(buf),
                        is_complete=False,
                        error=f"Malformed request line: {first_line!r}",
                    )
        return RequestParseResult(request=None, bytes_consumed=0, is_complete=False)

    # 2. Extract and parse header lines
    headers_bytes = buf[:header_end]
    headers_text = headers_bytes.decode("latin-1", errors="replace")
    lines = re.split(r"\r\n|\n", headers_text)

    if not lines or not lines[0].strip():
        return RequestParseResult(
            request=None,
            bytes_consumed=body_start,
            is_complete=False,
            error="Empty request line",
        )

    # 3. Parse Request-Line: METHOD PATH HTTP_VERSION
    request_line = lines[0].strip()
    tokens = request_line.split()

    if len(tokens) == 2:
        method, path = tokens
        http_version = "HTTP/1.1"
    elif len(tokens) >= 3:
        method = tokens[0]
        http_version = tokens[-1]
        path = " ".join(tokens[1:-1])
    else:
        return RequestParseResult(
            request=None,
            bytes_consumed=body_start,
            is_complete=False,
            error=f"Malformed request line token count: {request_line!r}",
        )

    method = method.upper()
    if not METHOD_TOKEN_REGEX.match(method):
        return RequestParseResult(
            request=None,
            bytes_consumed=body_start,
            is_complete=False,
            error=f"Invalid HTTP method token: {method!r}",
        )

    # 4. Parse Header Lines into CaseInsensitiveDict
    headers = CaseInsensitiveDict()
    for line in lines[1:]:
        line = line.strip()
        if not line:
            continue
        if ":" in line:
            name, value = line.split(":", 1)
            name = name.strip()
            value = value.strip()
            if name in headers:
                headers[name] = f"{headers[name]}, {value}"
            else:
                headers[name] = value

    # 5. Determine Body Boundaries and Transfer Encoding
    available_body = buf[body_start:]
    transfer_encoding = headers.get("transfer-encoding", "").lower()

    if "chunked" in transfer_encoding:
        chunk_body, wire_consumed, is_complete, chunk_err = _decode_chunked_body(available_body)
        if chunk_err:
            return RequestParseResult(
                request=None,
                bytes_consumed=body_start,
                is_complete=False,
                error=f"Chunked encoding error: {chunk_err}",
            )
        if not is_complete:
            return RequestParseResult(request=None, bytes_consumed=0, is_complete=False)

        raw_body_bytes = chunk_body or b""
        total_consumed = body_start + wire_consumed

    elif "content-length" in headers:
        cl_str = headers.get("content-length", "").strip()
        try:
            content_length = int(cl_str)
            if content_length < 0:
                raise ValueError("Negative Content-Length")
        except ValueError:
            return RequestParseResult(
                request=None,
                bytes_consumed=body_start,
                is_complete=False,
                error=f"Invalid Content-Length header: {cl_str!r}",
            )

        if len(available_body) < content_length:
            return RequestParseResult(request=None, bytes_consumed=0, is_complete=False)

        raw_body_bytes = available_body[:content_length]
        total_consumed = body_start + content_length

    else:
        raw_body_bytes = b""
        total_consumed = body_start

    # 6. Decode Body (JSON, text, or None)
    content_type = headers.get("content-type", "")
    decoded_body = _decode_body_content(raw_body_bytes, content_type)

    # 7. Construct ParsedHTTPRequest with CaseInsensitiveDict headers
    parsed_req = ParsedHTTPRequest(
        method=method,
        path=path,
        http_version=http_version,
        headers=headers,
        body=decoded_body,
        ts=ts,
        src_ip=src_ip,
        src_port=src_port,
        dst_ip=dst_ip,
        dst_port=dst_port,
    )

    return RequestParseResult(
        request=parsed_req,
        bytes_consumed=total_consumed,
        is_complete=True,
        error=None,
    )


def parse_all_requests(
    data: bytes | str | bytearray,
    ts: float = 0.0,
    src_ip: str = "",
    src_port: int = 0,
    dst_ip: str = "",
    dst_port: int = 0,
) -> list[ParsedHTTPRequest]:
    """Parse multiple pipelined or consecutive requests from a single buffer."""
    buf = (
        data.encode("utf-8", errors="replace")
        if isinstance(data, str)
        else bytes(data)
    )
    requests: list[ParsedHTTPRequest] = []
    offset = 0

    while offset < len(buf):
        remaining = buf[offset:]
        result = parse_http_request(
            remaining,
            ts=ts,
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
        )
        if not result.is_complete or result.request is None or result.bytes_consumed <= 0:
            break
        requests.append(result.request)
        offset += result.bytes_consumed

    return requests
