"""API-Sentinel HTTP Parser Module."""

from parser.auth import extract_identity_and_role
from parser.base import BaseHTTPParser
from parser.models import (
    ConnectionKey,
    ParsedHTTPRequest,
    ParsedHTTPResponse,
    RawFragment,
    Record,
    TrafficDirection,
)
from parser.reassembler import ConnectionState
from parser.request import CaseInsensitiveDict, RequestParseResult, parse_all_requests, parse_http_request

__version__ = "0.2.0"
__author__ = "Prince Kumar"
__module__ = "parser"

__all__ = [
    "BaseHTTPParser",
    "CaseInsensitiveDict",
    "ConnectionKey",
    "ConnectionState",
    "ParsedHTTPRequest",
    "ParsedHTTPResponse",
    "RawFragment",
    "Record",
    "RequestParseResult",
    "TrafficDirection",
    "extract_identity_and_role",
    "parse_all_requests",
    "parse_http_request",
]
