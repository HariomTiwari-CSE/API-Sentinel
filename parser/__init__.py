"""API-Sentinel HTTP Parser Module.

Reconstructs raw network fragments delivered from the kernel eBPF sensor and Rust agent
into complete HTTP requests and responses, matches transactions, extracts caller identity,
and emits normalized records for downstream security analysis engines.
"""

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

__version__ = "0.1.0"
__author__ = "Prince Kumar"
__module__ = "parser"

__all__ = [
    "BaseHTTPParser",
    "ConnectionKey",
    "ConnectionState",
    "ParsedHTTPRequest",
    "ParsedHTTPResponse",
    "RawFragment",
    "Record",
    "TrafficDirection",
    "extract_identity_and_role",
]
