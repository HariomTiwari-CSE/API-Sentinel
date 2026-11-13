"""Abstract base class and interface definition for HTTP parsers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

from parser.models import RawFragment, Record, TrafficDirection


class BaseHTTPParser(ABC):
    """Abstract interface defining the HTTP stream parser contract."""

    @abstractmethod
    def feed_fragment(self, fragment: RawFragment) -> list[Record]:
        """Process a single raw fragment and return any completed HTTP records."""
        raise NotImplementedError

    def feed_raw(
        self,
        connection_id: str,
        ts: float,
        direction: str | TrafficDirection,
        payload: bytes | str,
    ) -> list[Record]:
        """Convenience wrapper to feed raw fragment attributes directly."""
        dir_enum = (
            direction
            if isinstance(direction, TrafficDirection)
            else TrafficDirection.from_str(str(direction))
        )
        payload_bytes = (
            payload
            if isinstance(payload, bytes)
            else payload.encode("utf-8", errors="replace")
        )
        fragment = RawFragment(
            connection_id=connection_id,
            ts=ts,
            direction=dir_enum,
            payload=payload_bytes,
        )
        return self.feed_fragment(fragment)

    @abstractmethod
    def reset(self, connection_id: Optional[str] = None) -> None:
        """Clear buffered state for a specific connection or all connections."""
        raise NotImplementedError

    @abstractmethod
    def active_connections(self) -> list[str]:
        """Return list of active connection IDs currently holding buffered data."""
        raise NotImplementedError
