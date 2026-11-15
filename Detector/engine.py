"""DetectorEngine: one entry point that runs every detector and the verdict step."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Iterator

from .bfla import BflaConfig, BflaDetector
from .bola import BolaConfig, BolaDetector
from .models import Finding, Record
from .ownership import OwnershipMap
from .verdict import BlocklistSink, VerdictConfig, VerdictEngine


@dataclass
class EngineConfig:
    learning_records: int = 0  # first N records only teach, nothing is flagged
    bola: BolaConfig = field(default_factory=BolaConfig)
    bfla: BflaConfig = field(default_factory=BflaConfig)
    verdict: VerdictConfig = field(default_factory=VerdictConfig)
