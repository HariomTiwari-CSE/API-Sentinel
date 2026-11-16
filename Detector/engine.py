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

class DetectorEngine:
    def __init__(self, sink: BlocklistSink | None = None, config: EngineConfig | None = None):
        self.config = config or EngineConfig()
        self.ownership = OwnershipMap()
        self.bola = BolaDetector(self.ownership, self.config.bola)
        self.bfla = BflaDetector(self.config.bfla)
        self.verdicts = VerdictEngine(sink, self.config.verdict)
        self._seen = 0

    def process(self, rec: Record) -> list[Finding]:
        self._seen += 1
        if self._seen <= self.config.learning_records:
            self.bola.learn_only(rec)
            self.bfla.learn_only(rec)
            return []
        findings = self.bola.inspect(rec) + self.bfla.inspect(rec)
        return [self.verdicts.decide(f) for f in findings]

    def process_stream(self, records: Iterable[Record]) -> Iterator[Finding]:
        for rec in records:
            yield from self.process(rec)
