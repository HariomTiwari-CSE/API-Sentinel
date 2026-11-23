"""BFLA (OWASP API5) detection: a caller using a function their role may not use.

Two sources of truth:
  1. explicit rules (e.g. /admin/** requires role admin)
  2. learned privilege: an endpoint only ever used successfully by privileged
     roles is treated as privileged once enough samples exist.
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from .models import Finding, Record
from .normalize import parse_path


@dataclass(frozen=True)
class Rule:
    pattern: str  # regex matched against the path template
    allowed_roles: frozenset
    methods: frozenset | None = None  # None = any method

    def matches(self, method: str, template: str) -> bool:
        if self.methods is not None and method not in self.methods:
            return False
        return re.search(self.pattern, template) is not None
DEFAULT_RULES = (
    Rule(r"^/(?:api/)?(?:v\d+/)?admin(?:/|$)", frozenset({"admin"})),
    Rule(r"^/(?:api/)?(?:v\d+/)?internal(?:/|$)", frozenset({"service", "admin"})),
)


@dataclass
class BflaConfig:
    rules: tuple = DEFAULT_RULES
    privileged_roles: frozenset = frozenset({"admin"})
    learn_privileged: bool = True
    min_samples: int = 3


class BflaDetector:
    def __init__(self, config: BflaConfig | None = None):
        self.config = config or BflaConfig()
        self._roles_seen: dict[tuple[str, str], Counter] = defaultdict(Counter)

    def learn_only(self, rec: Record) -> None:
        if rec.ok:
            info = parse_path(rec.path)
            self._roles_seen[(rec.method, info.template)][rec.role] += 1

    def inspect(self, rec: Record) -> list[Finding]:
        cfg = self.config
        info = parse_path(rec.path)
        key = (rec.method, info.template)
        reason = None
