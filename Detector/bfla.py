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
