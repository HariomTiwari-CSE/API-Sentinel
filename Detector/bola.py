"""BOLA (OWASP API1) detection.

Core rule: a user may only touch object IDs the server itself handed to that
user (list responses, create responses, detail responses). A request for any
other ID is suspicious, and more so if the ID is known to belong to someone else.
"""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass

from .models import Finding, Record
from .normalize import parse_path
from .ownership import OwnershipMap

FAIL_STATUSES = frozenset({401, 403, 404})
LEARN_METHODS = frozenset({"GET", "POST"})


@dataclass
class BolaConfig:
    enum_distinct_threshold: int = 5  # distinct unauthorized IDs within the window
    enum_window_s: float = 60.0
    sequential_run: int = 4  # consecutive numeric IDs (1001, 1002, ...)
    fail_threshold: int = 5  # 401/403/404 on unauthorized IDs within the window
    public_owner_threshold: int = 5  # IDs seen by this many users are treated as public
    public_resources: frozenset = frozenset({"products", "categories"})
    privileged_roles: frozenset = frozenset({"admin"})
    learn_unowned_first_touch: bool = False  # accept deep links to never-seen IDs
