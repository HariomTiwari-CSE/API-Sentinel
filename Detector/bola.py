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

class BolaDetector:
    def __init__(self, ownership: OwnershipMap | None = None, config: BolaConfig | None = None):
        self.ownership = ownership if ownership is not None else OwnershipMap()
        self.config = config or BolaConfig()
        self._attempts: dict[tuple[str, str], deque] = defaultdict(deque)

    # -- learning --------------------------------------------------------
    def learn_only(self, rec: Record) -> None:
        """Warm-up mode: learn ownership from any successful response, flag nothing."""
        if rec.ok and rec.method in LEARN_METHODS:
            info = parse_path(rec.path)
            if info.learn_resource:
                self.ownership.learn_response(rec.user, info.learn_resource, rec.resp_body)
 
    # -- detection -------------------------------------------------------
    def inspect(self, rec: Record) -> list[Finding]:
        cfg = self.config
        info = parse_path(rec.path)

        # Collection endpoints (list / create): the server decides what the user gets.
        if info.object_id is None:
            if rec.ok and rec.method in LEARN_METHODS and info.learn_resource:
                self.ownership.learn_response(rec.user, info.learn_resource, rec.resp_body)
            return []

        resource, oid = info.resource, info.object_id
        if rec.role in cfg.privileged_roles or resource in cfg.public_resources:
            return []

        if self.ownership.is_authorized(rec.user, resource, oid):
            if rec.ok and rec.method == "GET" and info.learn_resource:
                self.ownership.learn_response(rec.user, info.learn_resource, rec.resp_body)
            return []

        owners = self.ownership.owners(resource, oid) - {rec.user}
        if len(owners) >= cfg.public_owner_threshold:
            return []
       
        
        # Unauthorized access. Never learn from this response, otherwise a
        # successful attack would authorize itself on the next request.
        queue = self._attempts[(rec.user, resource)]
        queue.append((rec.ts, oid, rec.status))
        cutoff = rec.ts - cfg.enum_window_s
        while queue and queue[0][0] < cutoff:
            queue.popleft()
        distinct, run, failures = self._stats(queue)
        enumeration = (
            distinct >= cfg.enum_distinct_threshold
            or run >= cfg.sequential_run
            or failures >= cfg.fail_threshold
        )

        if not owners and rec.ok and cfg.learn_unowned_first_touch and not enumeration:
            if info.learn_resource:
                self.ownership.learn_response(rec.user, info.learn_resource, rec.resp_body)
            return []

        if owners and rec.ok:
            severity, reason = "critical", "object_issued_to_other_user"
        elif enumeration:
            severity, reason = "high", "id_enumeration"
        elif owners:
            severity, reason = "medium", "other_user_object_denied"
        elif rec.ok:
            severity, reason = "low", "unseen_object_accessed"
        else:
            return []
        
        return [
            Finding(
                type="BOLA",
                owasp="API1",
                user=rec.user,
                src_ip=rec.src_ip,
                endpoint=f"{rec.method} {info.template}",
                severity=severity,
                action="alert",
                reason=reason,
                ts=rec.ts,
                evidence={
                    "resource": resource,
                    "object_id": oid,
                    "status": rec.status,
                    "owner_count": len(owners),
                    "distinct_ids": distinct,
                    "sequential_run": run,
                    "failures": failures,
                    "enumeration": enumeration,
                },
            )
        ]

    @staticmethod
    def _stats(queue) -> tuple[int, int, int]:
        ids = {oid for _, oid, _ in queue}
        failures = sum(1 for _, _, status in queue if status in FAIL_STATUSES)
        numbers = sorted({int(i) for i in ids if i.isdigit()})
        run = best = 0
        previous = None
        for n in numbers:
            run = run + 1 if previous is not None and n == previous + 1 else 1
            best = max(best, run)
            previous = n
        return len(ids), best, failures
