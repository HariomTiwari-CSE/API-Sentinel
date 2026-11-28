"""Synthetic labelled traffic against a deliberately BOLA-vulnerable fake API.

Contains: 8 benign shoppers (one uses deep links), an admin, a BOLA attacker that
enumerates order IDs, and a BFLA attacker that calls admin functions.
"""
from __future__ import annotations

import random

BENIGN_USERS = ["alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi"]


def generate(seed: int = 7) -> list[dict]:
    rng = random.Random(seed)
    ips = {u: f"10.0.0.{11 + i}" for i, u in enumerate(BENIGN_USERS)}
    ips.update({"mallory": "203.0.113.50", "trudy": "198.51.100.77", "root": "10.0.9.1"})

    orders: dict[int, str] = {}
    next_id = 1001
    for user in BENIGN_USERS:  # 1001-1024
        for _ in range(3):
            orders[next_id] = user
            next_id += 1
    
    for _ in range(2):  # 1025-1026
        orders[next_id] = "mallory"
        next_id += 1
    for _ in range(4):  # 1027-1030 belong to a user who never appears in traffic
        orders[next_id] = "ghost"
        next_id += 1
    created_id = [1041]  # 1031-1040 do not exist

    events: list[dict] = []

    def emit(ts, user, role, method, path, status, resp=None, label="benign", req=None):
        events.append(
            {
                "ts": round(ts, 3), "user": user, "method": method, "path": path,
                "status": status, "req_body": req, "resp_body": resp,
                "latency_ms": round(rng.uniform(8, 40), 1),
                "src_ip": ips[user], "role": role, "label": label,
            }
        )
