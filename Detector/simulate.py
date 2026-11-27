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
