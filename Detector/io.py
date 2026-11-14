"""JSONL helpers. Each line is a Record; an optional "label" field marks ground truth."""
from __future__ import annotations

import json

from .models import Record


def load_jsonl(path: str) -> list[tuple[Record, str]]:
    items = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                data = json.loads(line)
                items.append((Record.from_dict(data), data.get("label", "benign")))
    return items


def dump_jsonl(rows: list[dict], path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")
