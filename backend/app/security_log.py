"""Append-only security log for memory poisoning attempts."""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_lock = threading.Lock()


def log_poisoning_attempt(data_dir: Path, payload: dict[str, Any]) -> None:
    data_dir.mkdir(parents=True, exist_ok=True)
    path = data_dir / "security_log.jsonl"
    row = {
        "ts": datetime.now(timezone.utc).isoformat(),
        **payload,
    }
    line = json.dumps(row, ensure_ascii=False) + "\n"
    with _lock:
        path.open("a", encoding="utf-8").write(line)


def count_poisoning_attempts(data_dir: Path) -> int:
    path = data_dir / "security_log.jsonl"
    if not path.is_file():
        return 0
    with path.open("r", encoding="utf-8") as f:
        return sum(1 for _ in f)
