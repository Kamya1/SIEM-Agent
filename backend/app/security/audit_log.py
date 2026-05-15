"""Tamper-evident append-only audit log for memory and security events."""

from __future__ import annotations

import hashlib
import json
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.config import get_settings

_lock = threading.Lock()


def _log_path() -> Path:
    return get_settings().data_path / "audit_log.jsonl"


def _checksum(event_id: str, timestamp: str, session_id: str, event_type: str) -> str:
    payload = f"{event_id}|{timestamp}|{session_id}|{event_type}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def log_event(session_id: str, event_type: str, details: dict[str, Any] | None = None) -> dict[str, Any]:
    event_id = str(uuid.uuid4())
    ts = datetime.now(timezone.utc).isoformat()
    sid = session_id or "unknown"
    entry = {
        "event_id": event_id,
        "timestamp": ts,
        "session_id": sid,
        "event_type": event_type,
        "details": details or {},
        "checksum": _checksum(event_id, ts, sid, event_type),
    }
    path = _log_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(entry, ensure_ascii=False) + "\n"
    with _lock:
        path.open("a", encoding="utf-8").write(line)
    return entry


def verify_log_integrity() -> dict[str, Any]:
    path = _log_path()
    if not path.is_file():
        return {"total": 0, "valid": 0, "tampered": []}
    total = 0
    valid = 0
    tampered: list[str] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            total += 1
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                tampered.append(f"line-{total}")
                continue
            expected = _checksum(
                str(row.get("event_id", "")),
                str(row.get("timestamp", "")),
                str(row.get("session_id", "")),
                str(row.get("event_type", "")),
            )
            if row.get("checksum") == expected:
                valid += 1
            else:
                tampered.append(str(row.get("event_id", f"line-{total}")))
    return {"total": total, "valid": valid, "tampered": tampered}


def get_session_audit_trail(session_id: str, limit: int = 50) -> list[dict[str, Any]]:
    path = _log_path()
    if not path.is_file():
        return []
    out: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if row.get("session_id") == session_id:
                out.append(row)
    return out[-limit:]


def get_recent_events(limit: int = 50) -> list[dict[str, Any]]:
    path = _log_path()
    if not path.is_file():
        return []
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows[-limit:]
