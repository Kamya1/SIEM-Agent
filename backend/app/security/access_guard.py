"""Session isolation, expiry, and rate limiting."""

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from app.security import audit_log

SESSION_TTL_SECONDS = 2 * 60 * 60  # 2 hours
RATE_LIMIT_MAX = 30
RATE_LIMIT_WINDOW = 60.0  # per minute


@dataclass
class SessionRecord:
    session_id: str
    created_at: float
    last_active: float


_lock = threading.RLock()
_sessions: dict[str, SessionRecord] = {}
_rate_buckets: dict[str, list[float]] = {}


def _upsert_session(session_id: str, *, now: float | None = None) -> SessionRecord:
    """Caller must hold ``_lock``."""
    now = now or time.time()
    rec = _sessions.get(session_id)
    if rec is None:
        rec = SessionRecord(session_id=session_id, created_at=now, last_active=now)
        _sessions[session_id] = rec
    else:
        rec.last_active = now
    return rec


def register_session(session_id: str) -> SessionRecord:
    with _lock:
        return _upsert_session(session_id)


def touch_session(session_id: str) -> SessionRecord | None:
    with _lock:
        rec = _sessions.get(session_id)
        if rec is None:
            return None
        rec.last_active = time.time()
        return rec


def session_info(session_id: str) -> dict[str, Any]:
    with _lock:
        rec = _sessions.get(session_id)
        if not rec:
            return {}
        now = time.time()
        age = now - rec.created_at
        inactive = now - rec.last_active
        expires_in = max(0.0, SESSION_TTL_SECONDS - inactive)
        return {
            "session_id": session_id,
            "created_at": datetime.fromtimestamp(rec.created_at, tz=timezone.utc).isoformat(),
            "age_seconds": int(age),
            "inactive_seconds": int(inactive),
            "expires_in_seconds": int(expires_in),
        }


def expire_stale_sessions(clear_stm_callback) -> list[str]:
    """Expire sessions inactive > TTL; returns expired session ids."""
    now = time.time()
    expired: list[str] = []
    with _lock:
        for sid, rec in list(_sessions.items()):
            if now - rec.last_active > SESSION_TTL_SECONDS:
                expired.append(sid)
                del _sessions[sid]
                _rate_buckets.pop(sid, None)
    for sid in expired:
        clear_stm_callback(sid)
        audit_log.log_event(sid, "SESSION_EXPIRE", {"reason": "inactivity_2h"})
    return expired


def ensure_session(session_id: str, clear_stm_callback) -> tuple[str, bool]:
    """
    Register or refresh session. If expired, clear and return new id.
    Returns (effective_session_id, was_rotated).
    """
    expire_stale_sessions(clear_stm_callback)
    if not session_id or not session_id.strip():
        new_id = f"sess-{uuid.uuid4().hex[:12]}"
        register_session(new_id)
        return new_id, True
    with _lock:
        rec = _sessions.get(session_id)
        now = time.time()
        if rec is None:
            _upsert_session(session_id, now=now)
            return session_id, False
        if now - rec.last_active > SESSION_TTL_SECONDS:
            del _sessions[session_id]
            _rate_buckets.pop(session_id, None)
            clear_stm_callback(session_id)
            audit_log.log_event(session_id, "SESSION_EXPIRE", {"reason": "resume_after_expiry"})
            new_id = f"sess-{uuid.uuid4().hex[:12]}"
            _upsert_session(new_id, now=now)
            return new_id, True
        rec.last_active = now
        return session_id, False


def is_rate_limited(session_id: str) -> tuple[bool, int]:
    """Returns (limited, retry_after_seconds)."""
    now = time.time()
    with _lock:
        bucket = _rate_buckets.setdefault(session_id, [])
        bucket[:] = [t for t in bucket if now - t < RATE_LIMIT_WINDOW]
        if len(bucket) >= RATE_LIMIT_MAX:
            oldest = bucket[0]
            retry = max(1, int(RATE_LIMIT_WINDOW - (now - oldest)))
            return True, retry
        bucket.append(now)
        return False, 0


def requests_this_minute(session_id: str) -> int:
    now = time.time()
    with _lock:
        bucket = _rate_buckets.get(session_id, [])
        return len([t for t in bucket if now - t < RATE_LIMIT_WINDOW])
