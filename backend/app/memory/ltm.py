"""Long-term memory: encrypted sentence-transformer embeddings in SQLite."""

from __future__ import annotations

import logging
import re
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

import numpy as np

from app.security import audit_log, encryptor, threat_detector

logger = logging.getLogger(__name__)

_EMBED_LOCK = threading.Lock()
_EMBEDDERS: dict[str, Any] = {}


def _shared_sentence_transformer(model_name: str):
    with _EMBED_LOCK:
        if model_name not in _EMBEDDERS:
            from sentence_transformers import SentenceTransformer

            _EMBEDDERS[model_name] = SentenceTransformer(model_name)
        return _EMBEDDERS[model_name]


def detect_injection(text: str) -> tuple[bool, str | None]:
    """Legacy hook — delegates to threat_detector."""
    result = threat_detector.analyze_threat(text)
    if result["should_block"]:
        return True, result["explanation"]
    return False, None


def _cosine_sim(a: np.ndarray, b: np.ndarray) -> float:
    denom = float(np.linalg.norm(a) * np.linalg.norm(b)) or 1e-9
    return float(np.dot(a, b) / denom)


@dataclass
class LTMHit:
    id: int
    user_msg: str
    assistant_msg: str
    score: float
    session_id: str | None
    timestamp: str | None
    scenario_tag: str | None
    memory_mode: str | None
    shared: bool = False


class LongTermVectorStore:
    def __init__(
        self,
        db_path: Path,
        embed_model_name: str = "all-MiniLM-L6-v2",
        data_dir: Path | None = None,
    ) -> None:
        self._db_path = db_path
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._embed_model_name = embed_model_name
        self._lock = threading.Lock()
        self._data_dir = data_dir or db_path.parent
        self._conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ltm_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                timestamp TEXT,
                scenario_tag TEXT,
                memory_mode TEXT,
                user_msg TEXT,
                assistant_msg TEXT,
                embedding BLOB,
                retrieval_count INTEGER DEFAULT 0,
                shared INTEGER DEFAULT 0
            )
            """
        )
        cols = {r[1] for r in self._conn.execute("PRAGMA table_info(ltm_entries)").fetchall()}
        if "shared" not in cols:
            self._conn.execute("ALTER TABLE ltm_entries ADD COLUMN shared INTEGER DEFAULT 0")
        self._conn.commit()

    def _get_model(self):
        return _shared_sentence_transformer(self._embed_model_name)

    def embed_text(self, text: str) -> np.ndarray:
        model = self._get_model()
        v = model.encode(text or "", normalize_embeddings=True)
        return np.asarray(v, dtype=np.float32)

    def _decrypt_msg(self, stored: str) -> str:
        if not stored:
            return ""
        if encryptor.is_encrypted_payload(stored):
            return encryptor.decrypt_text(stored)
        return stored

    def try_store_exchange(
        self,
        *,
        session_id: str | None,
        user_msg: str,
        assistant_msg: str,
        memory_mode: str | None,
        scenario_tag: str | None = None,
        shared: bool = False,
        skip_threat_check: bool = False,
    ) -> tuple[bool, str | None]:
        combined = f"{user_msg}\n{assistant_msg}"
        if not skip_threat_check:
            threat = threat_detector.analyze_threat(combined)
            if threat["should_block"] or threat["threat_score"] >= 0.3:
                audit_log.log_event(
                    session_id or "unknown",
                    "INJECTION_BLOCKED" if threat["should_block"] else "SECURITY_ALERT",
                    {"reason": threat["explanation"], "ltm_store": False},
                )
                if threat["should_block"]:
                    return False, threat["explanation"]

        vec = self.embed_text(combined)
        enc_user = encryptor.encrypt_text(user_msg)
        enc_asst = encryptor.encrypt_text(assistant_msg)
        enc_blob = encryptor.encrypt_embedding(vec)
        ts = datetime.now(timezone.utc).isoformat()
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO ltm_entries
                (session_id, timestamp, scenario_tag, memory_mode, user_msg, assistant_msg, embedding, retrieval_count, shared)
                VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)
                """,
                (
                    session_id,
                    ts,
                    scenario_tag,
                    memory_mode,
                    enc_user,
                    enc_asst,
                    enc_blob,
                    1 if shared else 0,
                ),
            )
            self._conn.commit()
        audit_log.log_event(
            session_id or "unknown",
            "LTM_STORE",
            {"memory_mode": memory_mode, "shared": shared, "scenario_tag": scenario_tag},
        )
        return True, None

    def retrieve(
        self,
        query: str,
        k: int = 3,
        threshold: float = 0.35,
        exclude_text_substrings: Sequence[str] | None = None,
        session_id: str | None = None,
    ) -> list[LTMHit]:
        qv = self.embed_text(query)
        rows = self._conn.execute(
            """
            SELECT id, session_id, timestamp, scenario_tag, memory_mode,
                   user_msg, assistant_msg, embedding, retrieval_count, shared
            FROM ltm_entries
            """
        ).fetchall()
        if not rows:
            return []
        scored: list[tuple[float, sqlite3.Row]] = []
        subs = exclude_text_substrings or ()
        for r in rows:
            sid = r["session_id"]
            is_shared = int(r["shared"] or 0) == 1
            if session_id and sid != session_id and not is_shared:
                continue
            blob = r["embedding"]
            if not blob:
                continue
            try:
                doc = encryptor.decrypt_embedding(blob)
            except Exception:
                continue
            sim = _cosine_sim(qv, doc)
            u_plain = self._decrypt_msg(str(r["user_msg"] or ""))
            a_plain = self._decrypt_msg(str(r["assistant_msg"] or ""))
            text_blob = f"{u_plain}\n{a_plain}"
            if any(s and s in text_blob for s in subs if s):
                continue
            scored.append((sim, r))
        scored.sort(key=lambda x: -x[0])
        hits: list[LTMHit] = []
        for sim, r in scored[: k * 3]:
            if sim < threshold:
                continue
            hits.append(
                LTMHit(
                    id=int(r["id"]),
                    user_msg=self._decrypt_msg(str(r["user_msg"] or "")),
                    assistant_msg=self._decrypt_msg(str(r["assistant_msg"] or "")),
                    score=sim,
                    session_id=r["session_id"],
                    timestamp=r["timestamp"],
                    scenario_tag=r["scenario_tag"],
                    memory_mode=r["memory_mode"],
                    shared=bool(int(r["shared"] or 0)),
                )
            )
            if len(hits) >= k:
                break
        if hits:
            with self._lock:
                for h in hits:
                    self._conn.execute(
                        "UPDATE ltm_entries SET retrieval_count = retrieval_count + 1 WHERE id = ?",
                        (h.id,),
                    )
                self._conn.commit()
            audit_log.log_event(
                session_id or "unknown",
                "LTM_RETRIEVE",
                {"hit_count": len(hits), "top_score": round(hits[0].score, 4)},
            )
        return hits

    def list_entries(self, session_id: str | None = None) -> list[dict[str, Any]]:
        if session_id:
            rows = self._conn.execute(
                """
                SELECT id, session_id, timestamp, scenario_tag, memory_mode, retrieval_count,
                       user_msg, assistant_msg, shared
                FROM ltm_entries
                WHERE session_id = ? OR shared = 1
                ORDER BY id DESC
                """,
                (session_id,),
            ).fetchall()
        else:
            rows = self._conn.execute(
                """
                SELECT id, session_id, timestamp, scenario_tag, memory_mode, retrieval_count,
                       user_msg, assistant_msg, shared
                FROM ltm_entries ORDER BY id DESC
                """
            ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["user_msg"] = self._decrypt_msg(str(d.get("user_msg") or ""))
            d["assistant_msg"] = self._decrypt_msg(str(d.get("assistant_msg") or ""))
            d["shared"] = bool(int(d.get("shared") or 0))
            out.append(d)
        return out

    def set_shared(self, entry_id: int, shared: bool = True) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "UPDATE ltm_entries SET shared = ? WHERE id = ?",
                (1 if shared else 0, entry_id),
            )
            self._conn.commit()
            return cur.rowcount > 0

    def delete(self, entry_id: int, session_id: str | None = None) -> bool:
        with self._lock:
            if session_id:
                cur = self._conn.execute(
                    "DELETE FROM ltm_entries WHERE id = ? AND session_id = ?",
                    (entry_id, session_id),
                )
            else:
                cur = self._conn.execute("DELETE FROM ltm_entries WHERE id = ?", (entry_id,))
            self._conn.commit()
            ok = cur.rowcount > 0
        if ok:
            audit_log.log_event(session_id or "unknown", "LTM_DELETE", {"entry_id": entry_id})
        return ok

    def clear_all(self) -> int:
        with self._lock:
            cur = self._conn.execute("DELETE FROM ltm_entries")
            self._conn.commit()
            return cur.rowcount

    def entry_count(self) -> int:
        row = self._conn.execute("SELECT COUNT(*) AS c FROM ltm_entries").fetchone()
        return int(row["c"]) if row else 0

    def db_file_size_bytes(self) -> int:
        try:
            return self._db_path.stat().st_size
        except OSError:
            return 0
