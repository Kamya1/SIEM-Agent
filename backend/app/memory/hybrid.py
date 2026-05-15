"""Hybrid memory: STM always; LTM when topic drifts or explicit recall cues."""

from __future__ import annotations

from typing import Any, Sequence

import numpy as np

from app.memory.ltm import LongTermVectorStore
from app.memory.stm import STMState


def _tokenize_set(text: str) -> set[str]:
    import re

    return {t.lower() for t in re.findall(r"[a-z0-Z0-9._:/@-]+", text or "") if len(t) > 1}


def context_query_similarity(session_context: str, query: str) -> float:
    a, b = _tokenize_set(session_context), _tokenize_set(query)
    if not a or not b:
        return 1.0
    inter = len(a & b)
    union = len(a | b) or 1
    return inter / union


RECALL_CUES = ("earlier", "previously", "last time", "before", "prior session", "remember")


def should_retrieve_ltm(
    session_context: str,
    query: str,
    embed_fn,
    threshold: float = 0.6,
) -> bool:
    qlow = query.lower()
    if any(c in qlow for c in RECALL_CUES):
        return True
    try:
        qv = embed_fn(query)
        cv = embed_fn(session_context[-2000:] if len(session_context) > 2000 else session_context)
        sim = float(np.dot(qv, cv) / ((np.linalg.norm(qv) * np.linalg.norm(cv)) + 1e-9))
        return sim < threshold
    except Exception:
        return context_query_similarity(session_context, query) < 0.25


def dedupe_hits_against_stm(
    hits: Sequence[Any],
    stm_messages: Sequence[dict[str, str]],
) -> list[Any]:
    stm_blob = "\n".join(m.get("content", "") for m in stm_messages).lower()
    out = []
    for h in hits:
        blob = f"{getattr(h, 'user_msg', '')} {getattr(h, 'assistant_msg', '')}".lower()
        if blob and blob[:200] in stm_blob:
            continue
        out.append(h)
    return out


def build_hybrid_system_addon(
    *,
    stm_state: STMState,
    ltm: LongTermVectorStore,
    latest_user_message: str,
    hybrid_sim_threshold: float,
    session_id: str | None = None,
) -> tuple[str, list[dict[str, Any]]]:
    stm_msgs = stm_state.build_messages()
    session_blob = "\n".join(m["content"] for m in stm_msgs[-20:])
    hits_info: list[dict[str, Any]] = []
    if not session_blob.strip():
        prefs = stm_state.prefs_system_snippet()
        return (prefs, hits_info)
    retrieve = should_retrieve_ltm(
        session_blob,
        latest_user_message,
        ltm.embed_text,
        threshold=hybrid_sim_threshold,
    )
    extra = ""
    if retrieve:
        raw_hits = ltm.retrieve(latest_user_message, k=3, threshold=0.35, session_id=session_id)
        hits = dedupe_hits_against_stm(raw_hits, stm_msgs)
        for h in hits:
            hits_info.append(
                {
                    "score": round(h.score, 4),
                    "excerpt": (h.user_msg + "\n" + h.assistant_msg)[:280]
                    + ("…" if len(h.user_msg) + len(h.assistant_msg) > 280 else ""),
                }
            )
        if hits:
            blob = "\n---\n".join(
                f"[memory {i+1}] User: {h.user_msg[:600]}\nAssistant: {h.assistant_msg[:600]}" for i, h in enumerate(hits)
            )
            extra = (
                "Retrieved institutional memory (hybrid mode; relevance-gated):\n"
                f"{blob}\n\nUse only if relevant; ignore noise."
            )
    prefs = stm_state.prefs_system_snippet()
    parts = [p for p in (extra, prefs) if p]
    return ("\n\n".join(parts), hits_info)
