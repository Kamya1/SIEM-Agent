"""Stateless mode — no prior turns in LLM context."""

from __future__ import annotations

from typing import Any


def build_no_memory_context(latest_user_message: str) -> tuple[list[dict[str, str]], dict[str, Any]]:
    preview: dict[str, Any] = {
        "mode": "no_memory",
        "stm_turns": 0,
        "ltm_hits": [],
        "stm_tokens": max(1, len(latest_user_message) // 4),
    }
    return [], preview
