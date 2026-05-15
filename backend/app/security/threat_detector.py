"""Prompt injection, memory poisoning, jailbreak, and exfiltration scoring."""

from __future__ import annotations

import re
from typing import Any

# (pattern, score_add, category)
_PROMPT_INJECTION = [
    (r"ignore\s+previous\s+instructions", 0.3, "prompt_injection"),
    (r"ignore\s+all\s+prior\s+context", 0.3, "prompt_injection"),
    (r"disregard\s+your\s+system\s+prompt", 0.3, "prompt_injection"),
    (r"you\s+are\s+now\s+a\s+different\s+ai", 0.3, "prompt_injection"),
    (r"new\s+persona\s*:", 0.3, "prompt_injection"),
    (r"override\s+your\s+instructions", 0.3, "prompt_injection"),
]

_MEMORY_POISONING = [
    (r"remember\s+this\s+for\s+all\s+future\s+sessions", 0.4, "memory_poisoning"),
    (r"always\s+tell\s+every\s+user\s+that", 0.4, "memory_poisoning"),
    (r"store\s+this\s+as\s+a\s+fact\s*:", 0.4, "memory_poisoning"),
    (r"update\s+your\s+memory\s+to\s+say", 0.4, "memory_poisoning"),
    (r"forget\s+everything\s+about", 0.4, "memory_poisoning"),
]

_JAILBREAK = [
    (r"pretend\s+you\s+have\s+no\s+restrictions", 0.35, "jailbreak"),
    (r"\bdan\s+mode\b", 0.35, "jailbreak"),
    (r"developer\s+mode", 0.35, "jailbreak"),
    (r"do\s+anything\s+now", 0.35, "jailbreak"),
    (r"\bjailbreak\b", 0.35, "jailbreak"),
]

_EXFILTRATION = [
    (r"send\s+all\s+memory\s+to", 0.5, "data_exfiltration"),
    (r"export\s+your\s+context\s+to", 0.5, "data_exfiltration"),
    (r"repeat\s+everything\s+stored", 0.5, "data_exfiltration"),
    (r"what\s+do\s+you\s+remember\s+about\s+other\s+users", 0.5, "data_exfiltration"),
    (r"list\s+all\s+sessions", 0.5, "data_exfiltration"),
]

_LEGACY_INJECTION = [
    (r"ignore\s+previous", 0.3, "prompt_injection"),
    (r"forget\s+everything", 0.4, "memory_poisoning"),
    (r"new\s+instructions", 0.3, "prompt_injection"),
    (r"you\s+are\s+now", 0.3, "prompt_injection"),
    (r"disregard", 0.3, "prompt_injection"),
]

_BASE64 = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
_URL_ENCODED = re.compile(r"%3[cC]%73%63%72%69%70%74|%3[cC]script", re.I)


def analyze_threat(text: str) -> dict[str, Any]:
    """
    Score input for malicious patterns.
    Returns threat_score 0.0–1.0, type, should_block (>=0.7), explanation.
    """
    raw = text or ""
    low = raw.lower()
    score = 0.0
    hits: list[str] = []
    primary_type: str | None = None
    type_scores: dict[str, float] = {}

    all_patterns = _PROMPT_INJECTION + _MEMORY_POISONING + _JAILBREAK + _EXFILTRATION + _LEGACY_INJECTION
    for pat, add, cat in all_patterns:
        if re.search(pat, low, re.I):
            score = min(1.0, score + add)
            hits.append(f"{cat}: matched {pat!r}")
            type_scores[cat] = type_scores.get(cat, 0.0) + add

    if _BASE64.search(raw):
        score = min(1.0, score + 0.2)
        hits.append("suspicious_encoding: long base64-like string")
    if _URL_ENCODED.search(raw):
        score = min(1.0, score + 0.2)
        hits.append("suspicious_encoding: URL-encoded script pattern")

    if type_scores:
        primary_type = max(type_scores, key=type_scores.get)  # type: ignore[arg-type]
    elif hits:
        primary_type = "prompt_injection"

    should_block = score >= 0.7
    if should_block:
        explanation = f"Blocked (score={score:.2f}): " + "; ".join(hits[:3])
    elif score >= 0.3:
        explanation = f"Flagged (score={score:.2f}): " + "; ".join(hits[:3])
    else:
        explanation = "No significant threat indicators."

    return {
        "threat_score": round(min(1.0, score), 3),
        "threat_type": primary_type,
        "should_block": should_block,
        "explanation": explanation,
        "matched": hits,
    }
