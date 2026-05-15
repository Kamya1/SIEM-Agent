"""Detect MITRE ATT&CK technique IDs in analyst/assistant text."""

from __future__ import annotations

import re
from typing import Any

MITRE_PATTERN = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b", re.IGNORECASE)


def extract_mitre_techniques(text: str) -> list[str]:
    found = MITRE_PATTERN.findall(text or "")
    out: list[str] = []
    seen: set[str] = set()
    for t in found:
        norm = t.upper()
        if norm not in seen:
            seen.add(norm)
            out.append(norm)
    return out


def mitre_badge_data(technique_id: str) -> dict[str, Any]:
    tid = technique_id.upper().replace(".", "_")
    base = technique_id.upper().split(".")[0]
    url = f"https://attack.mitre.org/techniques/{base}/"
    if "." in technique_id.upper():
        sub = technique_id.upper().split(".", 1)[1]
        url = f"https://attack.mitre.org/techniques/{base}/{sub}/"
    return {"id": technique_id.upper(), "url": url, "tid": tid}
