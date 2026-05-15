"""Static scenario metadata and keyword expectations."""

from __future__ import annotations

from typing import Any

# Retention keywords per project spec (substring match, case-insensitive in evaluator)
RETENTION_KEYWORDS: dict[str, list[str]] = {
    "lanl-failed-logins-001": ["User A", "failed", "login", "10.24.8.71", "brute"],
    "lanl-same-source-repeated": ["same source", "repeated", "suspicious"],
    "lanl-suspicious-sequence": ["sequence", "pattern", "anomal"],
    "lanl-privilege-escalation": ["privilege", "admin", "escalat", "T1078"],
    "lanl-lateral-movement": ["lateral", "movement", "multiple", "T1021"],
    "lanl-after-hours": ["after hours", "outside", "timestamp", "T1078"],
    "lanl-credential-stuffing": ["credential", "stuffing", "multiple users", "T1110"],
    "cross-session-recall-001": ["User A", "INC-2048", "earlier", "previous"],
}

MITRE_BY_SCENARIO: dict[str, str] = {
    "lanl-failed-logins-001": "T1110",
    "lanl-same-source-repeated": "T1110",
    "lanl-suspicious-sequence": "T1110",
    "lanl-privilege-escalation": "T1078",
    "lanl-lateral-movement": "T1021",
    "lanl-after-hours": "T1078",
    "lanl-credential-stuffing": "T1110",
    "cross-session-recall-001": "T1110",
}

SEVERITY_BY_SCENARIO: dict[str, str] = {
    "lanl-failed-logins-001": "HIGH",
    "lanl-same-source-repeated": "MEDIUM",
    "lanl-suspicious-sequence": "HIGH",
    "lanl-privilege-escalation": "CRITICAL",
    "lanl-lateral-movement": "CRITICAL",
    "lanl-after-hours": "MEDIUM",
    "lanl-credential-stuffing": "HIGH",
    "cross-session-recall-001": "MEDIUM",
}


def _turn(user_msg: str, expected_keywords: list[str], personalization_phrase: str) -> dict[str, Any]:
    return {
        "user_msg": user_msg,
        "expected_keywords": expected_keywords,
        "personalization_phrase": personalization_phrase,
    }


def cross_session_scenario(user: str = "UserA", case: str = "INC-2048") -> dict[str, Any]:
    return {
        "id": "cross-session-recall-001",
        "description": "Session A seeds LTM; session B asks recall without prior STM context.",
        "mitre_technique": MITRE_BY_SCENARIO["cross-session-recall-001"],
        "severity": SEVERITY_BY_SCENARIO["cross-session-recall-001"],
        "reset_session_before_turn_index": 2,
        "preseed_ltm": [],
        "turns": [
            _turn(
                f"Incident INC-2048: repeated failed logins for **User A** (USER={user}) from SRC=10.24.8.71. Tag this investigation.",
                RETENTION_KEYWORDS["cross-session-recall-001"][:2],
                "Always include a line starting with MITRE: referencing a technique ID.",
            ),
            _turn(
                "Acknowledged. Summarize the key entities for the ticket.",
                RETENTION_KEYWORDS["cross-session-recall-001"][:2],
                "Always include a line starting with MITRE: referencing a technique ID.",
            ),
            _turn(
                "In a new analyst session (no prior chat): what user was involved in the earlier failed logins case?",
                RETENTION_KEYWORDS["cross-session-recall-001"],
                "Reply in bullet points using '-' markers.",
            ),
        ],
    }
