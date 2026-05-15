"""PII detection and redaction via regex (no external NLP)."""

from __future__ import annotations

import re
from typing import Any

# LANL-style anonymized host tokens: C123, etc.
_LANL_HOST = re.compile(r"\bC\d+\b", re.I)

_IPV4 = re.compile(r"\b(\d{1,3}\.){3}\d{1,3}\b")
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_API_KEY = re.compile(
    r"\b(sk-[a-zA-Z0-9]{20,}|gsk_[a-zA-Z0-9]{20,}|Bearer\s+[a-zA-Z0-9\-._~+/]+)\b",
    re.I,
)
_CC = re.compile(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b")
_PHONE_IN = re.compile(r"(?:\+91|0)?[6-9]\d{9}\b")
_PHONE_INTL = re.compile(r"\+\d{1,3}[\s-]?\d{7,14}\b")
_DOMAIN_CRED = re.compile(r"\b[A-Za-z0-9._-]+\\[A-Za-z0-9._-]+\b|\b[A-Za-z0-9._-]+@[A-Za-z0-9.-]+\.local\b", re.I)

_SECRET_LABEL = re.compile(
    r"(password|passwd|secret|token|api_key|credential)\s*[:=]\s*(\S+)",
    re.I,
)
_SECRET_NEAR = re.compile(
    r"(password|passwd|secret|token|api_key|credential)",
    re.I,
)


def _is_lanl_context(text: str, match: re.Match[str]) -> bool:
    """Keep IPv4-looking tokens if they are part of LANL C#### host naming nearby."""
    start = max(0, match.start() - 40)
    window = text[start : match.end() + 40]
    if _LANL_HOST.search(window):
        return True
    # SRC=C12 style
    if re.search(r"SRC\s*=\s*C\d+", window, re.I):
        return True
    return False


def detect_and_redact(text: str) -> dict[str, Any]:
    """Detect and replace sensitive patterns with placeholders."""
    t = text or ""
    pii_found: list[str] = []
    count = 0

    def _sub(rx: re.Pattern[str], repl: str, label: str, skip_if: callable | None = None) -> None:
        nonlocal t, count

        def replacer(m: re.Match[str]) -> str:
            nonlocal count
            if skip_if and skip_if(m):
                return m.group(0)
            count += 1
            if label not in pii_found:
                pii_found.append(label)
            return repl

        t = rx.sub(replacer, t)

    # IPv4 — skip LANL-style contexts
    def skip_ip(m: re.Match[str]) -> bool:
        return _is_lanl_context(t, m)

    _sub(_IPV4, "[IP_REDACTED]", "IPv4", skip_ip)
    _sub(_EMAIL, "[EMAIL_REDACTED]", "Email")
    _sub(_API_KEY, "[API_KEY_REDACTED]", "APIKey")
    _sub(_CC, "[CC_REDACTED]", "CreditCard")
    _sub(_PHONE_IN, "[PHONE_REDACTED]", "Phone")
    _sub(_PHONE_INTL, "[PHONE_REDACTED]", "Phone")
    _sub(_DOMAIN_CRED, "[DOMAIN_CRED_REDACTED]", "DomainCredential")

    # Secrets with label:value
    def secret_repl(m: re.Match[str]) -> str:
        nonlocal count
        count += 1
        if "Secret" not in pii_found:
            pii_found.append("Secret")
        return f"{m.group(1)}: [SECRET_REDACTED]"

    t = _SECRET_LABEL.sub(secret_repl, t)

    # value within 3 tokens after label
    parts = t.split()
    out: list[str] = []
    i = 0
    while i < len(parts):
        w = parts[i]
        if _SECRET_NEAR.match(w.rstrip(":=")):
            out.append(w)
            gap = 0
            j = i + 1
            while j < len(parts) and gap < 3:
                if parts[j] in (":", "="):
                    j += 1
                    continue
                if not parts[j].startswith("[") and len(parts[j]) > 2:
                    if "Secret" not in pii_found:
                        pii_found.append("Secret")
                    out.append("[SECRET_REDACTED]")
                    count += 1
                    i = j + 1
                    break
                out.append(parts[j])
                gap += 1
                j += 1
            else:
                i += 1
            continue
        out.append(w)
        i += 1
    t = " ".join(out)

    return {
        "redacted_text": t,
        "pii_found": pii_found,
        "redaction_count": count,
    }


def mask_for_display(text: str) -> str:
    """Lighter masking for UI display."""
    t = text or ""

    def mask_email(m: re.Match[str]) -> str:
        e = m.group(0)
        if "@" not in e:
            return e
        local, _, domain = e.partition("@")
        dname, _, tld = domain.partition(".")
        return f"{local[0]}***@{dname[0] if dname else '*'}***.{tld or '***'}"

    t = _EMAIL.sub(mask_email, t)

    def mask_ip(m: re.Match[str]) -> str:
        parts = m.group(0).split(".")
        return f"{parts[0]}.***.***.{parts[-1]}"

    t = _IPV4.sub(mask_ip, t)
    return t
