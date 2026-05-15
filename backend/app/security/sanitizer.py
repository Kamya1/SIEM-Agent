"""Input sanitization before STM/LTM storage."""

from __future__ import annotations

import logging
import re
import unicodedata

logger = logging.getLogger(__name__)

MAX_LEN = 2000

# Control / invisible chars (keep common whitespace)
_CONTROL_CHARS = re.compile(
    r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f"
    r"\u200b\u200c\u200d\ufeff"
    r"\u202a-\u202e\u2066-\u2069]"
)

_HTML_PATTERNS = [
    (re.compile(r"<script[^>]*>.*?</script>", re.I | re.S), "html_script_removed"),
    (re.compile(r"<iframe[^>]*>.*?</iframe>", re.I | re.S), "html_iframe_removed"),
    (re.compile(r"<img[^>]+>", re.I), "html_img_removed"),
    (re.compile(r"\bon\w+\s*=", re.I), "html_event_handler_removed"),
    (re.compile(r"javascript\s*:", re.I), "javascript_uri_removed"),
]

_SQL_PATTERNS = [
    (re.compile(r"--\s", re.I), "sql_comment_flagged"),
    (re.compile(r";\s*drop\s+table", re.I), "sql_injection_cleaned"),
    (re.compile(r";\s*delete\s+from", re.I), "sql_injection_cleaned"),
    (re.compile(r"'\s*or\s+'1'\s*=\s*'1", re.I), "sql_injection_cleaned"),
]

_URL_ENCODED_PAYLOAD = re.compile(r"%3[cC][a-zA-Z0-9%]+", re.I)


def sanitize(text: str) -> dict:
    """
    Run every input through this before storing in STM or LTM.
    Returns clean_text, was_modified, flags.
    """
    original = text or ""
    flags: list[str] = []
    t = original

    # 1. Strip null / zero-width / bidi controls
    cleaned_ctrl = _CONTROL_CHARS.sub("", t)
    if cleaned_ctrl != t:
        flags.append("control_chars_removed")
        t = cleaned_ctrl

    # Normalize unicode compatibility
    t = unicodedata.normalize("NFKC", t)

    # 2. Whitespace normalization
    t = re.sub(r"[ \t]+", " ", t)
    t = re.sub(r"\n{3,}", "\n\n", t)
    t = t.strip()

    # 3. Truncate
    if len(t) > MAX_LEN:
        logger.warning("Input truncated from %d to %d chars", len(t), MAX_LEN)
        flags.append("truncated_to_2000")
        t = t[:MAX_LEN]

    # 4. HTML / script
    for rx, flag in _HTML_PATTERNS:
        new_t, n = rx.subn("", t)
        if n:
            flags.append(flag)
            t = new_t

    # 5. SQL-ish patterns — clean dangerous fragments, flag
    for rx, flag in _SQL_PATTERNS:
        if rx.search(t):
            flags.append(flag)
            t = rx.sub(" ", t)

    # 6. Flag URL-encoded payloads (do not remove)
    if _URL_ENCODED_PAYLOAD.search(original):
        flags.append("url_encoded_payload_detected")

    was_modified = t != original or bool(flags)
    return {
        "clean_text": t,
        "was_modified": was_modified,
        "flags": flags,
    }
