"""Short-term memory: sliding window, preference dict, optional compression."""

from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

PREF_PATTERNS = [
    (re.compile(r"always\s+include\s+(.{1,400})", re.I), "always_include"),
    (re.compile(r"i\s+prefer\s+(.{1,400})", re.I), "prefer"),
    (re.compile(r"format\s+as\s+(.{1,400})", re.I), "format_as"),
]


def _approx_tokens(text: str) -> int:
    return max(1, len(text) // 4)


@dataclass
class STMState:
    """Up to 10 user/assistant pairs; compression when exceeding."""

    pairs: deque[tuple[str, str]] = field(default_factory=deque)
    compressed_prefix: str | None = None
    session_prefs: dict[str, str] = field(default_factory=dict)

    def detect_prefs(self, user_text: str) -> None:
        for rx, key in PREF_PATTERNS:
            m = rx.search(user_text)
            if m:
                self.session_prefs[key] = m.group(1).strip()[:800]

    def add_turn(self, user_text: str, assistant_text: str) -> bool:
        """Returns True if compression of oldest 5 pairs is needed."""
        self.pairs.append((user_text, assistant_text))
        if len(self.pairs) > 10:
            return True
        return False

    def pop_oldest_for_compress(self) -> list[tuple[str, str]]:
        batch: list[tuple[str, str]] = []
        for _ in range(min(5, len(self.pairs))):
            batch.append(self.pairs.popleft())
        return batch

    def stm_token_estimate(self) -> int:
        n = 0
        if self.compressed_prefix:
            n += _approx_tokens(self.compressed_prefix)
        for u, a in self.pairs:
            n += _approx_tokens(u) + _approx_tokens(a)
        return n

    def build_messages(self) -> list[dict[str, str]]:
        out: list[dict[str, str]] = []
        if self.compressed_prefix:
            out.append({"role": "user", "content": self.compressed_prefix})
        for u, a in self.pairs:
            out.append({"role": "user", "content": u})
            out.append({"role": "assistant", "content": a})
        return out

    def prefs_system_snippet(self) -> str:
        if not self.session_prefs:
            return ""
        lines = [f"- {k}: {v}" for k, v in self.session_prefs.items()]
        return "Analyst session preferences:\n" + "\n".join(lines)


CompressFn = Callable[[str], Awaitable[str]]


async def maybe_compress_stm(
    state: STMState,
    compress_fn: CompressFn,
) -> None:
    while len(state.pairs) > 10:
        batch = state.pop_oldest_for_compress()
        lines = []
        for i, (u, a) in enumerate(batch, 1):
            lines.append(f"Turn{i} user: {u}\nTurn{i} assistant: {a}")
        ctx = "\n\n".join(lines)
        prompt = (
            "Summarize this security investigation context in 3 bullet points, preserving: "
            "suspect user IDs, source IPs, MITRE techniques, and analyst preferences.\n\n"
            f"Context:\n{ctx}"
        )
        summary = await compress_fn(prompt)
        block = "[COMPRESSED CONTEXT]\n" + summary.strip()
        state.compressed_prefix = (state.compressed_prefix + "\n\n" if state.compressed_prefix else "") + block
