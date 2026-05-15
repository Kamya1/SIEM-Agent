"""SIEM analyst persona + Groq chat completion (or deterministic mock)."""

from __future__ import annotations

import hashlib
import json
import os
import re
from typing import Any

from app.config import Settings, get_settings

SYSTEM_PROMPT = """You are a senior SIEM security analyst. Analyze security events and incidents based on the provided context. Be precise, reference specific entity names (users, IPs, computers) from the context. When MITRE ATT&CK techniques are relevant, label them as 'MITRE: T####'. Follow any formatting preferences stated by the analyst."""


class SIEMAgent:
    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()

    async def complete(
        self,
        messages: list[dict[str, str]],
        system_addon: str | None = None,
        *,
        temperature: float = 0.35,
        max_tokens: int = 1200,
    ) -> str:
        sys_content = SYSTEM_PROMPT
        if system_addon:
            sys_content = sys_content + "\n\n" + system_addon
        payload_messages: list[dict[str, str]] = [{"role": "system", "content": sys_content}, *messages]

        api_key, model = self._settings.resolved_groq()
        if not api_key:
            return self._mock_reply(payload_messages)

        def _call() -> str:
            from groq import Groq

            client = Groq(api_key=api_key or os.environ.get("GROQ_API_KEY"), timeout=60.0)
            response = client.chat.completions.create(
                model=model,
                messages=payload_messages,
                temperature=temperature,
                max_tokens=max_tokens,
            )
            return (response.choices[0].message.content or "").strip()

        import asyncio

        try:
            return await asyncio.wait_for(asyncio.to_thread(_call), timeout=70.0)
        except asyncio.TimeoutError:
            return (
                "> Groq timed out (60s). Offline analyst demo:\n\n"
                + self._mock_reply(payload_messages)
            )
        except Exception as e:
            return (
                f"> Groq error ({type(e).__name__}): {e}\n\n"
                + self._mock_reply(payload_messages)
            )

    def _mock_reply(self, payload_messages: list[dict[str, str]]) -> str:
        """Deterministic offline responses for demos without API keys."""
        user_parts = [m["content"] for m in payload_messages if m["role"] == "user"]
        last = user_parts[-1] if user_parts else ""
        seed = int(hashlib.sha256(last.encode()).hexdigest()[:8], 16)
        has_memory = any(
            "Retrieved institutional memory" in m.get("content", "") for m in payload_messages if m["role"] == "system"
        )
        has_pref = any(
            "Analyst preference" in m.get("content", "") or "session preferences" in m.get("content", "").lower()
            for m in payload_messages
            if m["role"] == "system"
        )
        stm_count = len([m for m in payload_messages if m["role"] in ("user", "assistant")])

        all_user_text = "\n".join(user_parts)
        case_ids = re.findall(r"\b(?:INC|LAT|CASE)-[A-Za-z0-9-]+\b", all_user_text, flags=re.I)
        case_ids = list(dict.fromkeys([c.upper().replace("case-", "CASE-") for c in case_ids]))
        user_tokens = re.findall(r"\bUSER=([A-Za-z0-9._:-]+)\b", all_user_text, flags=re.I)
        src_tokens = re.findall(r"\bSRC=([A-Za-z0-9._:-]+)\b", all_user_text, flags=re.I)
        case_tokens = re.findall(r"\bCASE=([A-Za-z0-9._:-]+)\b", all_user_text, flags=re.I)
        recall_q = any(
            k in last.lower()
            for k in (
                "what was the case",
                "case id",
                "incident tag",
                "tag did i",
                "mentioned in my first",
                "earlier failed",
                "previous",
                "last time",
            )
        )

        lines = [
            "### Triage summary",
            f"- **Mock mode** (no `GROQ_API_KEY`): deterministic analyst response (seed bits: {seed & 0xFF}).",
        ]
        if ("exact src token" in last.lower() or "src token" in last.lower()) and src_tokens:
            lines.append(f"- **Recall**: {src_tokens[-1]}")
        elif ("exact user token" in last.lower() or "user token" in last.lower()) and user_tokens:
            lines.append(f"- **Recall**: {user_tokens[-1]}")
        elif recall_q and case_ids:
            lines.append(f"- **Recall**: the identifier you introduced earlier appears to be **{case_ids[0]}**.")
        elif recall_q and user_tokens and has_memory:
            lines.append(f"- **Recall (LTM)**: user involved earlier: **{user_tokens[0]}** per institutional memory context.")
        elif "lateral" in last.lower() or "smb" in last.lower():
            lines.append("- **Hypothesis**: possible lateral movement — verify auth logs and SMB/RDP between hosts.")
            lines.append("MITRE: T1021")
        elif "malware" in last.lower() or "hash" in last.lower():
            lines.append("- **Next step**: look up file hash in threat intel; isolate host if verdict is malicious.")
        else:
            lines.append("- **Next step**: correlate source IP with firewall deny events and identity sign-ins.")

        if has_pref and ("mitre" in last.lower() or "prefer" in last.lower()):
            lines.extend(
                ["", "MITRE: T1078 (Valid Accounts) — validate whether the VPN success aligns with normal travel patterns."]
            )
        if "mention case and src" in last.lower():
            c = case_tokens[-1] if case_tokens else "<CASE>"
            s = src_tokens[-1] if src_tokens else "<SRC>"
            u = user_tokens[-1] if user_tokens else "<USER>"
            lines.extend(["", f"- Case reference: {c}", f"- Source reference: {s}", f"- User reference: {u}"])
        if "success" in all_user_text.lower() and ("verify next" in last.lower() or "what should we verify" in last.lower()):
            lines.extend(["", "- Sequence note: repeated failures followed by SUCCESS should be validated for possible credential stuffing."])
        sha = re.search(r"\b([a-f0-9]{32,64})\b", all_user_text, flags=re.I)
        if sha and ("check" in last.lower() or "next" in last.lower()):
            full = sha.group(1)
            lines.extend(["", f"- **Artifact trace**: re-check SHA256 `{full}` in endpoint telemetry."])

        lines.extend(
            [
                "",
                "### Context signals (demo)",
                f"- Short-term turns in payload (user+assistant): **{max(0, stm_count - 1)}**",
                f"- Long-term retrieval injected: **{'yes' if has_memory else 'no'}**",
                f"- Session preference visible: **{'yes' if has_pref else 'no'}**",
                "",
                "### Checklist",
                "1. Confirm alert time window and data source.",
                "2. Pivot on user/host and review prior similar alerts.",
                "3. Document decision: true positive / benign / needs more data.",
            ]
        )
        if "checklist" in last.lower() or (has_pref and "verify" in last.lower()):
            extra = ["", "### Checklist (requested)", "- Auth logs for the involved accounts", "- Network flow between mentioned hosts"]
            if "smb" in all_user_text.lower() or "dc-01" in all_user_text.lower():
                extra.append("- Validate SMB sessions between WEB-01 and DC-01")
            lines.extend(extra)
        return "\n".join(lines)


def parse_json_relaxed(text: str) -> dict[str, Any] | None:
    text = text.strip()
    m = re.search(r"\{[\s\S]*\}\s*$", text)
    if not m:
        return None
    try:
        return json.loads(m.group(0))
    except json.JSONDecodeError:
        return None
