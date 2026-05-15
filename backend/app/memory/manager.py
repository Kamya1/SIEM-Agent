"""Orchestrates no / short-term / long-term / hybrid context for the SIEM agent."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

from app.config import Settings, get_settings
from app.memory import hybrid as hybrid_mod
from app.memory import no_memory as no_memory_mod
from app.memory.ltm import LongTermVectorStore
from app.memory.stm import STMState, maybe_compress_stm
from app.models.schemas import MemoryMode
from app.security import access_guard


@dataclass
class SessionBundle:
    stm: STMState = field(default_factory=STMState)


class MemoryManager:
    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()
        self._data_dir = self._settings.data_path
        self._data_dir.mkdir(parents=True, exist_ok=True)
        self._ltm = LongTermVectorStore(self._settings.ltm_db_path, data_dir=self._data_dir)
        self._sessions: dict[str, SessionBundle] = {}

    @property
    def ltm_store(self) -> LongTermVectorStore:
        return self._ltm

    def _bundle(self, session_id: str) -> SessionBundle:
        if session_id not in self._sessions:
            self._sessions[session_id] = SessionBundle()
        return self._sessions[session_id]

    def clear_session(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)

    def active_stm_sessions(self) -> int:
        return len(self._sessions)

    def maybe_capture_preference(self, session_id: str, user_text: str) -> None:
        self._bundle(session_id).stm.detect_prefs(user_text)

    async def finalize_turn(
        self,
        session_id: str,
        user_text: str,
        assistant_text: str,
        mode: MemoryMode,
        scenario_tag: str | None,
        compress_fn: Callable[[str], Awaitable[str]],
        *,
        store_in_memory: bool = True,
        ltm_shared: bool = False,
    ) -> None:
        if mode == MemoryMode.no_memory or not store_in_memory:
            return
        b = self._bundle(session_id)
        need = b.stm.add_turn(user_text, assistant_text)
        if need:
            await maybe_compress_stm(b.stm, compress_fn)
        if mode in (MemoryMode.long_term, MemoryMode.hybrid):
            self._ltm.try_store_exchange(
                session_id=session_id,
                user_msg=user_text,
                assistant_msg=assistant_text,
                memory_mode=mode.value,
                scenario_tag=scenario_tag,
                shared=ltm_shared,
                skip_threat_check=True,
            )

    def build_context(
        self,
        session_id: str,
        mode: MemoryMode,
        latest_user_message: str,
    ) -> tuple[list[dict[str, str]], dict[str, Any]]:
        access_guard.touch_session(session_id)
        preview: dict[str, Any] = {"mode": mode.value, "ltm_hits": [], "stm_turns": 0, "stm_tokens": 0}

        if mode == MemoryMode.no_memory:
            msgs, prev = no_memory_mod.build_no_memory_context(latest_user_message)
            preview.update(prev)
            return msgs, preview

        b = self._bundle(session_id)
        stm_msgs = b.stm.build_messages()
        preview["stm_turns"] = len(stm_msgs)
        preview["stm_tokens"] = b.stm.stm_token_estimate()
        system_extra = ""

        if mode == MemoryMode.short_term:
            p = b.stm.prefs_system_snippet()
            if p:
                system_extra = p
                preview["preference_captured"] = True
            return stm_msgs, {**preview, "system_addon": system_extra}

        if mode == MemoryMode.long_term:
            hits = self._ltm.retrieve(
                latest_user_message,
                k=self._settings.ltm_retrieval_k,
                threshold=self._settings.ltm_similarity_threshold,
                session_id=session_id,
            )
            preview["ltm_hits"] = [
                {"score": round(h.score, 4), "excerpt": (h.user_msg + "\n" + h.assistant_msg)[:280]}
                for h in hits
            ]
            if hits:
                blob = "\n---\n".join(
                    f"[memory {i+1}] User: {h.user_msg[:800]}\nAssistant: {h.assistant_msg[:800]}"
                    for i, h in enumerate(hits)
                )
                system_extra = (
                    "Retrieved institutional memory (may include past sessions):\n"
                    f"{blob}\n\nUse only if relevant; ignore noise."
                )
            p = b.stm.prefs_system_snippet()
            if p:
                system_extra = (system_extra + "\n\n" if system_extra else "") + p
                preview["preference_captured"] = True
            return stm_msgs, {**preview, "system_addon": system_extra}

        addon, hits_info = hybrid_mod.build_hybrid_system_addon(
            stm_state=b.stm,
            ltm=self._ltm,
            latest_user_message=latest_user_message,
            hybrid_sim_threshold=self._settings.hybrid_context_similarity_threshold,
            session_id=session_id,
        )
        preview["ltm_hits"] = hits_info
        p = b.stm.prefs_system_snippet()
        if p:
            addon = (addon + "\n\n" if addon else "") + p
            preview["preference_captured"] = True
        return stm_msgs, {**preview, "system_addon": addon}
