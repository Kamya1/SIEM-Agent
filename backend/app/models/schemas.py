from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class MemoryMode(str, Enum):
    no_memory = "no_memory"
    short_term = "short_term"
    long_term = "long_term"
    hybrid = "hybrid"


class ChatMessage(BaseModel):
    role: str = Field(..., pattern="^(user|assistant|system)$")
    content: str


class ChatRequest(BaseModel):
    session_id: str = Field(..., min_length=1, max_length=128)
    memory_mode: MemoryMode
    message: str = Field(..., min_length=1, max_length=32000)
    scenario_tag: str | None = Field(default=None, max_length=256)

    @field_validator("memory_mode", mode="before")
    @classmethod
    def _coerce_memory_mode(cls, v: Any) -> Any:
        if isinstance(v, str) and v.strip().lower() == "none":
            return "no_memory"
        return v


class SecurityEvent(BaseModel):
    threat_score: float = 0.0
    threat_type: str | None = None
    should_block: bool = False
    explanation: str = ""
    shield: str = "clean"  # clean | pii | flagged | blocked
    pii_found: list[str] = Field(default_factory=list)
    redaction_count: int = 0
    sanitize_flags: list[str] = Field(default_factory=list)
    session_rotated: bool = False
    effective_session_id: str | None = None


class ChatResponse(BaseModel):
    reply: str
    memory_mode: MemoryMode
    context_preview: dict[str, Any] = Field(default_factory=dict)
    mitre_techniques: list[str] = Field(default_factory=list)
    security_warning: str | None = None
    security_event: SecurityEvent | None = None
    session_id: str | None = None


class EvalRunRequest(BaseModel):
    scenarios: list[str] = Field(default_factory=lambda: ["all"])
    modes: list[MemoryMode] = Field(
        default_factory=lambda: [
            MemoryMode.no_memory,
            MemoryMode.short_term,
            MemoryMode.long_term,
            MemoryMode.hybrid,
        ]
    )
    runs_per_scenario: int = Field(default=1, ge=1, le=5)

    @field_validator("modes", mode="before")
    @classmethod
    def _coerce_modes(cls, v: Any) -> Any:
        if not isinstance(v, list):
            return v
        out = []
        for x in v:
            if isinstance(x, str) and x.strip().lower() == "none":
                out.append("no_memory")
            else:
                out.append(x)
        return out


class EvalScenarioResult(BaseModel):
    scenario_id: str
    memory_mode: MemoryMode
    turns: int
    retention_score: float
    consistency_score: float
    personalization_score: float
    aggregate: float
    latency_avg_ms: float = 0.0
    mitre_detected: list[str] = Field(default_factory=list)
    details: dict[str, Any] = Field(default_factory=dict)


class EvalRunResponse(BaseModel):
    run_id: str
    results: list[EvalScenarioResult]
    summary_by_mode: dict[str, dict[str, float]]
    dataset_source: str = "unknown"


class LTMMetaEntry(BaseModel):
    id: int
    session_id: str | None
    timestamp: str | None
    scenario_tag: str | None
    memory_mode: str | None
    retrieval_count: int
    excerpt: str
    similarity_on_list: float | None = None
    shared: bool = False


class MemoryShareRequest(BaseModel):
    shared: bool = True


class MemoryListResponse(BaseModel):
    entries: list[LTMMetaEntry]
    total_size_kb: float
