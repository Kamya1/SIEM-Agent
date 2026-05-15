from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Annotated

from fastapi import Body, FastAPI, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from app.agent.siem_agent import SIEMAgent
from app.config import get_settings
from app.evaluator import eval_sse_stream, run_evaluation_job
from app.memory.manager import MemoryManager
from app.mitre_tagger import extract_mitre_techniques
from app.models.schemas import (
    ChatRequest,
    ChatResponse,
    EvalRunRequest,
    EvalRunResponse,
    LTMMetaEntry,
    MemoryListResponse,
    MemoryMode,
    MemoryShareRequest,
    SecurityEvent,
)
from app.security import access_guard, audit_log, encryptor, pii_detector, sanitizer, threat_detector
from app.security_log import count_poisoning_attempts

settings = get_settings()
app = FastAPI(title="Agentic SIEM Analyst", version="2.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5173", "http://localhost:5173", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

_mgr = MemoryManager()
_agent = SIEMAgent()
_SCENARIOS = Path(__file__).resolve().parent.parent / "data" / "scenarios.json"


def _clear_stm(sid: str) -> None:
    _mgr.clear_session(sid)


@app.get("/api/health")
def health() -> dict[str, str | int | bool]:
    key, model = settings.resolved_groq()
    data_dir = settings.data_path
    return {
        "status": "ok",
        "groq_connected": bool(key),
        "ltm_entry_count": _mgr.ltm_store.entry_count(),
        "stm_sessions_active": _mgr.active_stm_sessions(),
        "model": model if key else "not configured (using mock)",
        "memory_poisoning_attempts": count_poisoning_attempts(data_dir),
        "ltm_encrypted": encryptor.encryption_enabled(),
        "audit_log_entries": audit_log.verify_log_integrity().get("total", 0),
    }


@app.get("/api/security/status")
def security_status(session_id: str = Query(..., min_length=1)) -> dict:
    access_guard.register_session(session_id)
    info = access_guard.session_info(session_id)
    return {
        "session": info,
        "requests_this_minute": access_guard.requests_this_minute(session_id),
        "rate_limit_max": 30,
        "ltm_encrypted": encryptor.encryption_enabled(),
    }


@app.get("/api/audit/trail")
def audit_trail(session_id: str = Query(..., min_length=1), limit: int = Query(50, ge=1, le=200)) -> list[dict]:
    return audit_log.get_session_audit_trail(session_id, limit=limit)


@app.get("/api/audit/verify")
def audit_verify() -> dict:
    return audit_log.verify_log_integrity()


@app.post("/api/chat", response_model=ChatResponse)
async def chat(req: ChatRequest, response: Response) -> ChatResponse:
    t0 = time.perf_counter()

    # Session registration / expiry
    effective_sid, rotated = access_guard.ensure_session(req.session_id, _clear_stm)
    if rotated:
        audit_log.log_event(req.session_id, "SESSION_EXPIRE", {"rotated_to": effective_sid})

    # Rate limit
    limited, retry_after = access_guard.is_rate_limited(effective_sid)
    if limited:
        audit_log.log_event(effective_sid, "RATE_LIMITED", {"retry_after": retry_after})
        response.headers["Retry-After"] = str(retry_after)
        raise HTTPException(status_code=429, detail=f"Too many requests. Retry after {retry_after}s.")

    raw_input = req.message

    # Threat detection
    threat = threat_detector.analyze_threat(raw_input)
    if threat["should_block"]:
        audit_log.log_event(
            effective_sid,
            "INJECTION_BLOCKED",
            {"reason": threat["explanation"], "threat_score": threat["threat_score"]},
        )
        sec = SecurityEvent(
            threat_score=threat["threat_score"],
            threat_type=threat.get("threat_type"),
            should_block=True,
            explanation=threat["explanation"],
            shield="blocked",
            effective_session_id=effective_sid,
            session_rotated=rotated,
        )
        return ChatResponse(
            reply=f"⚠️ Input blocked: {threat['explanation']}",
            memory_mode=req.memory_mode,
            context_preview={"blocked": True},
            security_warning=threat["explanation"],
            security_event=sec,
            session_id=effective_sid,
        )

    store_in_memory = threat["threat_score"] < 0.3
    shield = "clean"
    sec_warn: str | None = None
    if 0.3 <= threat["threat_score"] < 0.7:
        shield = "flagged"
        sec_warn = threat["explanation"]
        audit_log.log_event(
            effective_sid,
            "SECURITY_ALERT",
            {"threat_score": threat["threat_score"], "reason": threat["explanation"]},
        )

    # Sanitize + PII
    sanitized = sanitizer.sanitize(raw_input)
    pii_result = pii_detector.detect_and_redact(sanitized["clean_text"])
    safe_input = pii_result["redacted_text"]

    if pii_result["redaction_count"] > 0:
        shield = "pii" if shield == "clean" else shield
        audit_log.log_event(
            effective_sid,
            "PII_DETECTED",
            {
                "pii_types_found": pii_result["pii_found"],
                "redaction_count": pii_result["redaction_count"],
            },
        )

    audit_log.log_event(
        effective_sid,
        "STM_STORE",
        {
            "memory_mode": req.memory_mode.value,
            "was_sanitized": sanitized["was_modified"],
            "pii_types_found": pii_result["pii_found"],
            "redaction_count": pii_result["redaction_count"],
            "threat_score": threat["threat_score"],
            "flags": sanitized["flags"],
            "input_length": len(raw_input),
        },
    )

    _mgr.maybe_capture_preference(effective_sid, safe_input)
    hist, preview = _mgr.build_context(effective_sid, req.memory_mode, safe_input)
    messages = [*hist, {"role": "user", "content": safe_input}]
    system_addon = preview.get("system_addon") or None
    reply = await _agent.complete(messages, system_addon=system_addon)

    # Redact assistant reply before memory storage (defense in depth)
    asst_sanitized = sanitizer.sanitize(reply)
    asst_pii = pii_detector.detect_and_redact(asst_sanitized["clean_text"])
    safe_reply = asst_pii["redacted_text"]

    await _mgr.finalize_turn(
        effective_sid,
        safe_input,
        safe_reply,
        req.memory_mode,
        scenario_tag=req.scenario_tag,
        compress_fn=lambda p: _agent.complete(
            [{"role": "user", "content": p}],
            system_addon="You compress analyst chat for SIEM investigations.",
            temperature=0.2,
            max_tokens=400,
        ),
        store_in_memory=store_in_memory,
    )

    preview["latency_ms"] = round((time.perf_counter() - t0) * 1000, 2)
    mitre = extract_mitre_techniques(reply)

    sec_event = SecurityEvent(
        threat_score=threat["threat_score"],
        threat_type=threat.get("threat_type"),
        should_block=False,
        explanation=threat["explanation"],
        shield=shield,
        pii_found=pii_result["pii_found"],
        redaction_count=pii_result["redaction_count"],
        sanitize_flags=sanitized["flags"],
        effective_session_id=effective_sid,
        session_rotated=rotated,
    )

    return ChatResponse(
        reply=reply,
        memory_mode=req.memory_mode,
        context_preview=preview,
        mitre_techniques=mitre,
        security_warning=sec_warn,
        security_event=sec_event,
        session_id=effective_sid,
    )


@app.post("/api/session/reset")
def reset_session(session_id: str) -> dict[str, str]:
    _mgr.clear_session(session_id)
    return {"status": "cleared", "session_id": session_id}


@app.post("/api/eval/run")
async def eval_run(request: Request) -> StreamingResponse:
    body: dict = {}
    if request.headers.get("content-type", "").startswith("application/json"):
        try:
            body = await request.json()
        except Exception:
            body = {}
    if not body:
        body = EvalRunRequest().model_dump(mode="json")

    async def gen():
        async for chunk in eval_sse_stream(body, _SCENARIOS, settings):
            yield chunk

    return StreamingResponse(gen(), media_type="text/event-stream")


@app.post("/api/eval/run_sync", response_model=EvalRunResponse)
async def eval_run_sync(req: Annotated[EvalRunRequest | None, Body()] = None) -> EvalRunResponse:
    r = req or EvalRunRequest()
    run_id, results, summary, source = await run_evaluation_job(
        _SCENARIOS,
        scenario_filter=r.scenarios,
        modes=r.modes,
        runs_per_scenario=r.runs_per_scenario,
        progress=None,
        settings=settings,
    )
    return EvalRunResponse(run_id=run_id, results=results, summary_by_mode=summary, dataset_source=source)


@app.get("/api/memory/list", response_model=MemoryListResponse)
def memory_list(session_id: str | None = Query(None)) -> MemoryListResponse:
    rows = _mgr.ltm_store.list_entries(session_id=session_id)
    entries = [
        LTMMetaEntry(
            id=int(r["id"]),
            session_id=r.get("session_id"),
            timestamp=r.get("timestamp"),
            scenario_tag=r.get("scenario_tag"),
            memory_mode=r.get("memory_mode"),
            retrieval_count=int(r.get("retrieval_count") or 0),
            excerpt=((r.get("user_msg") or "") + " | " + (r.get("assistant_msg") or ""))[:100],
            shared=bool(r.get("shared")),
        )
        for r in rows
    ]
    kb = _mgr.ltm_store.db_file_size_bytes() / 1024.0
    return MemoryListResponse(entries=entries, total_size_kb=round(kb, 2))


@app.patch("/api/memory/share/{entry_id}")
def memory_share(entry_id: int, body: MemoryShareRequest, session_id: str = Query(...)) -> dict[str, str | bool]:
    ok = _mgr.ltm_store.set_shared(entry_id, body.shared)
    if not ok:
        raise HTTPException(status_code=404, detail="entry not found")
    audit_log.log_event(session_id, "LTM_STORE", {"action": "share_toggle", "entry_id": entry_id, "shared": body.shared})
    return {"status": "ok", "id": entry_id, "shared": body.shared}


@app.delete("/api/memory/delete/{entry_id}")
def memory_delete(entry_id: int, session_id: str | None = Query(None)) -> dict[str, str | bool]:
    ok = _mgr.ltm_store.delete(entry_id, session_id=session_id)
    if not ok:
        raise HTTPException(status_code=404, detail="entry not found")
    return {"status": "deleted", "id": entry_id}


@app.delete("/api/memory/clear")
def memory_clear() -> dict[str, int]:
    n = _mgr.ltm_store.clear_all()
    return {"deleted": n}


@app.get("/api/eval/history")
def eval_history() -> list[dict]:
    path = settings.data_path / "eval_history.json"
    if not path.is_file():
        return []
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []


@app.get("/api/eval/export")
def eval_export() -> FileResponse:
    path = settings.data_path / "results.csv"
    if not path.is_file():
        raise HTTPException(status_code=404, detail="results.csv not found; run evaluation first")
    return FileResponse(path, filename="results.csv", media_type="text/csv")


@app.get("/api/eval/report_md")
def eval_report_md() -> FileResponse:
    path = settings.data_path / "eval_report.md"
    if not path.is_file():
        raise HTTPException(status_code=404, detail="eval_report.md not found; run evaluation first")
    return FileResponse(path, filename="eval_report.md", media_type="text/markdown")


_frontend = Path(__file__).resolve().parent.parent.parent / "frontend" / "dist"
if _frontend.is_dir():
    app.mount("/", StaticFiles(directory=str(_frontend), html=True), name="static")


def create_app() -> FastAPI:
    return app
