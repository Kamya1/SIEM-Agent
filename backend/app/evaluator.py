"""Continuous evaluation metrics, multi-run consistency, exports, SSE support."""

from __future__ import annotations

import asyncio
import csv
import json
import re
import tempfile
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncIterator, Callable

from app.agent.siem_agent import SIEMAgent
from app.config import Settings, get_settings
from app.memory.manager import MemoryManager
from app.mitre_tagger import extract_mitre_techniques
from app.models.schemas import EvalScenarioResult, MemoryMode
from app.scenarios.loader import load_eval_scenarios

MEMORY_FAIL_PHRASES = (
    "i don't have context",
    "don't have context",
    "could you clarify",
    "no prior context",
    "i do not have access",
)


def _tokens(text: str) -> set[str]:
    return {t for t in re.findall(r"[a-zA-Z0-9._:/@-]+", (text or "").lower()) if len(t) > 2}


def jaccard_texts(a: str, b: str) -> float:
    sa, sb = _tokens(a), _tokens(b)
    if not sa and not sb:
        return 1.0
    u = sa | sb
    if not u:
        return 1.0
    return len(sa & sb) / len(u)


def triple_consistency_score(texts: list[str]) -> float:
    if len(texts) < 2:
        return 1.0
    if len(texts) == 2:
        return jaccard_texts(texts[0], texts[1])
    pairs = [
        jaccard_texts(texts[0], texts[1]),
        jaccard_texts(texts[0], texts[2]),
        jaccard_texts(texts[1], texts[2]),
    ]
    return sum(pairs) / len(pairs)


def _entity_tokens_from_scenario(first_user_msg: str) -> tuple[set[str], set[str]]:
    users = set(re.findall(r"USER=([A-Za-z0-9._:-]+)", first_user_msg, flags=re.I))
    ips = set(re.findall(r"SRC=([A-Za-z0-9._:/.\[\]]+)", first_user_msg, flags=re.I))
    users |= set(re.findall(r"\*\*User A\*\*", first_user_msg, flags=re.I))
    return users, ips


def retention_for_response(
    response: str,
    expected_keywords: list[str],
    entity_users: set[str],
    entity_ips: set[str],
) -> float:
    low = (response or "").lower()
    if not expected_keywords:
        base = 1.0
    else:
        hits = sum(1 for k in expected_keywords if k.lower() in low)
        base = hits / len(expected_keywords)
    bonus = 0.0
    for u in entity_users:
        if u and u.lower() in low:
            bonus += 0.05
    for ip in entity_ips:
        if ip and ip.lower() in low:
            bonus += 0.05
    bonus = min(0.1, bonus)
    score = min(1.0, base + bonus)
    if any(p in low for p in MEMORY_FAIL_PHRASES):
        score = max(0.0, score - 0.2)
    return score


def personalization_for_response(response: str, phrase: str) -> float:
    if not (phrase or "").strip():
        return 1.0
    low = response.lower()
    score_bits = 0.0
    parts = 0
    if "mitre:" in phrase.lower():
        parts += 1
        if "mitre:" in low:
            score_bits += 1.0
    if "bullet" in phrase.lower():
        parts += 1
        if "•" in response or "\n-" in response or re.search(r"(^|\n)\s*-\s+", response):
            score_bits += 1.0
    if parts == 0:
        return 1.0
    return score_bits / parts


async def measure_consistency(
    agent: SIEMAgent,
    messages: list[dict[str, str]],
    system_addon: str | None,
) -> float:
    texts: list[str] = []
    for _ in range(3):
        t = await agent.complete(messages, system_addon=system_addon, temperature=0.3, max_tokens=512)
        texts.append(t)
    return triple_consistency_score(texts)


def append_eval_history(data_dir: Path, record: dict[str, Any]) -> None:
    path = data_dir / "eval_history.json"
    hist: list[dict[str, Any]] = []
    if path.is_file():
        try:
            hist = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            hist = []
    hist.append(record)
    path.write_text(json.dumps(hist, indent=2), encoding="utf-8")


def export_results(data_dir: Path, results: list[EvalScenarioResult], summary: dict[str, dict[str, float]], source: str) -> None:
    data_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "dataset_source": source,
        "summary_by_mode": summary,
        "results": [r.model_dump(mode="json") for r in results],
    }
    (data_dir / "results.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")

    csv_path = data_dir / "results.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(
            [
                "scenario_id",
                "memory_mode",
                "retention",
                "consistency",
                "personalization",
                "aggregate",
                "latency_avg_ms",
                "mitre_detected",
            ]
        )
        for r in results:
            w.writerow(
                [
                    r.scenario_id,
                    r.memory_mode.value,
                    f"{r.retention_score:.4f}",
                    f"{r.consistency_score:.4f}",
                    f"{r.personalization_score:.4f}",
                    f"{r.aggregate:.4f}",
                    f"{r.latency_avg_ms:.1f}",
                    ";".join(r.mitre_detected),
                ]
            )

    md_lines = [
        "# Evaluation report",
        "",
        f"- Source: `{source}`",
        "",
        "## Summary by mode",
        "",
        "| Mode | Retention | Consistency | Personalization | Aggregate |",
        "|------|-----------|-------------|-----------------|-----------|",
    ]
    for mode, s in summary.items():
        md_lines.append(
            f"| {mode} | {s.get('retention_avg', 0):.3f} | {s.get('consistency_avg', 0):.3f} | "
            f"{s.get('personalization_avg', 0):.3f} | {s.get('aggregate_avg', 0):.3f} |"
        )
    md_lines.append("")
    md_lines.append("## Per scenario")
    md_lines.append("")
    md_lines.append("| Scenario | Mode | R | C | P | Agg | Latency ms |")
    md_lines.append("|----------|------|---|---|---|-----|------------|")
    for r in results:
        md_lines.append(
            f"| {r.scenario_id} | {r.memory_mode.value} | {r.retention_score:.2f} | {r.consistency_score:.2f} | "
            f"{r.personalization_score:.2f} | {r.aggregate:.2f} | {r.latency_avg_ms:.0f} |"
        )
    (data_dir / "eval_report.md").write_text("\n".join(md_lines), encoding="utf-8")


async def run_evaluation_job(
    scenarios_path: Path,
    *,
    scenario_filter: list[str] | None,
    modes: list[MemoryMode] | None,
    runs_per_scenario: int = 1,
    progress: Callable[[dict[str, Any]], None] | None = None,
    settings: Settings | None = None,
) -> tuple[str, list[EvalScenarioResult], dict[str, dict[str, float]], str]:
    settings = settings or get_settings()
    raw, source = load_eval_scenarios(scenarios_path)
    if scenario_filter and "all" not in scenario_filter:
        raw = [s for s in raw if s.get("id") in set(scenario_filter)]
    modes = modes or list(MemoryMode)
    run_id = str(uuid.uuid4())
    agent = SIEMAgent(settings)
    results: list[EvalScenarioResult] = []

    for scenario in raw:
        sid = scenario["id"]
        for mode in modes:
            for rep in range(max(1, runs_per_scenario)):
                tmp = tempfile.mkdtemp(prefix="siem-eval-")
                data_dir = Path(tmp) / "data"
                data_dir.mkdir(parents=True, exist_ok=True)
                d = settings.model_dump()
                d["data_dir"] = str(data_dir.resolve())
                d["db_path"] = str((data_dir / "ltm_store.db").resolve())
                mgr = MemoryManager(Settings(**d))
                for chunk in scenario.get("preseed_ltm", []):
                    text = chunk["text"] if isinstance(chunk, dict) else str(chunk)
                    mgr.ltm_store.try_store_exchange(
                        session_id="__preseed__",
                        user_msg=text[:2000],
                        assistant_msg="(preseed)",
                        memory_mode="long_term",
                        scenario_tag="preseed",
                    )

                session_id = f"eval-{sid}-{mode.value}-{run_id[:8]}-{rep}"
                assistant_turns: list[str] = []
                latencies: list[float] = []
                reset_at = scenario.get("reset_session_before_turn_index")

                first_turn_msg = scenario["turns"][0]["user_msg"] if scenario.get("turns") else ""
                entity_users, entity_ips = _entity_tokens_from_scenario(first_turn_msg)

                async def compress_fn(prompt: str) -> str:
                    return await agent.complete(
                        [{"role": "user", "content": prompt}],
                        system_addon="You compress analyst chat for SIEM investigations.",
                        temperature=0.2,
                        max_tokens=400,
                    )

                for turn_idx, turn in enumerate(scenario["turns"]):
                    if reset_at is not None and turn_idx == int(reset_at):
                        mgr.clear_session(session_id)
                        session_id = f"{session_id}-b"

                    user_text = turn["user_msg"]
                    mgr.maybe_capture_preference(session_id, user_text)
                    hist, preview = mgr.build_context(session_id, mode, user_text)
                    msgs = [*hist, {"role": "user", "content": user_text}]
                    system_addon = preview.get("system_addon") or None

                    t0 = time.perf_counter()
                    reply = await agent.complete(msgs, system_addon=system_addon, temperature=0.3, max_tokens=900)
                    latencies.append((time.perf_counter() - t0) * 1000)
                    assistant_turns.append(reply)
                    await mgr.finalize_turn(
                        session_id,
                        user_text,
                        reply,
                        mode,
                        scenario_tag=sid,
                        compress_fn=compress_fn,
                    )

                ret_scores: list[float] = []
                pers_scores: list[float] = []
                for turn, aresp in zip(scenario["turns"], assistant_turns):
                    ret_scores.append(
                        retention_for_response(aresp, turn.get("expected_keywords", []), entity_users, entity_ips)
                    )
                    pers_scores.append(
                        personalization_for_response(aresp, turn.get("personalization_phrase", ""))
                    )
                retention = sum(ret_scores) / max(1, len(ret_scores))
                personalization = sum(pers_scores) / max(1, len(pers_scores))

                last_user = scenario["turns"][-1]["user_msg"]
                hist, preview = mgr.build_context(session_id, mode, last_user)
                msgs = [*hist, {"role": "user", "content": last_user}]
                system_addon = preview.get("system_addon") or None
                consistency = await measure_consistency(agent, msgs, system_addon)

                aggregate = 0.4 * retention + 0.3 * consistency + 0.3 * personalization
                mitre_all: list[str] = []
                for t in assistant_turns:
                    mitre_all.extend(extract_mitre_techniques(t))
                mitre_all = list(dict.fromkeys(mitre_all))

                latency_avg = sum(latencies) / max(1, len(latencies))

                row = EvalScenarioResult(
                    scenario_id=sid,
                    memory_mode=mode,
                    turns=len(scenario["turns"]),
                    retention_score=round(retention, 4),
                    consistency_score=round(consistency, 4),
                    personalization_score=round(personalization, 4),
                    aggregate=round(aggregate, 4),
                    latency_avg_ms=round(latency_avg, 2),
                    mitre_detected=mitre_all,
                    details={"assistant_turns_preview": [t[:400] for t in assistant_turns]},
                )
                results.append(row)
                if progress:
                    progress(
                        {
                            "type": "progress",
                            "scenario": sid,
                            "mode": mode.value,
                            "retention": row.retention_score,
                            "aggregate": row.aggregate,
                        }
                    )

    summary: dict[str, dict[str, float]] = {}
    lat_by_mode: dict[str, list[float]] = defaultdict(list)
    for r in results:
        lat_by_mode[r.memory_mode.value].append(r.latency_avg_ms)
    for mode in MemoryMode:
        subset = [r for r in results if r.memory_mode == mode]
        if not subset:
            continue
        summary[mode.value] = {
            "retention_avg": sum(x.retention_score for x in subset) / len(subset),
            "consistency_avg": sum(x.consistency_score for x in subset) / len(subset),
            "personalization_avg": sum(x.personalization_score for x in subset) / len(subset),
            "aggregate_avg": sum(x.aggregate for x in subset) / len(subset),
            "latency_avg_ms": sum(lat_by_mode[mode.value]) / max(1, len(lat_by_mode[mode.value])),
        }

    data_dir = settings.data_path
    export_results(data_dir, results, summary, source)
    append_eval_history(
        data_dir,
        {
            "run_id": run_id,
            "ts": datetime.now(timezone.utc).isoformat(),
            "summary_by_mode": summary,
            "source": source,
        },
    )
    return run_id, results, summary, source


async def eval_sse_stream(body: dict[str, Any], scenarios_path: Path, settings: Settings) -> AsyncIterator[str]:
    from app.models.schemas import EvalRunRequest

    req = EvalRunRequest.model_validate(body)

    queue: asyncio.Queue[dict[str, Any] | None] = asyncio.Queue()

    def progress(evt: dict[str, Any]) -> None:
        queue.put_nowait(evt)

    async def worker() -> None:
        try:
            run_id, results, summary, source = await run_evaluation_job(
                scenarios_path,
                scenario_filter=req.scenarios,
                modes=req.modes,
                runs_per_scenario=req.runs_per_scenario,
                progress=progress,
                settings=settings,
            )
            queue.put_nowait(
                {
                    "type": "complete",
                    "run_id": run_id,
                    "results": [r.model_dump(mode="json") for r in results],
                    "summary_by_mode": summary,
                    "dataset_source": source,
                }
            )
        except Exception as e:
            queue.put_nowait({"type": "error", "message": str(e)})
        finally:
            queue.put_nowait(None)

    task = asyncio.create_task(worker())
    try:
        while True:
            evt = await queue.get()
            if evt is None:
                break
            yield f"data: {json.dumps(evt)}\n\n"
    finally:
        await task
