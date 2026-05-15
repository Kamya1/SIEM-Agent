"""Backward-compatible evaluation entrypoint."""

from __future__ import annotations

from pathlib import Path

from app.config import get_settings
from app.evaluator import run_evaluation_job
from app.models.schemas import EvalRunRequest, EvalScenarioResult, MemoryMode


async def run_evaluation(
    scenarios_path: Path,
) -> tuple[str, list[EvalScenarioResult], dict[str, dict[str, float]], str]:
    req = EvalRunRequest()
    return await run_evaluation_job(
        scenarios_path,
        scenario_filter=req.scenarios,
        modes=list(MemoryMode),
        runs_per_scenario=req.runs_per_scenario,
        progress=None,
        settings=get_settings(),
    )
