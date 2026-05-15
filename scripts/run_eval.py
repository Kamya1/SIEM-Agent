"""CLI: run benchmark (requires backend deps). Usage: python scripts/run_eval.py from repo root."""

import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.services.evaluation import run_evaluation  # noqa: E402


async def main() -> None:
    scenarios = ROOT / "backend" / "data" / "scenarios.json"
    run_id, results, summary, source = await run_evaluation(scenarios)
    print("run_id:", run_id)
    print("source:", source)
    print(json.dumps(summary, indent=2))
    for r in results:
        print(
            r.scenario_id,
            r.memory_mode.value,
            f"R={r.retention_score} P={r.personalization_score} C={r.consistency_score} A={r.aggregate:.2f}",
        )


if __name__ == "__main__":
    asyncio.run(main())
