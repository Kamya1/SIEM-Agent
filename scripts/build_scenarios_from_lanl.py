"""
Build evaluation scenarios from an *open* authentication log dataset.

This script is intentionally lightweight for course demos:
- You provide a small CSV extract (few thousand lines) from a standard dataset (e.g., LANL auth).
- The script emits `backend/data/scenarios.generated.json` in the same schema as `scenarios.json`.

Expected CSV columns (you can rename by editing COLUMN_MAP below):
  - timestamp
  - user
  - src_host
  - dst_host
  - result   (e.g., "FAIL" / "SUCCESS")
  - src_ip   (optional)

Usage (from repo root):
  python scripts/build_scenarios_from_lanl.py path\\to\\auth_sample.csv
"""

from __future__ import annotations

import csv
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path


COLUMN_MAP = {
    "timestamp": "timestamp",
    "user": "user",
    "src_host": "src_host",
    "dst_host": "dst_host",
    "result": "result",
    "src_ip": "src_ip",
}


def _norm(v: str) -> str:
    return (v or "").strip()


def build_failed_login_scenarios(rows: list[dict[str, str]], top_n: int = 2) -> list[dict]:
    """
    Pick the top users by FAIL count and generate 3-turn scenarios:
      turn0: establish user + rough context
      turn1: retention question (who had failed logins?)
      turn2: personalization instruction + consistency check (include MITRE)
    """
    fail_rows = [r for r in rows if _norm(r.get(COLUMN_MAP["result"], "")).upper().startswith("F")]
    by_user = Counter(_norm(r.get(COLUMN_MAP["user"], "UNKNOWN")) for r in fail_rows)
    top_users = [u for u, _ in by_user.most_common(top_n) if u]

    scenarios: list[dict] = []
    for idx, user in enumerate(top_users, start=1):
        user_fails = [r for r in fail_rows if _norm(r.get(COLUMN_MAP["user"], "")) == user]
        src_ips = Counter(_norm(r.get(COLUMN_MAP["src_ip"], "")) for r in user_fails if _norm(r.get(COLUMN_MAP["src_ip"], "")))
        ip = (src_ips.most_common(1)[0][0] if src_ips else "<SRC_IP>")
        case = f"LANL-FAIL-{idx:03d}"

        scenarios.append(
            {
                "id": f"lanl-failed-logins-{idx:03d}",
                "title": "Failed logins (LANL-derived)",
                "dataset_note": "Derived from a small extract of the LANL Authentication Dataset (failed logins).",
                "preseed_ltm": [],
                "turns": [
                    f"From dataset case {case}: user {user} had repeated failed logins from {ip} in a short window.",
                    "Which user had failed login attempts? Reply with the exact username token.",
                    "I prefer every answer to include a line labeled MITRE: with one technique ID. What should we check next?",
                ],
                "expect": {
                    "retention_any": [user],
                    "personalization_any": ["MITRE:", "T1110", "T1078"],
                    "consistency_any": [user, ip, case],
                },
            }
        )
    return scenarios


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: python scripts/build_scenarios_from_lanl.py path\\\\to\\\\auth_sample.csv")
        return 2

    csv_path = Path(sys.argv[1]).expanduser().resolve()
    if not csv_path.is_file():
        print(f"Not found: {csv_path}")
        return 2

    rows: list[dict[str, str]] = []
    with csv_path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for r in reader:
            rows.append(r)

    scenarios = build_failed_login_scenarios(rows, top_n=2)

    out_path = Path(__file__).resolve().parents[1] / "backend" / "data" / "scenarios.generated.json"
    out_path.write_text(json.dumps(scenarios, indent=2), encoding="utf-8")
    print(f"Wrote {len(scenarios)} scenarios to {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

