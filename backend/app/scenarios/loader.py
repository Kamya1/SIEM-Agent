"""Load LANL-style auth CSV and derive evaluation scenarios."""

from __future__ import annotations

import csv
import json
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

from app.scenarios.definitions import (
    MITRE_BY_SCENARIO,
    RETENTION_KEYWORDS,
    SEVERITY_BY_SCENARIO,
    cross_session_scenario,
)


def _norm(v: str | None) -> str:
    return (v or "").strip()


def _parse_ts_seconds(raw: str) -> float:
    s = _norm(raw)
    if not s:
        return 0.0
    try:
        if s.isdigit():
            v = int(s)
            if v < 10_000_000_000:
                return float(v) * 3600.0
            return float(v)
        return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
    except Exception:
        try:
            return float(s)
        except Exception:
            return float(abs(hash(s)) % 1_000_000)


def load_lanl_rows(csv_path: Path, max_rows: int = 10_000) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    with csv_path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            return rows
        fields = {x.lower() for x in reader.fieldnames}
        is_official = {
            "timestamp",
            "user_id",
            "src_computer",
            "dst_computer",
            "auth_type",
            "logon_type",
            "auth_orientation",
            "success_failure",
        }.issubset(fields)
        is_simple = {"timestamp", "user", "src_host", "dst_host", "result"}.issubset(fields)
        is_lanl_like = {"time", "src_user", "dst_user", "src_computer", "dst_computer", "success"}.issubset(fields)
        for i, r in enumerate(reader):
            if i >= max_rows:
                break
            if is_official:
                ok = _norm(r.get("success_failure")).upper() in {"SUCCESS", "S", "1", "TRUE", "T"}
                rows.append(
                    {
                        "timestamp": _norm(r.get("timestamp")),
                        "user_id": _norm(r.get("user_id")),
                        "src_computer": _norm(r.get("src_computer")),
                        "dst_computer": _norm(r.get("dst_computer")),
                        "auth_type": _norm(r.get("auth_type")),
                        "logon_type": _norm(r.get("logon_type")),
                        "auth_orientation": _norm(r.get("auth_orientation")),
                        "success_failure": "SUCCESS" if ok else "FAIL",
                    }
                )
            elif is_simple:
                rows.append(
                    {
                        "timestamp": _norm(r.get("timestamp")),
                        "user_id": _norm(r.get("user")),
                        "src_computer": _norm(r.get("src_host")),
                        "dst_computer": _norm(r.get("dst_host")),
                        "auth_type": "",
                        "logon_type": "",
                        "auth_orientation": "",
                        "success_failure": "SUCCESS" if _norm(r.get("result")).upper().startswith("S") else "FAIL",
                    }
                )
            elif is_lanl_like:
                ok = _norm(r.get("success")).upper() in {"1", "T", "TRUE", "SUCCESS"}
                rows.append(
                    {
                        "timestamp": _norm(r.get("time")),
                        "user_id": _norm(r.get("src_user")) or _norm(r.get("dst_user")) or "UNKNOWN",
                        "src_computer": _norm(r.get("src_computer")),
                        "dst_computer": _norm(r.get("dst_computer")),
                        "auth_type": "",
                        "logon_type": "",
                        "auth_orientation": "",
                        "success_failure": "SUCCESS" if ok else "FAIL",
                    }
                )
    return rows


def _turn(user_msg: str, expected_keywords: list[str], personalization_phrase: str) -> dict[str, Any]:
    return {"user_msg": user_msg, "expected_keywords": expected_keywords, "personalization_phrase": personalization_phrase}


def build_scenarios_from_rows(rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    scenarios: list[dict[str, Any]] = []
    if not rows:
        return scenarios

    indexed = [(i, _parse_ts_seconds(r["timestamp"]), r) for i, r in enumerate(rows)]
    indexed.sort(key=lambda x: (x[1], x[0]))
    sorted_rows = [x[2] for x in indexed]

    fail_rows = [r for r in sorted_rows if not r["success_failure"].startswith("S")]
    effective = fail_rows or sorted_rows
    is_heuristic = not fail_rows

    # 1) failed logins
    by_user = Counter(_norm(r.get("user_id")) for r in effective if _norm(r.get("user_id")))
    top_user = by_user.most_common(1)[0][0] if by_user else "UserA"
    urows = [r for r in effective if _norm(r.get("user_id")) == top_user]
    src_c = Counter(_norm(r.get("src_computer")) for r in urows if _norm(r.get("src_computer")))
    src_ip = src_c.most_common(1)[0][0] if src_c else "10.24.8.71"
    case_id = "LANL-FAIL-001"
    scenarios.append(
        {
            "id": "lanl-failed-logins-001",
            "description": "Repeated failed authentication attempts for a single user/source pair.",
            "mitre_technique": MITRE_BY_SCENARIO["lanl-failed-logins-001"],
            "severity": SEVERITY_BY_SCENARIO["lanl-failed-logins-001"],
            "preseed_ltm": [],
            "turns": [
                _turn(
                    (
                        f"CASE={case_id}. User **User A** (USER={top_user}) shows repeated failed logins from SRC={src_ip}."
                        if not is_heuristic
                        else f"CASE={case_id}. Heuristic: USER={top_user} repeated suspicious auth from SRC={src_ip}."
                    ),
                    RETENTION_KEYWORDS["lanl-failed-logins-001"],
                    "Always include a line starting with MITRE: referencing a technique ID.",
                ),
                _turn(
                    "Map this to MITRE and list the top 3 investigative pivots.",
                    RETENTION_KEYWORDS["lanl-failed-logins-001"],
                    "Always include a line starting with MITRE: referencing a technique ID.",
                ),
                _turn(
                    "Same user yesterday — what would you compare in historical auth logs?",
                    RETENTION_KEYWORDS["lanl-failed-logins-001"],
                    "Reply in bullet points using '-' markers.",
                ),
                _turn(
                    "What containment actions do you recommend for the involved source?",
                    RETENTION_KEYWORDS["lanl-failed-logins-001"],
                    "Always include a line starting with MITRE: referencing a technique ID.",
                ),
            ],
        }
    )

    # 2) same source repeated
    src_counts = Counter(_norm(r.get("src_computer")) for r in effective if _norm(r.get("src_computer")))
    src = src_counts.most_common(1)[0][0] if src_counts else "SRC-1"
    users_from_src = Counter(_norm(r.get("user_id")) for r in effective if _norm(r.get("src_computer")) == src)
    pivot_user = users_from_src.most_common(1)[0][0] if users_from_src else top_user
    case_id = "LANL-SRC-001"
    scenarios.append(
        {
            "id": "lanl-same-source-repeated",
            "description": "Same source computer shows repeated suspicious authentication activity.",
            "mitre_technique": MITRE_BY_SCENARIO["lanl-same-source-repeated"],
            "severity": SEVERITY_BY_SCENARIO["lanl-same-source-repeated"],
            "preseed_ltm": [],
            "turns": [
                _turn(
                    f"CASE={case_id}. SRC={src} appears in repeated failed logins; sample user USER={pivot_user}.",
                    RETENTION_KEYWORDS["lanl-same-source-repeated"],
                    "Always include a line starting with MITRE: referencing a technique ID.",
                ),
                _turn(
                    "Provide MITRE mapping and explain why same-source repetition matters.",
                    RETENTION_KEYWORDS["lanl-same-source-repeated"],
                    "Always include a line starting with MITRE: referencing a technique ID.",
                ),
                _turn(
                    "Attribute this activity: what hypotheses fit a shared source token?",
                    RETENTION_KEYWORDS["lanl-same-source-repeated"],
                    "Reply in bullet points using '-' markers.",
                ),
                _turn(
                    "Recommend containment steps prioritizing least business disruption.",
                    RETENTION_KEYWORDS["lanl-same-source-repeated"],
                    "Always include a line starting with MITRE: referencing a technique ID.",
                ),
            ],
        }
    )

    # 3) suspicious sequence fail->success
    success_rows = [r for r in sorted_rows if r["success_failure"].startswith("S")]
    seq_user = ""
    seq_src = ""
    for r in effective:
        u = _norm(r.get("user_id"))
        s = _norm(r.get("src_computer"))
        if not u or not s:
            continue
        if any(
            _norm(x.get("user_id")) == u and _norm(x.get("src_computer")) == s for x in success_rows
        ):
            seq_user, seq_src = u, s
            break
    if not seq_user:
        seq_user, seq_src = top_user, src_ip
    case_id = "LANL-SEQ-001"
    scenarios.append(
        {
            "id": "lanl-suspicious-sequence",
            "description": "Failed attempts followed by success for the same user/source pair.",
            "mitre_technique": MITRE_BY_SCENARIO["lanl-suspicious-sequence"],
            "severity": SEVERITY_BY_SCENARIO["lanl-suspicious-sequence"],
            "preseed_ltm": [],
            "turns": [
                _turn(
                    f"CASE={case_id}. USER={seq_user} had repeated FAIL then SUCCESS from SRC={seq_src}.",
                    RETENTION_KEYWORDS["lanl-suspicious-sequence"],
                    "Always include a line starting with MITRE: referencing a technique ID.",
                ),
                _turn(
                    "Describe the anomaly pattern and why it is risky.",
                    RETENTION_KEYWORDS["lanl-suspicious-sequence"],
                    "Always include a line starting with MITRE: referencing a technique ID.",
                ),
                _turn(
                    "What MITRE techniques commonly align with this sequence?",
                    RETENTION_KEYWORDS["lanl-suspicious-sequence"],
                    "Reply in bullet points using '-' markers.",
                ),
                _turn(
                    "What should the SOC verify next in authentication telemetry?",
                    RETENTION_KEYWORDS["lanl-suspicious-sequence"],
                    "Always include a line starting with MITRE: referencing a technique ID.",
                ),
            ],
        }
    )

    # 4) privilege escalation heuristic
    user_primary_src: dict[str, str] = {}
    user_dst_hist: dict[str, set[str]] = defaultdict(set)
    for r in sorted_rows:
        u = _norm(r.get("user_id"))
        if not u:
            continue
        s = _norm(r.get("src_computer"))
        d = _norm(r.get("dst_computer"))
        if s and u not in user_primary_src:
            user_primary_src[u] = s
        if d:
            user_dst_hist[u].add(d)

    pe_user = top_user
    pe_src = user_primary_src.get(pe_user, src_ip)
    pe_admin = None
    pe_ts = 0.0
    for i, r in enumerate(sorted_rows):
        u = _norm(r.get("user_id"))
        if u != pe_user:
            continue
        s = _norm(r.get("src_computer"))
        d = _norm(r.get("dst_computer"))
        t = _parse_ts_seconds(r["timestamp"])
        if s != pe_src:
            continue
        if not d:
            continue
        if "admin" in d.lower() or "dc" in d.lower() or "srv" in d.lower():
            if d not in user_dst_hist.get(u, set()) or True:
                for r2 in sorted_rows[i + 1 : i + 50]:
                    if _norm(r2.get("user_id")) != u:
                        continue
                    t2 = _parse_ts_seconds(r2["timestamp"])
                    if 0 < t2 - t <= 60 and _norm(r2.get("dst_computer")) == d:
                        pe_admin = d
                        pe_ts = t2
                        break
            if pe_admin:
                break
    if not pe_admin:
        pe_admin = "ADMIN-DC-01"

    scenarios.append(
        {
            "id": "lanl-privilege-escalation",
            "description": "User authenticates from own workstation then quickly to a privileged destination.",
            "mitre_technique": MITRE_BY_SCENARIO["lanl-privilege-escalation"],
            "severity": SEVERITY_BY_SCENARIO["lanl-privilege-escalation"],
            "preseed_ltm": [],
            "turns": [
                _turn(
                    f"CASE=PE-001. USER={pe_user} authenticates from workstation SRC={pe_src}, then within 60s authenticates to admin destination DST={pe_admin} not seen before for this user.",
                    RETENTION_KEYWORDS["lanl-privilege-escalation"],
                    "Always include a line starting with MITRE: referencing a technique ID.",
                ),
                _turn(
                    "Provide MITRE mapping for this pattern.",
                    RETENTION_KEYWORDS["lanl-privilege-escalation"],
                    "Always include a line starting with MITRE: referencing a technique ID.",
                ),
                _turn(
                    "Was this same user active yesterday — what would you compare?",
                    RETENTION_KEYWORDS["lanl-privilege-escalation"],
                    "Reply in bullet points using '-' markers.",
                ),
                _turn(
                    "Recommend immediate containment actions.",
                    RETENTION_KEYWORDS["lanl-privilege-escalation"],
                    "Always include a line starting with MITRE: referencing a technique ID.",
                ),
            ],
        }
    )

    # 5) lateral movement: same src -> 5+ dst in 120s window
    by_time = sorted_rows
    lat_src = ""
    lat_dsts: list[str] = []
    for i, r in enumerate(by_time):
        s = _norm(r.get("src_computer"))
        if not s:
            continue
        t0 = _parse_ts_seconds(r["timestamp"])
        dsts: set[str] = set()
        for r2 in by_time[i : i + 400]:
            if _norm(r2.get("src_computer")) != s:
                continue
            if _parse_ts_seconds(r2["timestamp"]) - t0 > 120:
                break
            d = _norm(r2.get("dst_computer"))
            if d:
                dsts.add(d)
            if len(dsts) >= 5:
                lat_src = s
                lat_dsts = list(dsts)[:6]
                break
    if not lat_src:
        lat_src = src
        lat_dsts = list({r.get("dst_computer", "D") for r in sorted_rows[:50]})[:5] or ["D1", "D2", "D3", "D4", "D5"]

    scenarios.append(
        {
            "id": "lanl-lateral-movement",
            "description": "Single source authenticates to many destinations within a short interval.",
            "mitre_technique": MITRE_BY_SCENARIO["lanl-lateral-movement"],
            "severity": SEVERITY_BY_SCENARIO["lanl-lateral-movement"],
            "preseed_ltm": [],
            "turns": [
                _turn(
                    f"CASE=LAT-001. SRC={lat_src} authenticates to {len(lat_dsts)}+ destinations including {', '.join(lat_dsts[:5])} within 120 seconds.",
                    RETENTION_KEYWORDS["lanl-lateral-movement"],
                    "Always include a line starting with MITRE: referencing a technique ID.",
                ),
                _turn(
                    "Explain detection rationale and MITRE mapping.",
                    RETENTION_KEYWORDS["lanl-lateral-movement"],
                    "Always include a line starting with MITRE: referencing a technique ID.",
                ),
                _turn(
                    "Attribution hypotheses: benign vs malicious automation?",
                    RETENTION_KEYWORDS["lanl-lateral-movement"],
                    "Reply in bullet points using '-' markers.",
                ),
                _turn(
                    "Containment recommendations for the SOC.",
                    RETENTION_KEYWORDS["lanl-lateral-movement"],
                    "Always include a line starting with MITRE: referencing a technique ID.",
                ),
            ],
        }
    )

    # 6) after hours
    ah_row = None
    for r in sorted_rows:
        raw = _norm(r.get("timestamp"))
        hour = None
        try:
            if raw.isdigit() and len(raw) <= 10:
                hour = int(raw) % 24
            else:
                dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
                hour = dt.hour
        except Exception:
            hour = None
        if hour is None:
            continue
        if hour < 8 or hour >= 18:
            ah_row = r
            break
    if ah_row is None:
        ah_row = sorted_rows[0]
    ah_user = _norm(ah_row.get("user_id")) or top_user
    ah_src = _norm(ah_row.get("src_computer")) or src
    scenarios.append(
        {
            "id": "lanl-after-hours",
            "description": "Authentication observed outside business hours (08:00–18:00).",
            "mitre_technique": MITRE_BY_SCENARIO["lanl-after-hours"],
            "severity": SEVERITY_BY_SCENARIO["lanl-after-hours"],
            "preseed_ltm": [],
            "turns": [
                _turn(
                    f"CASE=AH-001. After-hours login: USER={ah_user} from SRC={ah_src} at timestamp={_norm(ah_row.get('timestamp'))}.",
                    RETENTION_KEYWORDS["lanl-after-hours"],
                    "Always include a line starting with MITRE: referencing a technique ID.",
                ),
                _turn(
                    "Why is after-hours authentication risky here?",
                    RETENTION_KEYWORDS["lanl-after-hours"],
                    "Always include a line starting with MITRE: referencing a technique ID.",
                ),
                _turn(
                    "What benign explanations should be ruled out first?",
                    RETENTION_KEYWORDS["lanl-after-hours"],
                    "Reply in bullet points using '-' markers.",
                ),
                _turn(
                    "What monitoring improvements would reduce false positives?",
                    RETENTION_KEYWORDS["lanl-after-hours"],
                    "Always include a line starting with MITRE: referencing a technique ID.",
                ),
            ],
        }
    )

    # 7) credential stuffing: 10+ users same src in 300s
    cs_src = ""
    cs_users: list[str] = []
    for i, r in enumerate(by_time):
        s = _norm(r.get("src_computer"))
        if not s:
            continue
        t0 = _parse_ts_seconds(r["timestamp"])
        users: set[str] = set()
        for r2 in by_time[i : i + 800]:
            if _norm(r2.get("src_computer")) != s:
                continue
            if _parse_ts_seconds(r2["timestamp"]) - t0 > 300:
                break
            u = _norm(r2.get("user_id"))
            if u:
                users.add(u)
            if len(users) >= 10:
                cs_src = s
                cs_users = list(users)[:12]
                break
    if not cs_src:
        cs_src = src
        cs_users = list(by_user.keys())[:11] or [f"U{i}" for i in range(11)]

    scenarios.append(
        {
            "id": "lanl-credential-stuffing",
            "description": "Many distinct user IDs authenticate from the same source within a short interval.",
            "mitre_technique": MITRE_BY_SCENARIO["lanl-credential-stuffing"],
            "severity": SEVERITY_BY_SCENARIO["lanl-credential-stuffing"],
            "preseed_ltm": [],
            "turns": [
                _turn(
                    f"CASE=CS-001. SRC={cs_src} shows {len(cs_users)}+ distinct users including {', '.join(cs_users[:5])} within 300 seconds.",
                    RETENTION_KEYWORDS["lanl-credential-stuffing"],
                    "Always include a line starting with MITRE: referencing a technique ID.",
                ),
                _turn(
                    "Explain MITRE-relevant attack patterns for this telemetry.",
                    RETENTION_KEYWORDS["lanl-credential-stuffing"],
                    "Always include a line starting with MITRE: referencing a technique ID.",
                ),
                _turn(
                    "Detection engineering: thresholds and enrichments?",
                    RETENTION_KEYWORDS["lanl-credential-stuffing"],
                    "Reply in bullet points using '-' markers.",
                ),
                _turn(
                    "Containment and recovery steps for identity teams.",
                    RETENTION_KEYWORDS["lanl-credential-stuffing"],
                    "Always include a line starting with MITRE: referencing a technique ID.",
                ),
            ],
        }
    )

    scenarios.append(cross_session_scenario(user=top_user, case="INC-2048"))
    return scenarios


def load_eval_scenarios(default_scenarios_path: Path) -> tuple[list[dict[str, Any]], str]:
    data_dir = default_scenarios_path.parent
    for name in ("lanl_auth_sample.csv", "lanl_auth_tiny.csv"):
        p = data_dir / name
        if p.is_file():
            rows = load_lanl_rows(p)
            built = build_scenarios_from_rows(rows)
            if built:
                return built, f"dataset:{p.name}"
    raw = json.loads(default_scenarios_path.read_text(encoding="utf-8"))
    if isinstance(raw, list):
        return raw, f"static:{default_scenarios_path.name}"
    return raw.get("scenarios", []), f"static:{default_scenarios_path.name}"
