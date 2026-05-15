"""
Stream a subset from official LANL auth dataset (.bz2) into CSV for evaluation.

Default source:
  https://csr.lanl.gov/data/auth/lanl-auth-dataset-1-00.bz2

Usage (repo root):
  python scripts/fetch_lanl_subset.py --rows 10000
"""

from __future__ import annotations

import argparse
import bz2
import csv
import urllib.parse
import urllib.request
from pathlib import Path

DEFAULT_BASE_FILE = "lanl-auth-dataset-1-00.bz2"


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("--url", default="", help="Optional direct bz2 URL (advanced)")
    p.add_argument("--file", default=DEFAULT_BASE_FILE, help="LANL file name under auth/")
    p.add_argument("--email", default="student@example.com", help="Email for LANL data-fence token")
    p.add_argument("--usage", default="academic siem memory evaluation project", help="Usage text for token request")
    p.add_argument("--rows", type=int, default=10000, help="Rows to extract")
    p.add_argument(
        "--output",
        default=str(Path("backend") / "data" / "lanl_auth_sample.csv"),
        help="Output CSV path",
    )
    return p.parse_args()


def transform_row(parts: list[str]) -> dict[str, str] | None:
    """
    LANL auth row commonly has:
    time,src_user,dst_user,src_computer,dst_computer,auth_type,logon_type,auth_orient,success
    """
    if len(parts) < 9:
        return None
    time, src_user, dst_user, src_computer, dst_computer, _auth_type, _logon_type, _auth_orient, success = parts[:9]
    result = "SUCCESS" if success.strip().upper() in {"1", "T", "TRUE", "SUCCESS"} else "FAIL"
    user = src_user.strip() or dst_user.strip() or "UNKNOWN"
    src = src_computer.strip() or "SRC-HOST"
    dst = dst_computer.strip() or "DST-HOST"
    return {
        "timestamp": time.strip(),
        "user": user,
        "src_host": src,
        "dst_host": dst,
        "result": result,
        "src_ip": src,
    }


def main() -> int:
    args = parse_args()
    out_path = Path(args.output).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if args.url:
        dataset_url = args.url
    else:
        token_params = urllib.parse.urlencode({"email": args.email, "usage": args.usage})
        token_url = f"https://csr.lanl.gov/data-fence/token?{token_params}"
        with urllib.request.urlopen(token_url, timeout=60) as r:
            token = r.read().decode("utf-8", errors="ignore").strip()
        dataset_url = f"https://csr.lanl.gov/data-fence/{token}/auth/{args.file}"
        print(f"token_acquired file={args.file}")

    kept = 0
    with out_path.open("w", encoding="utf-8", newline="") as out:
        writer = csv.DictWriter(
            out,
            fieldnames=["timestamp", "user", "src_host", "dst_host", "result", "src_ip"],
        )
        writer.writeheader()
        with urllib.request.urlopen(dataset_url, timeout=120) as resp:
            with bz2.BZ2File(resp) as src:
                for raw in src:
                    line = raw.decode("utf-8", errors="ignore").strip()
                    if not line:
                        continue
                    row = transform_row(line.split(","))
                    if not row:
                        continue
                    writer.writerow(row)
                    kept += 1
                    if kept >= args.rows:
                        break

    print(f"wrote_rows={kept} output={out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

