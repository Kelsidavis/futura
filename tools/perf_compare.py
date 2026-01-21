#!/usr/bin/env python3
"""Compare performance harness output against a stored baseline.

Copyright (c) 2025 Kelsi Davis
Licensed under the MPL v2.0 — see LICENSE for details.
"""

import json
import math
import re
import sys
from pathlib import Path

METRIC_PATTERN = re.compile(r"\[PERF\]\s+(\S+)\s+p50=(\d+)\s+p90=(\d+)\s+p99=(\d+)")

THRESHOLD = 5.0  # percent


def load_baseline(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    return data


def parse_latest(path: Path) -> dict:
    latest = {}
    with path.open("r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            match = METRIC_PATTERN.search(line)
            if not match:
                continue
            name = match.group(1)
            latest[name] = {
                "p50": int(match.group(2)),
                "p90": int(match.group(3)),
                "p99": int(match.group(4)),
            }
    return latest


def compare_metrics(baseline: dict, latest: dict) -> int:
    failures = []
    for metric, expected in baseline.items():
        if metric not in latest:
            failures.append(f"missing metric '{metric}' in latest run")
            continue
        measured = latest[metric]
        for percentile in ("p50", "p90", "p99"):
            base_val = expected.get(percentile)
            curr_val = measured.get(percentile)
            if base_val is None or curr_val is None:
                failures.append(f"metric '{metric}' missing percentile '{percentile}'")
                continue
            if base_val == 0:
                continue
            delta = ((curr_val - base_val) / base_val) * 100.0
            if math.fabs(delta) > THRESHOLD:
                failures.append(
                    f"{metric}:{percentile} baseline={base_val} latest={curr_val} delta={delta:.2f}%"
                )
    if failures:
        print("perf_compare: FAIL")
        for line in failures:
            print(f"  {line}")
        return 1
    print("perf_compare: PASS")
    return 0


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: perf_compare.py <baseline.json> <latest.txt>", file=sys.stderr)
        return 2

    baseline_path = Path(argv[1])
    latest_path = Path(argv[2])

    if not baseline_path.exists():
        print(f"baseline file '{baseline_path}' not found", file=sys.stderr)
        return 2
    if not latest_path.exists():
        print(f"latest results '{latest_path}' not found", file=sys.stderr)
        return 2

    baseline = load_baseline(baseline_path)
    latest = parse_latest(latest_path)

    return compare_metrics(baseline, latest)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
