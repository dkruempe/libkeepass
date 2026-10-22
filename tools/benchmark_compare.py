#!/usr/bin/env python3
"""Compare a benchmark JSON file against a stored baseline.

Usage:
    tools/benchmark_compare.py --baseline test/benchmark_baseline.json \
        --current build/benchmark-current.json [--threshold 0.5] \
        [--ratio-threshold 0.5]

The absolute threshold applies to export_ms/import_ms and catches regressions
caused by a slower runner or a genuinely slower code path. The ratio threshold
compares export_ms/import_ms per scenario, which is largely independent of the
machine and catches a slowdown in one direction that the other direction hides.
Exits non-zero if a threshold is exceeded.
"""

from __future__ import annotations

import argparse
import json
import sys


def load(path: str) -> dict:
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def ratio(entry: dict) -> float:
    import_ms = float(entry.get("import_ms", 0.0))
    return float(entry.get("export_ms", 0.0)) / import_ms if import_ms > 0 else 0.0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", default="test/benchmark_baseline.json")
    parser.add_argument("--current", default="build/benchmark-current.json")
    parser.add_argument("--threshold", type=float, default=0.5,
                        help="max relative regression for export_ms/import_ms (default 0.5)")
    parser.add_argument("--ratio-threshold", type=float, default=0.5,
                        help="max relative regression for export/import ratio (default 0.5)")
    args = parser.parse_args()

    baseline = load(args.baseline)
    current = load(args.current)

    failures: list[str] = []
    base_scenarios = baseline.get("scenarios", {})
    current_scenarios = current.get("scenarios", {})

    print(f"{'scenario':24} {'metric':10} {'baseline':>10} {'current':>10} {'delta':>9}")
    for name, base in sorted(base_scenarios.items()):
        cur = current_scenarios.get(name)
        if cur is None:
            failures.append(f"{name}: missing from current benchmark")
            continue
        for metric in ("export_ms", "import_ms"):
            b = float(base.get(metric, 0.0))
            c = float(cur.get(metric, 0.0))
            if b <= 0:
                continue
            delta = (c - b) / b
            print(f"{name:24} {metric:10} {b:10.3f} {c:10.3f} {delta:+8.1%}")
            if delta > args.threshold:
                failures.append(
                    f"{name}: {metric} regressed by {delta:.1%} "
                    f"({b:.3f} -> {c:.3f} ms, limit {args.threshold:.0%})"
                )

        base_ratio = ratio(base)
        cur_ratio = ratio(cur)
        if base_ratio > 0:
            delta = (cur_ratio - base_ratio) / base_ratio
            print(f"{name:24} {'exp/imp':10} {base_ratio:10.3f} {cur_ratio:10.3f} {delta:+8.1%}")
            if delta > args.ratio_threshold:
                failures.append(
                    f"{name}: export/import ratio regressed by {delta:.1%} "
                    f"({base_ratio:.3f} -> {cur_ratio:.3f})"
                )

    base_rss = int(baseline.get("peak_rss_kib", 0))
    cur_rss = int(current.get("peak_rss_kib", 0))
    if base_rss > 0 and cur_rss > 0:
        delta = (cur_rss - base_rss) / base_rss
        print(f"{'process':24} {'peak_rss':10} {base_rss:10d} {cur_rss:10d} {delta:+8.1%}")
        if delta > args.threshold:
            failures.append(
                f"peak RSS regressed by {delta:.1%} ({base_rss} -> {cur_rss} KiB)"
            )

    if failures:
        print("\nBenchmark regressions:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1
    print("\nNo benchmark regressions above the configured thresholds.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
