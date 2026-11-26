#!/usr/bin/env python3
"""Throughput and memory measurement for the detector.

Reports **processing** time, which is the one place a clock is allowed to appear:
this is instrumentation, not a detection decision. The detector itself never reads
``time.time()``.

Memory is peak RSS of this process after the run, measured with
``resource.getrusage``, not estimated. Hardware is reported because "100k events
per second" on an unstated machine is not a number anyone can check.
"""

from __future__ import annotations

import json
import platform
import resource
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from pqc_kv import detect  # noqa: E402


def host_description() -> str:
    """Plain hardware string. Deliberately excludes hostname and user."""
    cpu = platform.processor() or platform.machine()
    count = None
    try:
        import os

        count = os.cpu_count()
    except Exception:  # pragma: no cover - platform dependent
        pass
    return (
        f"{platform.system()} {platform.release()} / {platform.machine()} / "
        f"{cpu}" + (f" / {count} cpus" if count else "") + f" / Python {platform.python_version()}"
    )


def measure(log_path: Path, *, repeats: int = 3, approvals: Path | None = None) -> dict:
    """Run the detector over ``log_path`` and report throughput and peak memory.

    Sampled more than once on purpose: a single reading of a fast run overstates
    precision, and this project has already been bitten by publishing one.
    """
    text = log_path.read_text(encoding="utf-8")
    approval_text = approvals.read_text(encoding="utf-8") if approvals and approvals.exists() else None

    # Warm up once so import and file-cache costs are not counted as throughput.
    report = detect.run(text, approvals=approval_text)
    events = report.ingest["events_accepted"]

    durations = []
    for _ in range(max(1, repeats)):
        started = time.perf_counter()
        report = detect.run(text, approvals=approval_text)
        durations.append(time.perf_counter() - started)

    usage = resource.getrusage(resource.RUSAGE_SELF)
    # ru_maxrss is kilobytes on Linux and bytes on macOS. Normalising matters: an
    # unreported unit would make this number wrong by 1024x on one of the two
    # platforms we claim to support.
    if sys.platform == "darwin":
        peak_mb = usage.ru_maxrss / (1024 * 1024)
    else:
        peak_mb = usage.ru_maxrss / 1024

    best = min(durations)
    median = statistics.median(durations)
    return {
        "case": "throughput",
        "claim": "processing time only; the detector makes no decision from wall clock",
        "log": log_path.name,
        "events": events,
        "bytes": len(text.encode("utf-8")),
        "repeats": len(durations),
        "seconds_min": round(best, 4),
        "seconds_median": round(median, 4),
        "events_per_second": round(events / best, 1) if best else 0.0,
        "events_per_second_median": round(events / median, 1) if median else 0.0,
        "peak_memory_mb": round(peak_mb, 1),
        "alerts": len(report.alerts),
        "host": host_description(),
    }


def main(argv=None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path)
    parser.add_argument("--approvals", type=Path, default=None)
    parser.add_argument("--repeats", type=int, default=3)
    args = parser.parse_args(argv)
    result = measure(args.log, repeats=args.repeats, approvals=args.approvals)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
