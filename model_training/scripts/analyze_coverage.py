#!/usr/bin/env python3
"""Analyze dataset coverage across 10 QiseGuard tasks.

Reads raw/, synthetic/, and processed/ directories and reports
coverage statistics and gaps.

Usage:
    python scripts/analyze_coverage.py
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RAW_DIR = PROJECT_ROOT / "datasets" / "raw"
SYNTH_DIR = PROJECT_ROOT / "datasets" / "synthetic"
PROCESSED_DIR = PROJECT_ROOT / "datasets" / "processed"

TASK_NAMES = {
    "task1": "Injection Detection",
    "task2": "Command Safety",
    "task3": "Exfiltration Detection",
    "task4": "Reasoning Safety",
    "task5": "Context Poisoning",
    "task6": "Tool Poisoning",
    "task7": "Supply Chain",
    "task8": "Resource Abuse",
    "task9": "Output Leakage",
    "task10": "Attack Chain",
}

# Minimum target per task (from requirements doc)
MIN_TARGETS = {
    "task1": 1000, "task2": 800, "task3": 600, "task4": 400,
    "task5": 400, "task6": 300, "task7": 200, "task8": 200,
    "task9": 400, "task10": 300,
}


def count_samples_in_jsonl(path: Path) -> dict:
    """Count samples by task and verdict in a JSONL file."""
    counts = {"total": 0, "by_task": Counter(), "by_verdict": Counter(), "by_task_verdict": Counter()}
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    sample = json.loads(line)
                except json.JSONDecodeError:
                    continue

                counts["total"] += 1
                task = sample.get("metadata", {}).get("task", "unknown")
                counts["by_task"][task] += 1

                # Extract verdict from assistant message
                messages = sample.get("messages", [])
                if len(messages) >= 3:
                    try:
                        resp = json.loads(messages[2].get("content", "{}"))
                        verdict = resp.get("verdict", "unknown")
                        counts["by_verdict"][verdict] += 1
                        counts["by_task_verdict"][(task, verdict)] += 1
                    except json.JSONDecodeError:
                        pass
    except FileNotFoundError:
        pass
    return counts


def analyze_directory(dir_path: Path, label: str) -> dict:
    """Analyze all JSONL files in a directory."""
    results = {}
    for f in sorted(dir_path.glob("*.jsonl")):
        counts = count_samples_in_jsonl(f)
        results[f.name] = counts
        print(f"\n  {f.name}: {counts['total']} samples")
        for task, count in counts["by_task"].most_common():
            print(f"    {task}: {count}")
    return results


def main() -> None:
    print("=" * 70)
    print("QiseGuard-SLM Dataset Coverage Analysis")
    print("=" * 70)

    # Analyze processed data
    print("\n── Processed Datasets ──")
    processed = {}
    if PROCESSED_DIR.exists():
        processed = analyze_directory(PROCESSED_DIR, "processed")

    # Analyze synthetic data
    print("\n── Synthetic Datasets ──")
    synthetic = {}
    if SYNTH_DIR.exists():
        synthetic = analyze_directory(SYNTH_DIR, "synthetic")

    # Aggregate by task
    print("\n" + "=" * 70)
    print("Coverage Summary by Task")
    print("=" * 70)

    task_totals = Counter()
    task_positive = Counter()
    task_negative = Counter()

    for datasets in [processed, synthetic]:
        for name, counts in datasets.items():
            for task, count in counts["by_task"].items():
                task_totals[task] += count
            for (task, verdict), count in counts["by_task_verdict"].items():
                if verdict in ("malicious", "suspicious", "alarmed", "concerned"):
                    task_positive[task] += count
                elif verdict == "safe":
                    task_negative[task] += count

    print(f"\n{'Task':10s} {'Name':25s} {'Total':>6s} {'Attack':>6s} {'Safe':>6s} {'Min':>6s} {'Status':10s}")
    print("-" * 70)

    for task_id in range(1, 11):
        task = f"task{task_id}"
        name = TASK_NAMES[task]
        total = task_totals.get(task, 0)
        pos = task_positive.get(task, 0)
        neg = task_negative.get(task, 0)
        minimum = MIN_TARGETS.get(task, 0)

        if total >= minimum:
            status = "OK"
        elif total > 0:
            status = f"GAP ({total}/{minimum})"
        else:
            status = "MISSING"

        print(f"{task:10s} {name:25s} {total:6d} {pos:6d} {neg:6d} {minimum:6d} {status}")

    # Overall
    total_all = sum(task_totals.values())
    total_min = sum(MIN_TARGETS.values())
    print("-" * 70)
    print(f"{'TOTAL':10s} {'':25s} {total_all:6d} {'':6s} {'':6s} {total_min:6d}")

    # Gap analysis
    gaps = []
    for task_id in range(1, 11):
        task = f"task{task_id}"
        total = task_totals.get(task, 0)
        minimum = MIN_TARGETS.get(task, 0)
        if total < minimum:
            gaps.append((task, TASK_NAMES[task], total, minimum, minimum - total))

    if gaps:
        print(f"\n{'='*70}")
        print("GAP ANALYSIS — Tasks needing more data")
        print(f"{'='*70}")
        for task, name, current, minimum, needed in gaps:
            print(f"  {task}: {name}")
            print(f"    Current: {current}, Target: {minimum}, Need: {needed} more samples")
            if current == 0:
                print(f"    → Run: python scripts/synthesize.py --task {task[4:]}")
    else:
        print("\nAll tasks meet minimum coverage targets!")

    # Recommendations
    print(f"\n{'='*70}")
    print("RECOMMENDATIONS")
    print(f"{'='*70}")
    print("""
1. Download public datasets:
   python scripts/download.py --all

2. Generate synthetic data for gap tasks:
   python scripts/synthesize.py --all-gaps

3. Convert all data to training format:
   python scripts/convert.py --all --include-synthetic

4. Validate the processed data:
   python scripts/validate.py datasets/processed/
""")


if __name__ == "__main__":
    main()
