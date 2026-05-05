#!/usr/bin/env python3
"""Validate QiseGuard training data quality and format.

Checks:
1. JSON format compliance (assistant response must be valid JSON)
2. Schema compliance (verdict, confidence, risk_source, reasoning)
3. Verdict value validity (safe/suspicious/malicious, concerned/alarmed)
4. Confidence range (0.0-1.0)
5. Risk source validity per task
6. Class balance (positive/negative ratio)
7. No duplicates
8. No markdown wrapping in assistant responses

Usage:
    python scripts/validate.py datasets/processed/
    python scripts/validate.py datasets/synthetic/
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

# Valid risk sources per task
VALID_RISK_SOURCES = {
    "task1": {"indirect_injection", "context_poisoning", "injection_compliance", "none"},
    "task2": {"command_injection", "privilege_escalation", "obfuscation", "none"},
    "task3": {"credential_exfil", "data_exfil", "dns_exfil", "covert_channel", "none"},
    "task4": {"exfil_intent", "bypass_intent", "privilege_escalation", "injection_compliance", "evasion_planning", "none"},
    "task5": {"memory_poison", "kb_poison", "none"},
    "task6": {"tool_poison", "tool_shadow", "none"},
    "task7": {"supply_chain", "none"},
    "task8": {"infinite_loop", "behavioral_anomaly", "resource_exhaustion", "none"},
    "task9": {"kb_leak", "pii_exposure", "credential_leak", "none"},
    "task10": {"attack_chain", "correlated_events", "none"},
}

VALID_VERDICTS = {"safe", "suspicious", "malicious", "concerned", "alarmed"}

# Task 4 uses concerned/alarmed instead of suspicious/malicious
TASK4_VERDICTS = {"safe", "concerned", "alarmed"}


def validate_file(filepath: Path) -> dict:
    """Validate a single JSONL file. Returns stats dict."""
    stats = {
        "total": 0,
        "errors": [],
        "verdict_counts": Counter(),
        "task_counts": Counter(),
        "source_counts": Counter(),
        "risk_source_counts": Counter(),
        "confidence_values": [],
        "duplicates": 0,
        "seen_hashes": set(),
    }

    for i, line in enumerate(filepath.open()):
        line = line.strip()
        if not line:
            continue

        stats["total"] += 1

        try:
            sample = json.loads(line)
        except json.JSONDecodeError as e:
            stats["errors"].append(f"Line {i}: Invalid JSON: {e}")
            continue

        # Check messages structure
        messages = sample.get("messages", [])
        if len(messages) != 3:
            stats["errors"].append(f"Line {i}: Expected 3 messages, got {len(messages)}")
            continue

        # Check roles
        roles = [m.get("role") for m in messages]
        if roles != ["system", "user", "assistant"]:
            stats["errors"].append(f"Line {i}: Invalid message roles: {roles}")
            continue

        # Check assistant response
        assistant_content = messages[2].get("content", "")

        # No markdown wrapping
        if assistant_content.startswith("```") or assistant_content.startswith("`"):
            stats["errors"].append(f"Line {i}: Assistant response contains markdown wrapping")

        # Parse response JSON
        try:
            response = json.loads(assistant_content)
        except json.JSONDecodeError as e:
            stats["errors"].append(f"Line {i}: Invalid JSON in assistant response: {e}")
            continue

        # Check required fields
        required = {"verdict", "confidence", "risk_source", "reasoning"}
        missing = required - set(response.keys())
        if missing:
            stats["errors"].append(f"Line {i}: Missing response fields: {missing}")

        # Validate verdict
        verdict = response.get("verdict", "")
        if verdict not in VALID_VERDICTS:
            stats["errors"].append(f"Line {i}: Invalid verdict: '{verdict}'")
        stats["verdict_counts"][verdict] += 1

        # Validate confidence
        confidence = response.get("confidence", -1)
        if not isinstance(confidence, (int, float)) or confidence < 0 or confidence > 1:
            stats["errors"].append(f"Line {i}: Invalid confidence: {confidence}")
        else:
            stats["confidence_values"].append(confidence)

        # Get task from metadata
        task = sample.get("metadata", {}).get("task", "unknown")
        stats["task_counts"][task] += 1

        # Validate risk_source per task
        risk_source = response.get("risk_source", "")
        stats["risk_source_counts"][risk_source] += 1
        if task in VALID_RISK_SOURCES:
            if risk_source not in VALID_RISK_SOURCES[task]:
                stats["errors"].append(f"Line {i}: Invalid risk_source '{risk_source}' for {task}")

        # Check for duplicates
        content_hash = hash(messages[1].get("content", ""))
        if content_hash in stats["seen_hashes"]:
            stats["duplicates"] += 1
        stats["seen_hashes"].add(content_hash)

        # Track source
        source = sample.get("metadata", {}).get("source", "unknown")
        stats["source_counts"][source] += 1

    return stats


def print_report(filepath: Path, stats: dict) -> None:
    """Print validation report for a file."""
    print(f"\n{'='*60}")
    print(f"File: {filepath.name}")
    print(f"{'='*60}")

    print(f"Total samples: {stats['total']}")
    print(f"Errors: {len(stats['errors'])}")
    print(f"Duplicates: {stats['duplicates']}")

    if stats["verdict_counts"]:
        print(f"\nVerdict distribution:")
        for verdict, count in stats["verdict_counts"].most_common():
            pct = count / stats["total"] * 100
            print(f"  {verdict:12s}: {count:5d} ({pct:.1f}%)")

    if stats["task_counts"]:
        print(f"\nTask distribution:")
        for task, count in sorted(stats["task_counts"].items()):
            pct = count / stats["total"] * 100
            print(f"  {task:10s}: {count:5d} ({pct:.1f}%)")

    if stats["confidence_values"]:
        avg_conf = sum(stats["confidence_values"]) / len(stats["confidence_values"])
        min_conf = min(stats["confidence_values"])
        max_conf = max(stats["confidence_values"])
        print(f"\nConfidence: avg={avg_conf:.3f}, min={min_conf:.3f}, max={max_conf:.3f}")

    # Positive/negative balance
    positive = stats["verdict_counts"].get("malicious", 0) + stats["verdict_counts"].get("suspicious", 0) + stats["verdict_counts"].get("alarmed", 0) + stats["verdict_counts"].get("concerned", 0)
    negative = stats["verdict_counts"].get("safe", 0)
    if positive + negative > 0:
        ratio = positive / negative if negative > 0 else float("inf")
        print(f"\nClass balance: positive={positive}, negative={negative}, ratio={ratio:.2f}")
        if ratio > 3 or ratio < 0.33:
            print("  WARNING: Class imbalance detected (ideal ratio ~1.0)")

    if stats["errors"]:
        print(f"\nFirst 10 errors:")
        for err in stats["errors"][:10]:
            print(f"  {err}")
        if len(stats["errors"]) > 10:
            print(f"  ... and {len(stats['errors']) - 10} more errors")


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate QiseGuard training data")
    parser.add_argument("path", type=str, help="Directory or file to validate")
    parser.add_argument("--strict", action="store_true", help="Exit with error on any validation failure")

    args = parser.parse_args()
    path = Path(args.path)

    if path.is_file():
        files = [path]
    elif path.is_dir():
        files = sorted(path.glob("*.jsonl"))
    else:
        print(f"ERROR: Path not found: {path}")
        sys.exit(1)

    if not files:
        print(f"No JSONL files found in {path}")
        sys.exit(1)

    total_errors = 0
    for filepath in files:
        stats = validate_file(filepath)
        print_report(filepath, stats)
        total_errors += len(stats["errors"])

    print(f"\n{'='*60}")
    print(f"SUMMARY: {len(files)} files, {total_errors} total errors")
    print(f"{'='*60}")

    if args.strict and total_errors > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
