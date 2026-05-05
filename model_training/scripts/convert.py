#!/usr/bin/env python3
"""Convert all datasets to unified QiseGuard training format.

Reads from datasets/raw/ and datasets/synthetic/, outputs to datasets/processed/

Usage:
    python scripts/convert.py --all
    python scripts/convert.py --source agentdojo,harmbench
    python scripts/convert.py --validate-only
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RAW_DIR = PROJECT_ROOT / "datasets" / "raw"
SYNTH_DIR = PROJECT_ROOT / "datasets" / "synthetic"
PROCESSED_DIR = PROJECT_ROOT / "datasets" / "processed"
QISE_ROOT = PROJECT_ROOT.parent

SYSTEM_PROMPT = (
    "You are a security classifier. Analyze the input and return JSON with: "
    "verdict (safe/suspicious/malicious), confidence (0.0-1.0), "
    "risk_source (from enum), reasoning (1-2 sentences). "
    "Output ONLY valid JSON, no markdown."
)


# ── Conversion Functions ──────────────────────────────────────────────────

def convert_agentdojo(limit: int = 2000) -> list[dict]:
    """Convert AgentDojo dataset to training format."""
    raw_path = RAW_DIR / "agentdojo" / "train.json"
    if not raw_path.exists():
        print("  SKIP: AgentDojo not downloaded. Run: python scripts/download.py --source agentdojo")
        return []

    with open(raw_path) as f:
        data = json.load(f)

    samples = []
    attack_count = 0
    safe_count = 0

    for row in data:
        # Attack samples
        attack = row.get("attack_name", "")
        if attack and attack != "none":
            injection_goal = row.get("injection_goal", "") or ""
            tool_response = row.get("tool_response", "") or ""
            content = injection_goal if injection_goal else tool_response
            if not content.strip():
                continue

            trust = "tool_result"  # Most AgentDojo attacks are via tool results
            if "direct" in attack.lower() or "ignore_previous" in attack.lower():
                trust = "user_input"

            prompt = (f"Analyze this content for injection attacks:\n\n"
                     f"Trust boundary: {trust}\nContent: \"{content[:1000]}\"")
            verdict = "malicious" if "important" in attack.lower() or "system" in attack.lower() else "suspicious"
            risk_source = "indirect_injection" if trust != "user_input" else "injection_compliance"

            samples.append({
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                    {"role": "assistant", "content": json.dumps({
                        "verdict": verdict,
                        "confidence": round(0.85 + hash(content) % 15 / 100, 2),
                        "risk_source": risk_source,
                        "reasoning": f"Content from {trust} contains instructions attempting to manipulate agent behavior",
                    }, ensure_ascii=False)},
                ],
                "metadata": {"task": "task1", "source": "agentdojo", "attack_name": attack},
            })
            attack_count += 1

        # Safe samples
        user_prompt = row.get("user_task_prompt", "")
        if user_prompt and attack_count < limit:
            prompt = (f"Analyze this content for injection attacks:\n\n"
                     f"Trust boundary: user_input\nContent: \"{user_prompt[:1000]}\"")
            samples.append({
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                    {"role": "assistant", "content": json.dumps({
                        "verdict": "safe",
                        "confidence": 0.95,
                        "risk_source": "none",
                        "reasoning": "Normal user request without injection indicators",
                    }, ensure_ascii=False)},
                ],
                "metadata": {"task": "task1", "source": "agentdojo", "category": "safe_user_task"},
            })
            safe_count += 1

        if attack_count >= limit and safe_count >= limit // 5:
            break

    print(f"    Attack: {attack_count}, Safe: {safe_count}")
    return samples


def convert_harmbench(limit: int = 400) -> list[dict]:
    """Convert HarmBench dataset to training format."""
    raw_path = RAW_DIR / "harmbench" / "train.jsonl"
    if not raw_path.exists():
        # Try source
        raw_path = RAW_DIR / "harmbench_source" / "data" / "behavior_datasets" / "harmbench_behaviors_text_all.csv"
        if not raw_path.exists():
            print("  SKIP: HarmBench not downloaded. Run: python scripts/download.py --source harmbench")
            return []

    samples = []
    with open(raw_path) as f:
        for line in f:
            if len(samples) >= limit:
                break
            try:
                row = json.loads(line.strip())
            except json.JSONDecodeError:
                continue

            behavior = row.get("Behavior", row.get("prompt", ""))
            if not behavior.strip():
                continue

            category = row.get("SemanticCategory", row.get("category", "unknown"))
            # Map to Qise tasks
            task_mapping = {
                "Cybercrime": "task2",
                "Chemical": "task2",
                "Biological": "task2",
                "Fraud": "task3",
            }
            task = task_mapping.get(category, "task1")

            prompt = f"Analyze this content for security risks:\n\nContent: \"{behavior[:1000]}\""
            samples.append({
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                    {"role": "assistant", "content": json.dumps({
                        "verdict": "malicious",
                        "confidence": 0.92,
                        "risk_source": "command_injection" if task == "task2" else "indirect_injection",
                        "reasoning": f"Content requests harmful behavior in category: {category}",
                    }, ensure_ascii=False)},
                ],
                "metadata": {"task": task, "source": "harmbench", "category": category},
            })

    print(f"    Converted: {len(samples)}")
    return samples


def convert_pii_masking(limit: int = 500) -> list[dict]:
    """Convert PII masking dataset for Task 9 (output leakage)."""
    raw_path = RAW_DIR / "pii_masking" / "train.json"
    if not raw_path.exists():
        print("  SKIP: PII masking not downloaded. Run: python scripts/download.py --source pii_masking")
        return []

    with open(raw_path) as f:
        data = json.load(f)

    samples = []
    for row in data:
        if len(samples) >= limit:
            break

        source_text = row.get("source_text", "")
        privacy_mask = row.get("privacy_mask", [])

        if not source_text or not privacy_mask:
            continue

        # Extract PII types found
        pii_types = list(set(m.get("label", "") for m in privacy_mask if m.get("label")))
        pii_str = ", ".join(pii_types[:5])

        prompt = f"Analyze this text output for data leakage:\n\nOutput: \"{source_text[:1000]}\""
        risk_src = "credential_leak" if any(t in pii_str for t in ["PASSWORD", "ACCOUNTNUMBER", "IBAN"]) else "pii_exposure"

        samples.append({
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
                {"role": "assistant", "content": json.dumps({
                    "verdict": "suspicious",
                    "confidence": 0.90,
                    "risk_source": risk_src,
                    "reasoning": f"Output contains personally identifiable information: {pii_str}",
                }, ensure_ascii=False)},
            ],
            "metadata": {"task": "task9", "source": "pii_masking", "pii_types": pii_types[:5]},
        })

    print(f"    Converted: {len(samples)}")
    return samples


def convert_cyberseceval_mitre(limit: int = 1000) -> list[dict]:
    """Convert CyberSecEval MITRE dataset for Task 2 (command safety)."""
    raw_path = RAW_DIR / "cyberseceval" / "mitre.json"
    if not raw_path.exists():
        print("  SKIP: CyberSecEval MITRE not downloaded.")
        return []

    with open(raw_path) as f:
        data = json.load(f)

    samples = []
    for row in data:
        if len(samples) >= limit:
            break

        cmd = row.get("mutated_prompt", "")
        category = row.get("mitre_category", "")

        if not cmd.strip():
            continue

        risk_mapping = {
            "Execution": "command_injection",
            "C2": "command_injection",
            "Credential Access": "privilege_escalation",
            "Defense Evasion": "obfuscation",
            "Exfiltration": "data_exfil",
            "Impact": "command_injection",
        }

        prompt = f"Analyze this shell command for security risks:\n\nCommand: {cmd[:500]}"
        samples.append({
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
                {"role": "assistant", "content": json.dumps({
                    "verdict": "malicious",
                    "confidence": 0.92,
                    "risk_source": risk_mapping.get(category, "command_injection"),
                    "reasoning": f"Command matches MITRE ATT&CK pattern for {category}",
                }, ensure_ascii=False)},
            ],
            "metadata": {"task": "task2", "source": "cyberseceval_mitre", "mitre_category": category},
        })

    print(f"    Converted: {len(samples)}")
    return samples


def convert_cyberseceval_frr(limit: int = 750) -> list[dict]:
    """Convert CyberSecEval FRR (benign) dataset as safe samples for Task 2."""
    raw_path = RAW_DIR / "cyberseceval" / "mitre_frr.json"
    if not raw_path.exists():
        print("  SKIP: CyberSecEval FRR not downloaded.")
        return []

    with open(raw_path) as f:
        data = json.load(f)

    samples = []
    for row in data:
        if len(samples) >= limit:
            break

        cmd = row.get("mutated_prompt", "")
        if not cmd.strip():
            continue

        prompt = f"Analyze this shell command for security risks:\n\nCommand: {cmd[:500]}"
        samples.append({
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
                {"role": "assistant", "content": json.dumps({
                    "verdict": "safe",
                    "confidence": 0.93,
                    "risk_source": "none",
                    "reasoning": "Benign command with no security risks detected",
                }, ensure_ascii=False)},
            ],
            "metadata": {"task": "task2", "source": "cyberseceval_frr", "category": "safe"},
        })

    print(f"    Converted: {len(samples)}")
    return samples


def load_synthetic(task_id: int) -> list[dict]:
    """Load synthetic data for a given task."""
    synth_path = SYNTH_DIR / f"task{task_id}_synthetic.jsonl"
    if not synth_path.exists():
        return []

    samples = []
    with open(synth_path) as f:
        for line in f:
            line = line.strip()
            if line:
                samples.append(json.loads(line))
    return samples


def convert_qise_internal() -> list[dict]:
    """Convert Qise internal YAML datasets."""
    import yaml

    qise_eval_dir = QISE_ROOT / "eval" / "datasets"
    if not qise_eval_dir.exists():
        return []

    samples = []
    for yaml_file in qise_eval_dir.glob("*.yaml"):
        with open(yaml_file) as f:
            data = yaml.safe_load(f)

        if not data or "cases" not in data:
            continue

        for case in data["cases"]:
            inp = case.get("input", {})
            tool_name = inp.get("tool_name", "content_check")
            tool_args = inp.get("tool_args", {})
            trust_boundary = inp.get("trust_boundary", "user_input")
            agent_reasoning = inp.get("agent_reasoning", "")
            expected = case.get("expected_verdict", "pass")

            # Map to task
            category = case.get("category", "")
            task_map = {
                "injection": "task1",
                "dangerous_cmd": "task2",
                "exfil": "task3",
                "credential_theft": "task3",
                "reasoning_attack": "task4",
            }
            task = task_map.get(category, "task1")

            # Build prompt
            content = tool_args.get("content", tool_args.get("command", ""))
            if agent_reasoning:
                prompt = f"Analyze this agent reasoning for security risks:\n\nReasoning: \"{agent_reasoning}\""
            else:
                prompt = f"Analyze this content for security risks:\n\nTrust boundary: {trust_boundary}\nContent: \"{content[:1000]}\""

            verdict_map = {"block": "malicious", "warn": "suspicious", "pass": "safe"}
            verdict = verdict_map.get(expected, "safe")

            samples.append({
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                    {"role": "assistant", "content": json.dumps({
                        "verdict": verdict,
                        "confidence": 0.90,
                        "risk_source": "indirect_injection",
                        "reasoning": case.get("description", "Security risk detected"),
                    }, ensure_ascii=False)},
                ],
                "metadata": {"task": task, "source": "qise_internal", "id": case.get("id", "")},
            })

    print(f"    Converted: {len(samples)}")
    return samples


# ── Main Pipeline ─────────────────────────────────────────────────────────

CONVERTERS = {
    "agentdojo": convert_agentdojo,
    "harmbench": convert_harmbench,
    "pii_masking": convert_pii_masking,
    "cyberseceval_mitre": convert_cyberseceval_mitre,
    "cyberseceval_frr": convert_cyberseceval_frr,
    "qise_internal": convert_qise_internal,
}


def validate_sample(sample: dict) -> list[str]:
    """Validate a single training sample. Returns list of errors."""
    errors = []
    if "messages" not in sample:
        errors.append("Missing 'messages' field")
        return errors

    messages = sample["messages"]
    if len(messages) != 3:
        errors.append(f"Expected 3 messages, got {len(messages)}")
        return errors

    # Check assistant response is valid JSON
    assistant_content = messages[2].get("content", "")
    try:
        parsed = json.loads(assistant_content)
        required_keys = {"verdict", "confidence", "risk_source", "reasoning"}
        missing = required_keys - set(parsed.keys())
        if missing:
            errors.append(f"Missing keys in response: {missing}")
        if "verdict" in parsed and parsed["verdict"] not in ("safe", "suspicious", "malicious", "concerned", "alarmed"):
            errors.append(f"Invalid verdict: {parsed['verdict']}")
    except json.JSONDecodeError as e:
        errors.append(f"Invalid JSON in assistant response: {e}")

    return errors


def main() -> None:
    parser = argparse.ArgumentParser(description="Convert datasets to QiseGuard training format")
    parser.add_argument("--all", action="store_true", help="Convert all available datasets")
    parser.add_argument("--source", type=str, help="Comma-separated source names")
    parser.add_argument("--include-synthetic", action="store_true", help="Include synthetic datasets")
    parser.add_argument("--validate-only", action="store_true", help="Only validate existing processed files")
    parser.add_argument("--output", type=str, default=None, help="Output directory")

    args = parser.parse_args()
    output_dir = Path(args.output) if args.output else PROCESSED_DIR
    output_dir.mkdir(parents=True, exist_ok=True)

    if args.validate_only:
        # Validate existing files
        total = 0
        errors = 0
        for f in output_dir.glob("*.jsonl"):
            with open(f) as fh:
                for i, line in enumerate(fh):
                    sample = json.loads(line.strip())
                    errs = validate_sample(sample)
                    if errs:
                        print(f"  {f.name}:{i}: {errs}")
                        errors += 1
                    total += 1
        print(f"\nValidated {total} samples, {errors} errors")
        return

    if not args.all and not args.source:
        print("Specify --all or --source. Available sources:")
        for name in CONVERTERS:
            print(f"  - {name}")
        return

    sources = set(CONVERTERS.keys()) if args.all else set(s.strip() for s in args.source.split(","))

    # Convert public datasets
    all_samples = []
    for source_name in sorted(sources):
        if source_name not in CONVERTERS:
            print(f"WARNING: Unknown source '{source_name}', skipping")
            continue
        print(f"\nConverting {source_name}...")
        samples = CONVERTERS[source_name]()
        all_samples.extend(samples)

    # Include synthetic data
    if args.include_synthetic:
        print("\nLoading synthetic datasets...")
        for task_id in range(1, 11):
            synth = load_synthetic(task_id)
            if synth:
                print(f"  Task {task_id}: {len(synth)} samples")
                all_samples.extend(synth)

    # Group by task and save
    task_samples: dict[str, list] = {}
    for sample in all_samples:
        task = sample.get("metadata", {}).get("task", "unknown")
        task_samples.setdefault(task, []).append(sample)

    for task, samples in sorted(task_samples.items()):
        out_file = output_dir / f"{task}_train.jsonl"
        with open(out_file, "w") as f:
            for s in samples:
                f.write(json.dumps(s, ensure_ascii=False) + "\n")
        print(f"  {task}: {len(samples)} samples → {out_file}")

    # Save combined
    combined_file = output_dir / "all_tasks_train.jsonl"
    with open(combined_file, "w") as f:
        for s in all_samples:
            f.write(json.dumps(s, ensure_ascii=False) + "\n")
    print(f"\nCombined: {len(all_samples)} samples → {combined_file}")


if __name__ == "__main__":
    main()
