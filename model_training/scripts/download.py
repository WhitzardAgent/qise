#!/usr/bin/env python3
"""Download public datasets for QiseGuard-SLM training.

Usage:
    python scripts/download.py --all
    python scripts/download.py --source agentdojo
    python scripts/download.py --source agentharm,harmbench
    python scripts/download.py --list
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path

# Project paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent
RAW_DIR = PROJECT_ROOT / "datasets" / "raw"
QISE_ROOT = PROJECT_ROOT.parent  # qise/ root


# ── Dataset Registry ─────────────────────────────────────────────────────

HUGGINGFACE_DATASETS = {
    "agentdojo": {
        "hf_id": "ffuuugor/agentdojo-dump",
        "split": "train",
        "output_dir": "agentdojo",
        "description": "AgentDojo: ~13,913 rows of indirect prompt injection attacks",
    },
    "agentharm": {
        "hf_id": "ai-safety-institute/AgentHarm",
        "split": "test_public",
        "configs": ["harmful", "harmless_benign"],
        "output_dir": "agentharm",
        "description": "AgentHarm: 208 harmful + 208 benign agent behaviors",
    },
    "harmbench": {
        "hf_id": "walledai/HarmBench",
        "split": "train",
        "output_dir": "harmbench",
        "description": "HarmBench: 400 harmful behavior prompts",
    },
    "harmbench_cls": {
        "hf_id": "justinphan3110/harmbench_classifier_train",
        "split": "train",
        "output_dir": "harmbench_cls",
        "description": "HarmBench classifier training data",
    },
    "pii_masking": {
        "hf_id": "ai4privacy/pii-masking-200k",
        "split": "train",
        "output_dir": "pii_masking",
        "description": "PII Masking: 209K rows with 54 PII classes",
    },
    # --- Newly discovered datasets ---
    "pi_attacks_55k": {
        "hf_id": "Smooth-3/llm-prompt-injection-attacks",
        "split": "train",
        "output_dir": "pi_attacks_55k",
        "description": "55K prompt injection attacks (5 labels: BENIGN/JAILBREAK/INSTRUCTION_OVERRIDE/ROLE_HIJACK/DATA_EXFILTRATION)",
    },
    "indirect_pi_bipia": {
        "hf_id": "MAlmasabi/Indirect-Prompt-Injection-BIPIA-GPT",
        "split": "train",
        "output_dir": "indirect_pi_bipia",
        "description": "70K indirect prompt injection (35K malicious + 35K benign)",
    },
    "pi_multilingual": {
        "hf_id": "Octavio-Santana/prompt-injection-attack-detection-multilingual",
        "split": "train",
        "output_dir": "pi_multilingual",
        "description": "7,924 multilingual prompt injection detection samples",
    },
    "pii_english_156k": {
        "hf_id": "Ari-S-123/pii-detection-english-consolidated",
        "split": "train",
        "output_dir": "pii_english_156k",
        "description": "156K PII detection (17 types incl. SSN, CREDITCARD, PASSPORT)",
    },
    "pii_intent_multi": {
        "hf_id": "gorkem371/pii-intent-detection-multilingual",
        "split": "train",
        "output_dir": "pii_intent_multi",
        "description": "41K PII intent detection multilingual",
    },
    "adv_agent_intent_240k": {
        "hf_id": "yatin-superintelligence/Adversarial-Agent-Intent-Safety-Analysis-240K",
        "split": "train",
        "output_dir": "adv_agent_intent_240k",
        "description": "242K adversarial agent intent with sophistication levels",
    },
    "multi_turn_jailbreak": {
        "hf_id": "tom-gibbs/multi-turn_jailbreak_attack_datasets",
        "split": "train",
        "output_dir": "multi_turn_jailbreak",
        "description": "6,918 multi-turn jailbreak attack samples",
    },
    "mcp_tool_quality": {
        "hf_id": "rogue-security/mcp-tool-use-quality-benchmark",
        "split": "train",
        "output_dir": "mcp_tool_quality",
        "description": "MCP tool use quality benchmark (VALID_CALL/TOOL_ERROR/PARAM errors)",
    },
}

GITHUB_DATASETS = {
    "agentpoison": {
        "repo": "AI-secure/AgentPoison",
        "output_dir": "agentpoison",
        "description": "AgentPoison: Memory/KB backdoor poisoning (NeurIPS 2024)",
    },
    "agentdojo_source": {
        "repo": "ethz-spylab/agentdojo",
        "output_dir": "agentdojo_source",
        "description": "AgentDojo source code with full benchmark suite",
    },
    "harmbench_source": {
        "repo": "centerforaisafety/HarmBench",
        "output_dir": "harmbench_source",
        "description": "HarmBench source with 400 behaviors + classifier",
    },
    "agentseal": {
        "repo": "getagentseal/agentseal",
        "output_dir": "agentseal",
        "description": "AgentSeal: 225+ adversarial probes for agent security",
    },
    "skill_audit": {
        "repo": "eltociear/skill-audit-mcp",
        "output_dir": "skill_audit",
        "description": "Skill Audit MCP: 68+ malicious pattern signatures",
    },
    # --- Newly discovered repos ---
    "injecagent": {
        "repo": "uiuc-kang-lab/InjecAgent",
        "output_dir": "injecagent",
        "description": "InjecAgent: 1,054 indirect injection test cases (17 user + 62 attacker tools)",
    },
    "injectlab": {
        "repo": "ahow2004/injectlab",
        "output_dir": "injectlab",
        "description": "InjectLab: 19 techniques across 6 ATT&CK-style tactics",
    },
    "agentdefense_bench": {
        "repo": "arunsanna/AgentDefense-Bench",
        "output_dir": "agentdefense_bench",
        "description": "AgentDefense-Bench: 35,989 MCP attack samples (17 vectors)",
    },
    "mcp_injection": {
        "repo": "invariantlabs-ai/mcp-injection-experiments",
        "output_dir": "mcp_injection",
        "description": "MCP Injection: Sleeper rug-pull, hidden exfiltration PoCs",
    },
    "agentshield": {
        "repo": "doronp/agentshield-benchmark",
        "output_dir": "agentshield",
        "description": "AgentShield: 537 total, 87 exfil tests (8 categories)",
    },
    "agenttrust": {
        "repo": "chenglin1112/AgentTrust",
        "output_dir": "agenttrust",
        "description": "AgentTrust: 300 scenarios, 7 RiskChain multi-step attack patterns",
    },
    "owasp_agentic": {
        "repo": "evolutionstorm/owasp-agentic-security-dataset",
        "output_dir": "owasp_agentic",
        "description": "OWASP Top 10 for Agentic Apps 2026 (70+ attack scenarios)",
    },
    "agent_egress": {
        "repo": "luckyPipewrench/agent-egress-bench",
        "output_dir": "agent_egress",
        "description": "Agent Egress Bench: 143 cases, 16 attack categories, OWASP mapping",
    },
    "clawsafety": {
        "repo": "weibowen555/ClawSafety",
        "output_dir": "clawsafety",
        "description": "ClawSafety: 120 adversarial test cases across 5 professional domains",
    },
}

PURPLELLAMA_COMMIT = "fe05293b610dabc3967443f2dd4dc35c4e8971b6"
CYBERSECEVAL_URLS = {
    "cyberseceval_pi": {
        "url": f"https://raw.githubusercontent.com/meta-llama/PurpleLlama/{PURPLELLAMA_COMMIT}/CybersecurityBenchmarks/datasets/prompt_injection/prompt_injection.json",
        "output_file": "cyberseceval/prompt_injection.json",
        "description": "CyberSecEval: 251 English prompt injection samples",
    },
    "cyberseceval_pi_multilingual": {
        "url": f"https://raw.githubusercontent.com/meta-llama/PurpleLlama/{PURPLELLAMA_COMMIT}/CybersecurityBenchmarks/datasets/prompt_injection/prompt_injection_multilingual_machine_translated.json",
        "output_file": "cyberseceval/prompt_injection_multilingual.json",
        "description": "CyberSecEval: 1004 multilingual injection samples",
    },
    "cyberseceval_mitre": {
        "url": f"https://raw.githubusercontent.com/meta-llama/PurpleLlama/{PURPLELLAMA_COMMIT}/CybersecurityBenchmarks/datasets/mitre/mitre_benchmark_100_per_category_with_augmentation.json",
        "output_file": "cyberseceval/mitre.json",
        "description": "CyberSecEval: 1000 MITRE ATT&CK samples",
    },
    "cyberseceval_frr": {
        "url": f"https://raw.githubusercontent.com/meta-llama/PurpleLlama/{PURPLELLAMA_COMMIT}/CybersecurityBenchmarks/datasets/mitre_frr/mitre_frr.json",
        "output_file": "cyberseceval/mitre_frr.json",
        "description": "CyberSecEval: 750 benign MITRE samples",
    },
}


# ── Download Functions ────────────────────────────────────────────────────

def download_hf_dataset(name: str, info: dict) -> None:
    """Download a dataset from HuggingFace."""
    try:
        from datasets import load_dataset
    except ImportError:
        print("  ERROR: `datasets` package required. Run: pip install datasets")
        return

    output_dir = RAW_DIR / info["output_dir"]
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"  Downloading {name} ({info['hf_id']})...")

    configs = info.get("configs")
    if configs:
        for config in configs:
            print(f"    Config: {config}...")
            ds = load_dataset(info["hf_id"], config, split=info["split"], cache_dir=str(output_dir / ".cache"))
            out_path = output_dir / f"{config}_{info['split']}.json"
            ds.to_json(str(out_path))
            print(f"    → {out_path} ({len(ds)} rows)")
    else:
        ds = load_dataset(info["hf_id"], split=info["split"], cache_dir=str(output_dir / ".cache"))
        out_path = output_dir / f"{info['split']}.json"
        ds.to_json(str(out_path))
        print(f"    → {out_path} ({len(ds)} rows)")


def download_github_repo(name: str, info: dict) -> None:
    """Clone a GitHub repository."""
    output_dir = RAW_DIR / info["output_dir"]

    if output_dir.exists():
        print(f"  {name}: already exists at {output_dir}, skipping")
        return

    print(f"  Cloning {name} ({info['repo']})...")
    repo_url = f"https://github.com/{info['repo']}.git"
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", repo_url, str(output_dir)],
            check=True,
            capture_output=True,
        )
        print(f"    → {output_dir}")
    except subprocess.CalledProcessError as e:
        print(f"  ERROR: Failed to clone {info['repo']}: {e.stderr.decode()[:200]}")


def download_url(name: str, info: dict) -> None:
    """Download a file from URL."""
    output_path = RAW_DIR / info["output_file"]
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if output_path.exists():
        print(f"  {name}: already exists at {output_path}, skipping")
        return

    print(f"  Downloading {name}...")
    try:
        req = urllib.request.Request(info["url"], headers={"User-Agent": "QiseGuard-Training/1.0"})
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = resp.read()
        output_path.write_bytes(data)
        print(f"    → {output_path} ({len(data)} bytes)")
    except Exception as e:
        print(f"  ERROR: Failed to download {name}: {e}")


def copy_qise_internal() -> None:
    """Copy Qise internal eval datasets."""
    output_dir = RAW_DIR / "qise_internal"
    output_dir.mkdir(parents=True, exist_ok=True)

    source_dir = QISE_ROOT / "eval" / "datasets"
    if not source_dir.exists():
        print("  WARNING: Qise eval/datasets/ not found, skipping internal datasets")
        return

    for yaml_file in source_dir.glob("*.yaml"):
        dest = output_dir / yaml_file.name
        if not dest.exists():
            shutil.copy2(yaml_file, dest)
            print(f"    → {dest}")
        else:
            print(f"    {yaml_file.name}: already exists")

    print(f"  Qise internal datasets copied to {output_dir}")


# ── CLI ───────────────────────────────────────────────────────────────────

def list_datasets() -> None:
    """Print all available datasets."""
    print("\n=== HuggingFace Datasets ===")
    for name, info in HUGGINGFACE_DATASETS.items():
        print(f"  {name:20s} — {info['description']}")

    print("\n=== GitHub Repositories ===")
    for name, info in GITHUB_DATASETS.items():
        print(f"  {name:20s} — {info['description']}")

    print("\n=== URL Downloads (CyberSecEval) ===")
    for name, info in CYBERSECEVAL_URLS.items():
        print(f"  {name:20s} — {info['description']}")

    print("\n=== Qise Internal ===")
    print(f"  qise_internal        — Qise eval YAML datasets (auto-copied from eval/datasets/)")


def main() -> None:
    parser = argparse.ArgumentParser(description="Download datasets for QiseGuard-SLM training")
    parser.add_argument("--all", action="store_true", help="Download all datasets")
    parser.add_argument("--source", type=str, help="Comma-separated source names (e.g., agentdojo,harmbench)")
    parser.add_argument("--list", action="store_true", help="List available datasets")
    parser.add_argument("--hf-only", action="store_true", help="Only download HuggingFace datasets")
    parser.add_argument("--github-only", action="store_true", help="Only clone GitHub repos")
    parser.add_argument("--skip-large", action="store_true", help="Skip large datasets (>100MB)")

    args = parser.parse_args()

    if args.list:
        list_datasets()
        return

    RAW_DIR.mkdir(parents=True, exist_ok=True)

    all_sources = set()
    all_sources.update(HUGGINGFACE_DATASETS.keys())
    all_sources.update(GITHUB_DATASETS.keys())
    all_sources.update(CYBERSECEVAL_URLS.keys())
    all_sources.add("qise_internal")

    if args.all:
        sources = all_sources
    elif args.source:
        sources = set(s.strip() for s in args.source.split(","))
        unknown = sources - all_sources
        if unknown:
            print(f"ERROR: Unknown sources: {unknown}")
            print(f"Available: {sorted(all_sources)}")
            sys.exit(1)
    else:
        print("Specify --all or --source. Use --list to see available datasets.")
        sys.exit(1)

    print(f"Downloading {len(sources)} dataset(s) to {RAW_DIR}/\n")

    # Download HuggingFace datasets
    hf_sources = sources & set(HUGGINGFACE_DATASETS.keys())
    if hf_sources and not args.github_only:
        print("── HuggingFace Datasets ──")
        for name in sorted(hf_sources):
            download_hf_dataset(name, HUGGINGFACE_DATASETS[name])
        print()

    # Clone GitHub repos
    gh_sources = sources & set(GITHUB_DATASETS.keys())
    if gh_sources and not args.hf_only:
        print("── GitHub Repositories ──")
        for name in sorted(gh_sources):
            download_github_repo(name, GITHUB_DATASETS[name])
        print()

    # Download URL-based datasets
    url_sources = sources & set(CYBERSECEVAL_URLS.keys())
    if url_sources and not args.hf_only and not args.github_only:
        print("── URL Downloads ──")
        for name in sorted(url_sources):
            download_url(name, CYBERSECEVAL_URLS[name])
        print()

    # Copy Qise internal datasets
    if "qise_internal" in sources:
        print("── Qise Internal ──")
        copy_qise_internal()
        print()

    print("Done!")


if __name__ == "__main__":
    main()
