# Qise Guard Evaluation

Evaluation framework for measuring guard performance against third-party benchmarks and local YAML test datasets.

## Directory Structure

```
eval/
├── README.md              # This file
├── runner.py              # QiseEvaluator + CLI runner
├── converters/            # Benchmark → EvalSample converters
│   ├── __init__.py
│   ├── agentdojo.py       # AgentDojo (indirect prompt injection)
│   ├── agentharm.py       # AgentHarm (harmful agent behaviors)
│   └── cyberseceval.py    # CyberSecEval 4 (injection + MITRE ATT&CK)
├── datasets/              # Local YAML test cases + cache
│   ├── injection_attacks.yaml
│   ├── exfil_attacks.yaml
│   ├── reasoning_attacks.yaml
│   └── safe_operations.yaml
└── results/               # Evaluation results
```

## Quick Start

```bash
# Third-party benchmarks (downloads data automatically)
python -m eval.runner --source agentdojo --mode rules-only
python -m eval.runner --source agentharm --mode rules-only
python -m eval.runner --source cyberseceval --mode rules-only
python -m eval.runner --source all --mode rules-only --output eval/results/baseline_rules.md

# Local YAML datasets
python -m eval.runner --dataset eval/datasets/ --mode rules-only

# Limit sample count for quick tests
python -m eval.runner --source agentdojo --limit 100

# Compare modes (rules-only vs slm vs full)
python -m eval.runner --source agentdojo --compare
```

## Benchmark Sources

### AgentDojo (ffuuugor/agentdojo-dump on HuggingFace)

Indirect prompt injection attacks via tool results, emails, web content.
Directly matches Qise's Ingress detection (PromptGuard).

- ~13,900 samples (86 user tasks x 27 injection tasks x 12 attack types)
- 4 suites: workspace, travel, banking, slack
- Attack types: important_instructions, ignore_previous, system_message, tool_knowledge, etc.
- Requires: `pip install datasets`

### AgentHarm (ai-safety-institute/AgentHarm on HuggingFace)

Harmful agent behaviors with tool calls. Matches Qise's Egress + Output detection.

- 208 harmful + 208 benign behaviors (test_public split)
- 8 categories: Cybercrime, Fraud, Disinformation, Drugs, Harassment, Hate, Sexual, Copyright
- Category → Pipeline mapping:
  - Cybercrime/Drugs → Egress (CommandGuard)
  - Fraud → Egress (ExfilGuard)
  - Disinfo/Harassment/Hate/Sexual → Output (OutputGuard)
- Requires: `pip install datasets`

### CyberSecEval 4 (Meta PurpleLlama on GitHub)

Prompt injection, MITRE ATT&CK, and insecure code samples.

- prompt_injection: 251 English samples → Ingress
- prompt_injection_multilingual: 1004 samples (17 languages) → Ingress
- mitre: 1000 samples (10 categories) → Egress
- mitre_frr: 750 benign samples → Safe baseline
- Downloaded directly from GitHub (no HF authentication needed)

## Local YAML Datasets

For custom test cases not covered by benchmarks:

```yaml
name: dataset_name_v1
description: What this dataset tests
cases:
  - id: UNIQUE-ID
    category: attack_category
    description: "Human-readable description"
    input:
      tool_name: bash
      tool_args:
        command: "some command"
      trust_boundary: user_input      # optional
      agent_reasoning: "reasoning"    # optional
    expected_verdict: block           # block | warn | pass
```

### Matching Rules

- `block` expected → actual must be `block` (missed detection is a false negative)
- `warn` expected → actual must be `warn` or `block` (over-detection is acceptable)
- `pass` expected → actual must be `pass` (false positive if not)

## Metrics

| Metric | Description |
|--------|-------------|
| Precision | TP / (TP + FP) — accuracy of positive detections |
| Recall | TP / (TP + FN) — coverage of actual attacks |
| F1 | Harmonic mean of precision and recall |
| FPR | FP / (FP + TN) — false positive rate on safe inputs |

## Report Format

The runner outputs Markdown reports with:

1. **Overall Metrics** — aggregate Precision/Recall/F1/FPR
2. **Per-Source Metrics** — breakdown by benchmark (agentdojo, agentharm, etc.)
3. **Per-Guard Results** — which guards caught what (TP/FP/FN/TN per guard)
4. **Per-Category Metrics** — breakdown by attack category
5. **Mismatches** — samples where Qise's verdict didn't match expected

## Dependencies

```bash
pip install datasets  # Required for AgentDojo and AgentHarm
# CyberSecEval downloads directly from GitHub (no extra deps)
```
