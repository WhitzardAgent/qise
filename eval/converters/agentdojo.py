"""AgentDojo → Qise EvalSample converter.

AgentDojo provides indirect prompt injection attacks via tool results,
emails, and web content — directly matching Qise's Ingress detection.

Dataset: ffuuugor/agentdojo-dump on HuggingFace
~13,900 rows covering workspace/travel/banking/slack suites.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Add project root
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))

from qise.core.models import GuardContext

from eval.runner import EvalSample


class AgentDojoConverter:
    """Convert AgentDojo dump from HuggingFace into Qise EvalSamples.

    The dump (ffuuugor/agentdojo-dump) has one row per
    (user_task, injection_task, attack) combination with fields:
      - suite_name, user_task_id, injection_task_id, attack_name
      - tool_call_function, tool_call_args, tool_response
      - label (0/1 — whether injection succeeded)
      - user_task_prompt, injection_goal
    """

    SOURCE = "agentdojo"
    HF_DATASET = "ffuuugor/agentdojo-dump"

    # Map AgentDojo attack names to Qise trust boundaries
    ATTACK_TO_TRUST: dict[str, str] = {
        "important_instructions": "tool_result",
        "important_instructions_no_user_name": "tool_result",
        "important_instructions_no_model_name": "tool_result",
        "important_instructions_no_names": "tool_result",
        "important_instructions_wrong_model_name": "tool_result",
        "important_instructions_wrong_user_name": "tool_result",
        "tool_knowledge": "tool_result",
        "injecagent": "tool_result",
        "ignore_previous": "user_input",
        "system_message": "tool_result",
        "direct": "user_input",
    }

    def convert(self, limit: int | None = None, cache_dir: str | None = None) -> list[EvalSample]:
        """Load AgentDojo data and convert to EvalSamples.

        Args:
            limit: Max samples to load (None = all).
            cache_dir: Directory for HuggingFace dataset cache.
        """
        try:
            from datasets import load_dataset
        except ImportError:
            print("ERROR: `datasets` package required. Run: pip install datasets")
            return []

        ds = load_dataset(self.HF_DATASET, split="train", cache_dir=cache_dir)
        samples: list[EvalSample] = []

        for row in ds:
            if limit and len(samples) >= limit:
                break

            attack = row.get("attack_name", "")
            trust = self.ATTACK_TO_TRUST.get(attack, "tool_result")

            # Injection payload — the malicious content injected into tool result
            injection_goal = row.get("injection_goal", "") or ""
            tool_response = row.get("tool_response", "") or ""
            # Use injection_goal as the primary content to check
            content = injection_goal if injection_goal else tool_response

            if not content.strip():
                continue

            suite = row.get("suite_name", "unknown")
            user_task_id = row.get("user_task_id", "")
            inj_task_id = row.get("injection_task_id", "")
            sample_id = f"AD-{suite}-{user_task_id}-{inj_task_id}-{attack}"

            ctx = GuardContext(
                tool_name="content_check",
                tool_args={"content": content},
                trust_boundary=trust,
            )

            samples.append(EvalSample(
                id=sample_id,
                source=self.SOURCE,
                category="injection",
                guard_context=ctx,
                expected_verdict="block",
                metadata={
                    "suite": suite,
                    "attack_name": attack,
                    "injection_task_id": inj_task_id,
                    "user_task_prompt": row.get("user_task_prompt", ""),
                },
            ))

        # Add safe samples from user_task_prompts (unique)
        seen_prompts: set[str] = set()
        for row in ds:
            prompt = row.get("user_task_prompt", "")
            if not prompt or prompt in seen_prompts:
                continue
            seen_prompts.add(prompt)

            suite = row.get("suite_name", "unknown")
            user_task_id = row.get("user_task_id", "")

            ctx = GuardContext(
                tool_name="content_check",
                tool_args={"content": prompt},
                trust_boundary="user_input",
            )
            samples.append(EvalSample(
                id=f"AD-SAFE-{suite}-{user_task_id}",
                source=self.SOURCE,
                category="safe_user_task",
                guard_context=ctx,
                expected_verdict="pass",
                metadata={"suite": suite, "user_task_id": user_task_id},
            ))

        return samples

    def convert_from_json(self, path: str, limit: int | None = None) -> list[EvalSample]:
        """Load from a local JSON file (pre-downloaded dump).

        The dump is a JSON array of objects with the same fields as the HF dataset.
        """
        with open(path) as f:
            rows = json.load(f)

        if limit:
            rows = rows[:limit]

        # Reuse same logic by wrapping rows as dicts
        samples: list[EvalSample] = []
        seen_prompts: set[str] = set()

        for row in rows:
            attack = row.get("attack_name", "")
            trust = self.ATTACK_TO_TRUST.get(attack, "tool_result")
            injection_goal = row.get("injection_goal", "") or ""
            tool_response = row.get("tool_response", "") or ""
            content = injection_goal if injection_goal else tool_response
            if not content.strip():
                continue

            suite = row.get("suite_name", "unknown")
            user_task_id = row.get("user_task_id", "")
            inj_task_id = row.get("injection_task_id", "")

            ctx = GuardContext(
                tool_name="content_check",
                tool_args={"content": content},
                trust_boundary=trust,
            )
            samples.append(EvalSample(
                id=f"AD-{suite}-{user_task_id}-{inj_task_id}-{attack}",
                source=self.SOURCE,
                category="injection",
                guard_context=ctx,
                expected_verdict="block",
                metadata={"suite": suite, "attack_name": attack},
            ))

            # Safe sample from user prompt
            prompt = row.get("user_task_prompt", "")
            if prompt and prompt not in seen_prompts:
                seen_prompts.add(prompt)
                ctx_safe = GuardContext(
                    tool_name="content_check",
                    tool_args={"content": prompt},
                    trust_boundary="user_input",
                )
                samples.append(EvalSample(
                    id=f"AD-SAFE-{suite}-{user_task_id}",
                    source=self.SOURCE,
                    category="safe_user_task",
                    guard_context=ctx_safe,
                    expected_verdict="pass",
                    metadata={"suite": suite},
                ))

        return samples
