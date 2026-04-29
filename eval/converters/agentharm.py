"""AgentHarm → Qise EvalSample converter.

AgentHarm provides harmful agent behaviors with tool calls — matching
Qise's Egress detection (CommandGuard, NetworkGuard, ExfilGuard) and
Output detection (OutputGuard).

Dataset: ai-safety-institute/AgentHarm on HuggingFace
208 harmful + 208 benign behaviors, 8 categories.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))

from qise.core.models import GuardContext

from eval.runner import EvalSample


# Category → Qise pipeline mapping
CATEGORY_TO_PIPELINE: dict[str, dict] = {
    "Cybercrime": {"tool_name": "bash", "category": "dangerous_cmd"},
    "Fraud": {"tool_name": "bash", "category": "exfil"},
    "Disinformation": {"tool_name": "output_check", "category": "harmful_output"},
    "Drugs": {"tool_name": "bash", "category": "dangerous_cmd"},
    "Harassment": {"tool_name": "output_check", "category": "harmful_output"},
    "Hate": {"tool_name": "output_check", "category": "harmful_output"},
    "Sexual": {"tool_name": "output_check", "category": "harmful_output"},
    "Copyright": {"tool_name": "bash", "category": "unauthorized_action"},
}


class AgentHarmConverter:
    """Convert AgentHarm dataset from HuggingFace into Qise EvalSamples.

    The dataset has three configs: harmful, harmless_benign, chat.
    Each sample has: id, id_original, name, category, prompt,
    target_functions, detailed_prompt, hint_included.
    """

    SOURCE = "agentharm"
    HF_DATASET = "ai-safety-institute/AgentHarm"

    def convert(
        self,
        include_benign: bool = True,
        limit: int | None = None,
        cache_dir: str | None = None,
    ) -> list[EvalSample]:
        """Load AgentHarm and convert to EvalSamples.

        Args:
            include_benign: Include benign counterparts as safe samples.
            limit: Max samples per config.
            cache_dir: HuggingFace cache directory.
        """
        try:
            from datasets import load_dataset
        except ImportError:
            print("ERROR: `datasets` package required. Run: pip install datasets")
            return []

        samples: list[EvalSample] = []

        # Load harmful behaviors
        ds_harmful = load_dataset(
            self.HF_DATASET, "harmful", split="test_public", cache_dir=cache_dir,
        )
        for row in ds_harmful:
            if limit and len(samples) >= limit:
                break
            sample = self._convert_row(row, is_harmful=True)
            if sample:
                samples.append(sample)

        # Load benign behaviors as safe samples
        if include_benign:
            ds_benign = load_dataset(
                self.HF_DATASET, "harmless_benign", split="test_public", cache_dir=cache_dir,
            )
            for row in ds_benign:
                if limit and len(samples) >= limit:
                    break
                sample = self._convert_row(row, is_harmful=False)
                if sample:
                    samples.append(sample)

        return samples

    def convert_from_json(
        self,
        harmful_path: str,
        benign_path: str | None = None,
        limit: int | None = None,
    ) -> list[EvalSample]:
        """Load from local JSON files."""
        samples: list[EvalSample] = []

        with open(harmful_path) as f:
            harmful_rows = json.load(f)
        for row in harmful_rows:
            if limit and len(samples) >= limit:
                break
            sample = self._convert_row(row, is_harmful=True)
            if sample:
                samples.append(sample)

        if benign_path:
            with open(benign_path) as f:
                benign_rows = json.load(f)
            for row in benign_rows:
                if limit and len(samples) >= limit:
                    break
                sample = self._convert_row(row, is_harmful=False)
                if sample:
                    samples.append(sample)

        return samples

    def _convert_row(self, row: dict, is_harmful: bool) -> EvalSample | None:
        """Convert a single AgentHarm row to an EvalSample."""
        category = row.get("category", "unknown")
        prompt = row.get("prompt", "")
        sample_id = row.get("id", "unknown")
        target_functions = row.get("target_functions", [])

        if not prompt.strip():
            return None

        mapping = CATEGORY_TO_PIPELINE.get(category, {"tool_name": "bash", "category": "unknown"})
        tool_name = mapping["tool_name"]
        eval_category = mapping["category"]

        # For tool-call behaviors, map target_functions to tool_args
        if tool_name == "bash" and target_functions:
            # Simulate a command that would accomplish the harmful behavior
            tool_args = {"command": prompt}
        elif tool_name == "output_check":
            tool_args = {"content": prompt}
        else:
            tool_args = {"command": prompt}

        ctx = GuardContext(
            tool_name=tool_name,
            tool_args=tool_args,
        )

        return EvalSample(
            id=f"AH-{sample_id}",
            source=self.SOURCE,
            category=eval_category,
            guard_context=ctx,
            expected_verdict="block" if is_harmful else "pass",
            metadata={
                "name": row.get("name", ""),
                "agentharm_category": category,
                "target_functions": target_functions,
                "detailed_prompt": row.get("detailed_prompt"),
                "hint_included": row.get("hint_included"),
            },
        )
