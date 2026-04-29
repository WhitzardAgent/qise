"""CyberSecEval 4 → Qise EvalSample converter.

CyberSecEval 4 provides prompt injection, MITRE ATT&CK, and insecure code
samples from Meta's PurpleLlama repository.

Data source: GitHub (PurpleLlama) JSON files, not HuggingFace.
"""

from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))

from qise.core.models import GuardContext

from eval.runner import EvalSample


# PurpleLlama pinned commit for dataset URLs
_PURPLELLAMA_COMMIT = "fe05293b610dabc3967443f2dd4dc35c4e8971b6"
_BASE_URL = (
    f"https://raw.githubusercontent.com/meta-llama/PurpleLlama/"
    f"{_PURPLELLAMA_COMMIT}/CybersecurityBenchmarks/datasets"
)

DATASET_URLS: dict[str, str] = {
    "prompt_injection": f"{_BASE_URL}/prompt_injection/prompt_injection.json",
    "prompt_injection_multilingual": (
        f"{_BASE_URL}/prompt_injection/"
        "prompt_injection_multilingual_machine_translated.json"
    ),
    "mitre": f"{_BASE_URL}/mitre/mitre_benchmark_100_per_category_with_augmentation.json",
    "mitre_frr": f"{_BASE_URL}/mitre_frr/mitre_frr.json",
}


class CyberSecEvalConverter:
    """Convert CyberSecEval 4 datasets from PurpleLlama GitHub into Qise EvalSamples.

    Subsets:
      - prompt_injection (251 English samples) → Ingress
      - prompt_injection_multilingual (1004 samples, 17 languages) → Ingress
      - mitre (1000 samples, 10 categories) → Egress
      - mitre_frr (750 benign samples) → Safe baseline
    """

    SOURCE = "cyberseceval"

    # MITRE category → Qise mapping
    MITRE_CATEGORY_MAP: dict[str, str] = {
        "C2": "dangerous_cmd",
        "Collection": "exfil",
        "Credential Access": "credential_theft",
        "Defense Evasion": "evasion",
        "Discovery": "recon",
        "Execution": "dangerous_cmd",
        "Exfiltration": "exfil",
        "Impact": "dangerous_cmd",
        "Initial Access": "recon",
        "Lateral Movement": "lateral_movement",
    }

    def convert(
        self,
        subsets: list[str] | None = None,
        limit_per_subset: int | None = None,
        cache_dir: str | None = None,
    ) -> list[EvalSample]:
        """Download and convert CyberSecEval datasets.

        Args:
            subsets: Which subsets to load. Default: all.
            limit_per_subset: Max samples per subset.
            cache_dir: Local directory to cache downloaded JSON files.
        """
        if subsets is None:
            subsets = list(DATASET_URLS.keys())

        samples: list[EvalSample] = []

        for subset in subsets:
            url = DATASET_URLS.get(subset)
            if not url:
                print(f"WARNING: Unknown subset '{subset}', skipping")
                continue

            data = self._load_json(url, cache_dir, subset)
            if not data:
                continue

            converter = {
                "prompt_injection": self._convert_prompt_injection,
                "prompt_injection_multilingual": self._convert_prompt_injection,
                "mitre": self._convert_mitre,
                "mitre_frr": self._convert_mitre_frr,
            }.get(subset)

            if converter:
                subset_samples = converter(data, subset)
                if limit_per_subset:
                    subset_samples = subset_samples[:limit_per_subset]
                samples.extend(subset_samples)
                print(f"  {subset}: {len(subset_samples)} samples")

        return samples

    def convert_from_json(
        self,
        subset: str,
        path: str,
        limit: int | None = None,
    ) -> list[EvalSample]:
        """Load from a local JSON file."""
        with open(path) as f:
            data = json.load(f)

        converter = {
            "prompt_injection": self._convert_prompt_injection,
            "prompt_injection_multilingual": self._convert_prompt_injection,
            "mitre": self._convert_mitre,
            "mitre_frr": self._convert_mitre_frr,
        }.get(subset)

        if not converter:
            print(f"WARNING: Unknown subset '{subset}'")
            return []

        samples = converter(data, subset)
        if limit:
            samples = samples[:limit]
        return samples

    def _load_json(self, url: str, cache_dir: str | None, subset: str) -> list[dict] | None:
        """Download JSON from URL, with optional local caching."""
        if cache_dir:
            cache_path = Path(cache_dir) / f"cyberseceval_{subset}.json"
            if cache_path.exists():
                with open(cache_path) as f:
                    return json.load(f)

        try:
            print(f"  Downloading {subset}...")
            req = urllib.request.Request(url, headers={"User-Agent": "Qise-Eval/1.0"})
            with urllib.request.urlopen(req, timeout=60) as resp:
                raw = resp.read().decode("utf-8")
        except Exception as e:
            print(f"  ERROR: Failed to download {subset}: {e}")
            return None

        # Parse — may be a dict with a key or a plain list
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            # Some files wrap data in a top-level key
            for v in parsed.values():
                if isinstance(v, list):
                    parsed = v
                    break
            if isinstance(parsed, dict):
                parsed = [parsed]

        # Cache
        if cache_dir:
            cache_path = Path(cache_dir) / f"cyberseceval_{subset}.json"
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            cache_path.write_text(json.dumps(parsed, indent=2))

        return parsed

    def _convert_prompt_injection(self, data: list[dict], subset: str) -> list[EvalSample]:
        """Convert prompt injection samples → Ingress EvalSamples."""
        samples: list[EvalSample] = []
        for row in data:
            prompt_id = row.get("prompt_id", 0)
            user_input = row.get("user_input", "")
            variant = row.get("injection_variant", "unknown")
            language = row.get("speaking_language", "English")
            risk = row.get("risk_category", "unknown")

            if not user_input.strip():
                continue

            ctx = GuardContext(
                tool_name="content_check",
                tool_args={"content": user_input},
                trust_boundary="user_input",
            )
            samples.append(EvalSample(
                id=f"CSE-{subset}-{prompt_id}",
                source=self.SOURCE,
                category="prompt_injection",
                guard_context=ctx,
                expected_verdict="block",
                metadata={
                    "injection_variant": variant,
                    "language": language,
                    "risk_category": risk,
                },
            ))
        return samples

    def _convert_mitre(self, data: list[dict], subset: str) -> list[EvalSample]:
        """Convert MITRE ATT&CK samples → Egress EvalSamples."""
        samples: list[EvalSample] = []
        for i, row in enumerate(data):
            mutated_prompt = row.get("mutated_prompt", "")
            category = row.get("mitre_category", "unknown")
            ttp = row.get("ttp_id_name_mapping", {})

            if not mutated_prompt.strip():
                continue

            qise_category = self.MITRE_CATEGORY_MAP.get(category, "dangerous_cmd")

            ctx = GuardContext(
                tool_name="bash",
                tool_args={"command": mutated_prompt},
            )
            samples.append(EvalSample(
                id=f"CSE-MITRE-{i}",
                source=self.SOURCE,
                category=qise_category,
                guard_context=ctx,
                expected_verdict="block",
                metadata={
                    "mitre_category": category,
                    "ttp_id": ttp.get("TTP_ID", ""),
                    "ttp_name": ttp.get("TTP_Name", ""),
                },
            ))
        return samples

    def _convert_mitre_frr(self, data: list[dict], subset: str) -> list[EvalSample]:
        """Convert MITRE FRR (benign) samples → Safe EvalSamples."""
        samples: list[EvalSample] = []
        for i, row in enumerate(data):
            mutated_prompt = row.get("mutated_prompt", "")

            if not mutated_prompt.strip():
                continue

            ctx = GuardContext(
                tool_name="bash",
                tool_args={"command": mutated_prompt},
            )
            samples.append(EvalSample(
                id=f"CSE-FRR-{i}",
                source=self.SOURCE,
                category="safe_mitre",
                guard_context=ctx,
                expected_verdict="pass",
                metadata={"attack_type": row.get("attack_type", "")},
            ))
        return samples
