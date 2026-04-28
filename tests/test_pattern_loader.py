"""Tests for ThreatPatternLoader."""

from pathlib import Path

import pytest

from qise.data.pattern_loader import ThreatPatternLoader


@pytest.fixture
def loader() -> ThreatPatternLoader:
    return ThreatPatternLoader(Path("./data/threat_patterns"))


class TestThreatPatternLoader:

    def test_loads_yaml_files(self, loader: ThreatPatternLoader) -> None:
        assert len(loader.patterns) >= 3  # At least 3 YAML files

    def test_get_examples_for_prompt(self, loader: ThreatPatternLoader) -> None:
        examples = loader.get_examples_for_prompt("world_to_agent", count=2)
        assert len(examples) <= 2
        assert all("input" in ex and "verdict" in ex for ex in examples)

    def test_get_rule_signatures(self, loader: ThreatPatternLoader) -> None:
        sigs = loader.get_rule_signatures("world_to_agent")
        assert len(sigs) > 0
        assert all(s.type in ("regex", "keyword_in_description", "length_anomaly") for s in sigs)

    def test_get_mitigations(self, loader: ThreatPatternLoader) -> None:
        mits = loader.get_mitigations("indirect_injection")
        assert len(mits) > 0

    def test_get_isolation_banners(self, loader: ThreatPatternLoader) -> None:
        banners = loader.get_isolation_banners("tool_result")
        assert len(banners) > 0
        assert all(isinstance(b, str) for b in banners)

    def test_nonexistent_dir(self) -> None:
        loader = ThreatPatternLoader(Path("/nonexistent"))
        assert len(loader.patterns) == 0

    def test_empty_category(self, loader: ThreatPatternLoader) -> None:
        examples = loader.get_examples_for_prompt("nonexistent_category")
        assert examples == []
