"""ShieldConfig — Pydantic model for shield.yaml configuration.

Supports:
  - Parsing shield.yaml with sensible defaults
  - Environment variable overrides (QISE_*)
  - Per-guard mode configuration (observe/enforce/off)
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field

from qise.models.router import ModelConfig


# ---------------------------------------------------------------------------
# Config sub-models
# ---------------------------------------------------------------------------


class IntegrationProxyConfig(BaseModel):
    port: int = 8822
    target_agents: list[str] = Field(default_factory=lambda: ["claude_code"])
    auto_takeover: bool = True
    crash_recovery: bool = True


class IntegrationConfig(BaseModel):
    mode: Literal["proxy", "mcp", "sdk"] = "sdk"
    proxy: IntegrationProxyConfig = Field(default_factory=IntegrationProxyConfig)
    mcp: dict[str, Any] = Field(default_factory=dict)


class GuardConfig(BaseModel):
    mode: Literal["observe", "enforce", "off"] = "observe"
    slm_confidence_threshold: float | None = None
    threshold_adjustment_factor: float | None = None


class GuardsConfig(BaseModel):
    enabled: list[str] = Field(
        default_factory=lambda: [
            "prompt", "command", "credential", "reasoning",
            "filesystem", "network", "exfil", "resource", "audit",
            "tool_sanity", "context", "output", "tool_policy", "supply_chain",
        ]
    )
    config: dict[str, GuardConfig] = Field(default_factory=dict)


class DataConfig(BaseModel):
    threat_patterns_dir: str = "./data/threat_patterns"
    security_contexts_dir: str = "./data/security_contexts"
    baselines_dir: str = "./data/baselines"


class LoggingConfig(BaseModel):
    level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    format: Literal["json", "text"] = "json"
    output: Literal["stderr", "file"] = "stderr"


class ModelsConfig(BaseModel):
    slm: ModelConfig = Field(default_factory=ModelConfig)
    llm: ModelConfig = Field(default_factory=lambda: ModelConfig(timeout_ms=5000))
    embedding: ModelConfig = Field(default_factory=ModelConfig)


class ToolPolicyProfileConfig(BaseModel):
    """Configuration for a tool policy profile."""

    deny: list[str] = Field(default_factory=list)
    require_approval: list[str] = Field(default_factory=list)
    owner_only: dict[str, list[str]] = Field(default_factory=dict)
    allow_all: bool = False


class ToolPolicyConfigModel(BaseModel):
    """Configuration for tool policy guard."""

    profiles: dict[str, ToolPolicyProfileConfig] = Field(
        default_factory=lambda: {"default": ToolPolicyProfileConfig()}
    )
    active_profile: str = "default"


# ---------------------------------------------------------------------------
# Top-level config
# ---------------------------------------------------------------------------


class ShieldConfig(BaseModel):
    """Root configuration model for Qise shield.yaml."""

    version: str = "1.0"
    integration: IntegrationConfig = Field(default_factory=IntegrationConfig)
    models: ModelsConfig = Field(default_factory=ModelsConfig)
    guards: GuardsConfig = Field(default_factory=GuardsConfig)
    data: DataConfig = Field(default_factory=DataConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    tool_policy: ToolPolicyConfigModel = Field(default_factory=ToolPolicyConfigModel)

    # ------------------------------------------------------------------
    # Loaders
    # ------------------------------------------------------------------

    @classmethod
    def from_yaml(cls, path: str | Path) -> ShieldConfig:
        """Load config from a YAML file, then apply environment variable overrides."""
        path = Path(path)
        if path.exists():
            with open(path) as f:
                raw = yaml.safe_load(f) or {}
        else:
            raw = {}

        config = cls(**raw)
        config._apply_env_overrides()
        return config

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ShieldConfig:
        """Load config from a dict (useful for tests)."""
        config = cls(**data)
        config._apply_env_overrides()
        return config

    @classmethod
    def default(cls) -> ShieldConfig:
        """Return a config with all defaults (no YAML file needed)."""
        config = cls()
        config._apply_env_overrides()
        return config

    # ------------------------------------------------------------------
    # Environment variable overrides
    # ------------------------------------------------------------------

    def _apply_env_overrides(self) -> None:
        """Override config values from QISE_* environment variables."""
        if val := os.getenv("QISE_INTEGRATION_MODE"):
            self.integration.mode = val  # type: ignore[assignment]

        if val := os.getenv("QISE_PROXY_PORT"):
            self.integration.proxy.port = int(val)

        if val := os.getenv("QISE_SLM_BASE_URL"):
            self.models.slm.base_url = val
        if val := os.getenv("QISE_SLM_MODEL"):
            self.models.slm.model = val

        if val := os.getenv("QISE_LLM_BASE_URL"):
            self.models.llm.base_url = val
        if val := os.getenv("QISE_LLM_MODEL"):
            self.models.llm.model = val

        if val := os.getenv("QISE_LOG_LEVEL"):
            self.logging.level = val  # type: ignore[assignment]

        if val := os.getenv("QISE_MODE"):
            # Global guard mode override — apply to all guards
            for name in self.guards.config:
                self.guards.config[name].mode = val  # type: ignore[assignment]

    # ------------------------------------------------------------------
    # Convenience accessors
    # ------------------------------------------------------------------

    def guard_mode(self, guard_name: str) -> str:
        """Return the mode for a specific guard, defaulting to 'observe'."""
        gc = self.guards.config.get(guard_name)
        if gc is not None:
            return gc.mode
        return "observe"

    def is_guard_enabled(self, guard_name: str) -> bool:
        """True if the guard is in the enabled list and not set to 'off'."""
        if guard_name not in self.guards.enabled:
            return False
        gc = self.guards.config.get(guard_name)
        return gc is None or gc.mode != "off"
