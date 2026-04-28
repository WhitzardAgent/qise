"""SupplyChainGuard — AI + rules guard for Skill/MCP/KB supply chain verification.

Source whitelist, hash verification, and MCP configuration integrity checks.
"""

from __future__ import annotations

import re

from qise.core.guard_base import AIGuardBase, RuleChecker
from qise.core.models import GuardContext, GuardResult, GuardVerdict, RiskAttribution
from qise.data.baseline_manager import BaselineManager

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

_DEFAULT_WHITELIST = frozenset({"system", "official", "verified"})

_MCP_DANGEROUS_COMMAND_PATTERNS: list[tuple[str, str]] = [
    (r"curl\s+.*\|\s*(ba)?sh", "curl pipe to shell in MCP command"),
    (r"wget\s+.*\|\s*(ba)?sh", "wget pipe to shell in MCP command"),
]

_MCP_SENSITIVE_ENV = frozenset({"API_KEY", "SECRET", "TOKEN", "PASSWORD", "PRIVATE_KEY"})


# ---------------------------------------------------------------------------
# RuleChecker
# ---------------------------------------------------------------------------


class SupplyChainGuardRuleChecker(RuleChecker):
    """Deterministic supply chain verification checks."""

    def __init__(
        self,
        baseline_manager: BaselineManager | None = None,
        source_whitelist: set[str] | None = None,
    ) -> None:
        self.baseline_manager = baseline_manager
        self.source_whitelist = source_whitelist or set(_DEFAULT_WHITELIST)

    def check(self, context: GuardContext) -> GuardResult:
        # 1. Source whitelist
        result = self._check_source(context)
        if result is not None:
            return result

        # 2. Hash verification
        if self.baseline_manager:
            result = self._check_hash(context)
            if result is not None:
                return result

        # 3. MCP configuration integrity
        result = self._check_mcp_config(context)
        if result is not None:
            return result

        return GuardResult(guard_name="supply_chain", verdict=GuardVerdict.PASS)

    def _check_source(self, context: GuardContext) -> GuardResult | None:
        """Check if tool/content source is in whitelist."""
        if not context.tool_source:
            return None

        if context.tool_source not in self.source_whitelist:
            return GuardResult(
                guard_name="supply_chain",
                verdict=GuardVerdict.WARN,
                confidence=0.7,
                message=f"Unverified source: {context.tool_source}",
                risk_attribution=RiskAttribution(
                    risk_source="supply_chain",
                    failure_mode="unverified_source",
                    real_world_harm="system_compromise",
                    confidence=0.7,
                    reasoning=f"Source '{context.tool_source}' not in whitelist: {self.source_whitelist}",
                ),
            )
        return None

    def _check_hash(self, context: GuardContext) -> GuardResult | None:
        """Verify content hash against baseline."""
        content = context.tool_args.get("content") or context.tool_args.get("description")
        item_id = context.tool_args.get("id") or context.tool_name

        if not content or not isinstance(content, str) or not item_id:
            return None

        result = self.baseline_manager.check_tool_baseline(str(item_id), content)
        if result.changed:
            return GuardResult(
                guard_name="supply_chain",
                verdict=GuardVerdict.BLOCK,
                confidence=0.85,
                message=f"Supply chain integrity violation: {context.tool_name} hash changed",
                risk_attribution=RiskAttribution(
                    risk_source="supply_chain",
                    failure_mode="content_tampering",
                    real_world_harm="system_compromise",
                    confidence=0.85,
                    reasoning=f"Content hash for '{context.tool_name}' does not match baseline",
                ),
            )
        return None

    def _check_mcp_config(self, context: GuardContext) -> GuardResult | None:
        """Check MCP configuration for suspicious patterns."""
        # Check command field
        command = context.tool_args.get("command")
        if isinstance(command, str):
            for pattern, desc in _MCP_DANGEROUS_COMMAND_PATTERNS:
                if re.search(pattern, command, re.IGNORECASE):
                    return GuardResult(
                        guard_name="supply_chain",
                        verdict=GuardVerdict.BLOCK,
                        confidence=0.9,
                        message=f"Dangerous command in MCP config: {desc}",
                        risk_attribution=RiskAttribution(
                            risk_source="supply_chain",
                            failure_mode="remote_code_execution",
                            real_world_harm="system_compromise",
                            confidence=0.9,
                            reasoning=f"MCP command matches dangerous pattern: {desc}",
                        ),
                    )

        # Check env field
        env = context.tool_args.get("env")
        if isinstance(env, dict):
            for key in env:
                key_upper = key.upper()
                for sensitive in _MCP_SENSITIVE_ENV:
                    if sensitive in key_upper:
                        return GuardResult(
                            guard_name="supply_chain",
                            verdict=GuardVerdict.WARN,
                            confidence=0.7,
                            message=f"Sensitive environment variable in MCP config: {key}",
                        )

        return None


# ---------------------------------------------------------------------------
# SupplyChainGuard
# ---------------------------------------------------------------------------


class SupplyChainGuard(AIGuardBase):
    """AI + rules guard for Skill/MCP/KB supply chain verification.

    Rules: source whitelist, hash verification, MCP config integrity.
    SLM: Semantic analysis of Skill/MCP content for malicious intent.
    """

    name = "supply_chain"
    primary_strategy = "ai"

    slm_prompt_template = """Analyze this Skill or MCP server configuration for malicious intent:
1. Does it attempt to exfiltrate data to external services?
2. Does it contain hidden instructions that manipulate agent behavior?
3. Does it execute suspicious commands or access sensitive resources?

Tool name: {tool_name}
Source: {tool_source}
Configuration: {tool_args}

Return JSON:
{{"verdict": "safe" | "suspicious" | "malicious", "confidence": 0.0-1.0, "risk_source": "supply_chain" | "none", "reasoning": "..."}}"""

    llm_prompt_template = None

    def __init__(
        self,
        baseline_manager: BaselineManager | None = None,
    ) -> None:
        self.rule_fallback = SupplyChainGuardRuleChecker(
            baseline_manager=baseline_manager,
        )
