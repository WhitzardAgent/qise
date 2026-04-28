"""ToolPolicyGuard — pure rules guard for profile-based tool access control.

Enforces deny lists, require-approval lists, and owner-only restrictions
using fnmatch glob patterns for flexible matching.
"""

from __future__ import annotations

import fnmatch

from pydantic import BaseModel, Field

from qise.core.guard_base import AIGuardBase, RuleChecker
from qise.core.models import GuardContext, GuardResult, GuardVerdict, RiskAttribution

# ---------------------------------------------------------------------------
# Config models
# ---------------------------------------------------------------------------


class ToolPolicyProfile(BaseModel):
    """A tool access policy profile."""

    deny: list[str] = Field(default_factory=list)
    require_approval: list[str] = Field(default_factory=list)
    owner_only: dict[str, list[str]] = Field(default_factory=dict)
    allow_all: bool = False


class ToolPolicyConfig(BaseModel):
    """Configuration for tool policy guard."""

    profiles: dict[str, ToolPolicyProfile] = Field(
        default_factory=lambda: {"default": ToolPolicyProfile()}
    )
    active_profile: str = "default"


# ---------------------------------------------------------------------------
# RuleChecker
# ---------------------------------------------------------------------------


class ToolPolicyGuardRuleChecker(RuleChecker):
    """Deterministic tool access policy enforcement."""

    def __init__(
        self,
        profiles: dict[str, ToolPolicyProfile] | None = None,
        active_profile: str = "default",
    ) -> None:
        self.profiles = profiles or {"default": ToolPolicyProfile()}
        self.active_profile = active_profile

    def check(self, context: GuardContext) -> GuardResult:
        profile = self.profiles.get(self.active_profile)
        if profile is None:
            return GuardResult(guard_name="tool_policy", verdict=GuardVerdict.PASS)

        # 1. Deny list
        for pattern in profile.deny:
            if fnmatch.fnmatch(context.tool_name, pattern):
                return GuardResult(
                    guard_name="tool_policy",
                    verdict=GuardVerdict.BLOCK,
                    confidence=0.95,
                    message=f"Tool denied by policy: {context.tool_name} matches '{pattern}'",
                    risk_attribution=RiskAttribution(
                        risk_source="tool_policy_violation",
                        failure_mode="unauthorized_action",
                        real_world_harm="system_compromise",
                        confidence=0.95,
                        reasoning=f"Tool '{context.tool_name}' matches deny pattern '{pattern}'",
                    ),
                )

        # 2. Require-approval list
        for pattern in profile.require_approval:
            if fnmatch.fnmatch(context.tool_name, pattern):
                return GuardResult(
                    guard_name="tool_policy",
                    verdict=GuardVerdict.APPROVE,
                    confidence=0.9,
                    message=f"Tool requires approval: {context.tool_name} matches '{pattern}'",
                )

        # 3. Owner-only tools
        for pattern, owners in profile.owner_only.items():
            if fnmatch.fnmatch(context.tool_name, pattern):
                if context.user_id not in owners:
                    return GuardResult(
                        guard_name="tool_policy",
                        verdict=GuardVerdict.BLOCK,
                        confidence=0.9,
                        message=f"Tool restricted to owners: {context.tool_name}",
                        risk_attribution=RiskAttribution(
                            risk_source="tool_policy_violation",
                            failure_mode="unauthorized_action",
                            real_world_harm="system_compromise",
                            confidence=0.9,
                            reasoning=f"User '{context.user_id}' not in owner list for '{context.tool_name}'",
                        ),
                    )

        return GuardResult(guard_name="tool_policy", verdict=GuardVerdict.PASS)


# ---------------------------------------------------------------------------
# ToolPolicyGuard
# ---------------------------------------------------------------------------


class ToolPolicyGuard(AIGuardBase):
    """Pure rules guard for profile-based tool access control.

    No SLM/LLM needed — policy rules are deterministic.
    """

    name = "tool_policy"
    primary_strategy = "rules"
    slm_prompt_template = ""
    llm_prompt_template = None

    def __init__(
        self,
        profiles: dict[str, ToolPolicyProfile] | None = None,
        active_profile: str = "default",
    ) -> None:
        self.rule_fallback = ToolPolicyGuardRuleChecker(
            profiles=profiles,
            active_profile=active_profile,
        )
