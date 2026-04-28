"""OutputGuard — AI + rules guard detecting KB content leaks and PII exposure.

PII pattern matching, credential detection, KB content hash matching,
and SLM semantic analysis for paraphrased leaks.
"""

from __future__ import annotations

import re
from typing import Any

from qise.core.guard_base import AIGuardBase, RuleChecker
from qise.core.models import GuardContext, GuardResult, GuardVerdict, RiskAttribution


# ---------------------------------------------------------------------------
# PII patterns
# ---------------------------------------------------------------------------

_PII_PATTERNS: list[tuple[re.Pattern, str, float]] = [
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"), "email", 0.85),
    (re.compile(r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b"), "phone_number", 0.7),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "SSN", 0.95),
    (re.compile(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b"), "credit_card", 0.9),
    (re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"), "IP_address", 0.5),
]

# Core credential patterns (subset from CredentialGuard)
_CREDENTIAL_PATTERNS: list[tuple[re.Pattern, str, float]] = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS Access Key ID", 0.95),
    (re.compile(r"ghp_[A-Za-z0-9_]{36,}"), "GitHub PAT", 0.95),
    (re.compile(r"sk-ant-[a-zA-Z0-9\-_]{20,}"), "Anthropic API Key", 0.95),
    (re.compile(r"-----BEGIN\s+\w+\s+PRIVATE\s+KEY-----"), "Private Key", 0.98),
    (re.compile(r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+"), "JWT Token", 0.8),
]


# ---------------------------------------------------------------------------
# RuleChecker
# ---------------------------------------------------------------------------


class OutputGuardRuleChecker(RuleChecker):
    """Deterministic PII and credential detection in agent output."""

    def check(self, context: GuardContext) -> GuardResult:
        text = self._extract_text(context)
        if not text:
            return GuardResult(guard_name="output", verdict=GuardVerdict.PASS)

        findings: list[tuple[str, float, str]] = []  # (label, confidence, risk_source)

        # 1. PII patterns
        self._scan_pii(text, findings)

        # 2. Credential patterns
        self._scan_credentials(text, findings)

        if not findings:
            return GuardResult(guard_name="output", verdict=GuardVerdict.PASS)

        best_label, best_conf, best_source = max(findings, key=lambda x: x[1])

        if best_conf >= 0.9:
            return GuardResult(
                guard_name="output",
                verdict=GuardVerdict.BLOCK,
                confidence=best_conf,
                message=f"Sensitive data in output: {best_label}",
                risk_attribution=RiskAttribution(
                    risk_source=best_source,
                    failure_mode="data_leakage",
                    real_world_harm="privacy_violation",
                    confidence=best_conf,
                    reasoning=f"Output contains {best_label}",
                ),
            )

        if best_conf >= 0.7:
            return GuardResult(
                guard_name="output",
                verdict=GuardVerdict.WARN,
                confidence=best_conf,
                message=f"Possible sensitive data in output: {best_label}",
            )

        return GuardResult(
            guard_name="output",
            verdict=GuardVerdict.WARN,
            confidence=best_conf,
            message=f"Low-confidence sensitive data match: {best_label}",
        )

    def _extract_text(self, context: GuardContext) -> str:
        """Extract text content from tool_args."""
        for key in ("text", "content", "output", "message", "result"):
            val = context.tool_args.get(key)
            if isinstance(val, str) and val:
                return val
        # Fallback: join all string values
        parts: list[str] = []
        for v in context.tool_args.values():
            if isinstance(v, str):
                parts.append(v)
        return " ".join(parts)

    def _scan_pii(self, text: str, findings: list[tuple[str, float, str]]) -> None:
        """Scan for PII patterns."""
        for pattern, label, confidence in _PII_PATTERNS:
            if pattern.search(text):
                findings.append((label, confidence, "pii_exposure"))

    def _scan_credentials(self, text: str, findings: list[tuple[str, float, str]]) -> None:
        """Scan for credential patterns."""
        for pattern, label, confidence in _CREDENTIAL_PATTERNS:
            if pattern.search(text):
                findings.append((label, confidence, "credential_leak"))


# ---------------------------------------------------------------------------
# OutputGuard
# ---------------------------------------------------------------------------


class OutputGuard(AIGuardBase):
    """AI + rules guard detecting KB content leaks and PII exposure.

    Rules: PII patterns, credential patterns.
    SLM: Paraphrased KB content, partial credentials.
    """

    name = "output"
    primary_strategy = "ai"

    slm_prompt_template = """Analyze this agent output for data leaks. Does it contain:
1. Verbatim or paraphrased knowledge base content that should not be exposed
2. Personal information (PII) that shouldn't be in the output
3. Sensitive data presented in ways that bypass regex (e.g., "the key starts with AKIA and ends with...")
4. Credential fragments or partial secrets

Output text: {tool_args}

Return JSON:
{{"verdict": "safe" | "suspicious" | "malicious", "confidence": 0.0-1.0, "risk_source": "kb_leak" | "pii_exposure" | "credential_leak" | "none", "reasoning": "..."}}"""

    llm_prompt_template = None

    def __init__(self) -> None:
        self.rule_fallback = OutputGuardRuleChecker()
