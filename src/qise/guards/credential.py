"""CredentialGuard — pure rules guard detecting credentials in output.

30+ regex patterns for API keys, tokens, private keys, and passwords.
Recursively scans all string values in tool_args (nested dicts/lists).
Also uses parameter name heuristics for sensitive field detection.
"""

from __future__ import annotations

import re
from typing import Any

from qise.core.guard_base import AIGuardBase, RuleChecker
from qise.core.models import GuardContext, GuardResult, GuardVerdict, RiskAttribution

# ---------------------------------------------------------------------------
# API key patterns: (regex, label, confidence)
# ---------------------------------------------------------------------------

_CREDENTIAL_PATTERNS: list[tuple[str, str, float]] = [
    # Cloud providers
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID", 0.95),
    (r"aws_secret_access_key\s*=\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?", "AWS Secret Access Key", 0.95),
    (r"AIza[0-9A-Za-z\-_]{35}", "Google API Key", 0.9),
    (r"ya29\.[0-9A-Za-z\-_]+", "Google OAuth Token", 0.85),
    (r"ASI[A0-9][0-9A-Z]{15}", "AWS STS Access Key ID", 0.9),
    # GitHub
    (r"ghp_[A-Za-z0-9_]{36,}", "GitHub Personal Access Token", 0.95),
    (r"gho_[A-Za-z0-9_]{36,}", "GitHub OAuth Token", 0.95),
    (r"ghu_[A-Za-z0-9_]{36,}", "GitHub User-to-Server Token", 0.95),
    (r"ghs_[A-Za-z0-9_]{36,}", "GitHub Server-to-Server Token", 0.95),
    (r"ghr_[A-Za-z0-9_]{36,}", "GitHub Refresh Token", 0.95),
    # Slack
    (r"xox[baprs]-[0-9]{10,}-[0-9]{10,}-[0-9a-zA-Z]{24,}", "Slack Token", 0.9),
    # Stripe
    (r"sk_live_[0-9a-zA-Z]{24,}", "Stripe Live Secret Key", 0.95),
    (r"pk_live_[0-9a-zA-Z]{24,}", "Stripe Live Publishable Key", 0.85),
    # Anthropic
    (r"sk-ant-[a-zA-Z0-9\-_]{20,}", "Anthropic API Key", 0.95),
    # OpenAI
    (r"sk-[a-zA-Z0-9]{20,}T3BlbkFJ[a-zA-Z0-9]{20,}", "OpenAI API Key", 0.95),
    # Private keys
    (r"-----BEGIN\s+RSA\s+PRIVATE\s+KEY-----", "RSA Private Key", 0.98),
    (r"-----BEGIN\s+EC\s+PRIVATE\s+KEY-----", "EC Private Key", 0.98),
    (r"-----BEGIN\s+DSA\s+PRIVATE\s+KEY-----", "DSA Private Key", 0.98),
    (r"-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----", "OpenSSH Private Key", 0.98),
    (r"-----BEGIN\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----", "PGP Private Key", 0.98),
    # Generic patterns
    (r"(?i)api[_-]?key\s*[:=]\s*['\"]?[A-Za-z0-9\-_]{20,}['\"]?", "API Key assignment", 0.7),
    (r"(?i)secret[_-]?key\s*[:=]\s*['\"]?[A-Za-z0-9\-_]{20,}['\"]?", "Secret Key assignment", 0.7),
    (r"(?i)access[_-]?token\s*[:=]\s*['\"]?[A-Za-z0-9\-_\.]{20,}['\"]?", "Access Token assignment", 0.7),
    (r"(?i)auth[_-]?token\s*[:=]\s*['\"]?[A-Za-z0-9\-_\.]{20,}['\"]?", "Auth Token assignment", 0.7),
    (r"(?i)bearer\s+[A-Za-z0-9\-_\.]{20,}", "Bearer Token", 0.8),
    (r"(?i)password\s*[:=]\s*['\"][^\s'\"]{8,}['\"]", "Password assignment", 0.65),
    # JWT-like tokens
    (r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+", "JWT Token", 0.8),
    # Heroku
    (r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "UUID/API Key (possible)", 0.4),
]

# Pre-compile patterns
_COMPILED_PATTERNS: list[tuple[re.Pattern, str, float]] = [
    (re.compile(p), label, conf) for p, label, conf in _CREDENTIAL_PATTERNS
]

# Parameter name heuristics
_SENSITIVE_PARAM_NAMES: set[str] = {
    "password", "passwd", "pwd",
    "secret", "secret_key", "secretkey",
    "token", "access_token", "auth_token", "refresh_token", "id_token",
    "api_key", "apikey", "api_secret",
    "private_key", "privatekey",
    "credentials", "credential",
    "auth", "authorization",
}


# ---------------------------------------------------------------------------
# RuleChecker
# ---------------------------------------------------------------------------


class CredentialGuardRuleChecker(RuleChecker):
    """Pure rules credential detection in tool arguments."""

    def check(self, context: GuardContext) -> GuardResult:
        findings: list[tuple[str, float]] = []  # (label, confidence)

        # Recursively scan all string values
        self._scan_values(context.tool_args, findings)

        # Check parameter names
        param_findings = self._check_param_names(context.tool_args)
        findings.extend(param_findings)

        if not findings:
            return GuardResult(guard_name="credential", verdict=GuardVerdict.PASS)

        # Use the highest-confidence finding
        best_label, best_conf = max(findings, key=lambda x: x[1])

        if best_conf >= 0.9:
            return GuardResult(
                guard_name="credential",
                verdict=GuardVerdict.BLOCK,
                confidence=best_conf,
                message=f"Credential detected: {best_label}",
                risk_attribution=RiskAttribution(
                    risk_source="credential_exfil",
                    failure_mode="data_leakage",
                    real_world_harm="privacy_violation",
                    confidence=best_conf,
                    reasoning=f"Credential pattern matched: {best_label}",
                ),
            )

        if best_conf >= 0.7:
            return GuardResult(
                guard_name="credential",
                verdict=GuardVerdict.WARN,
                confidence=best_conf,
                message=f"Possible credential: {best_label}",
            )

        return GuardResult(
            guard_name="credential",
            verdict=GuardVerdict.WARN,
            confidence=best_conf,
            message=f"Low-confidence credential match: {best_label}",
        )

    def _scan_values(self, obj: Any, findings: list[tuple[str, float]]) -> None:
        """Recursively scan string values for credential patterns."""
        if isinstance(obj, str):
            for pattern, label, confidence in _COMPILED_PATTERNS:
                if pattern.search(obj):
                    findings.append((label, confidence))
        elif isinstance(obj, dict):
            for v in obj.values():
                self._scan_values(v, findings)
        elif isinstance(obj, list):
            for item in obj:
                self._scan_values(item, findings)

    def _check_param_names(self, obj: Any, prefix: str = "") -> list[tuple[str, float]]:
        """Check dict keys for sensitive parameter names."""
        results: list[tuple[str, float]] = []
        if isinstance(obj, dict):
            for key, value in obj.items():
                if isinstance(key, str) and key.lower() in _SENSITIVE_PARAM_NAMES:
                    if isinstance(value, str) and len(value) > 0:
                        results.append((f"sensitive param: {key}", 0.6))
                results.extend(self._check_param_names(value, prefix=key))
        elif isinstance(obj, list):
            for item in obj:
                results.extend(self._check_param_names(item))
        return results


# ---------------------------------------------------------------------------
# CredentialGuard
# ---------------------------------------------------------------------------


class CredentialGuard(AIGuardBase):
    """Pure rules guard detecting credentials in agent output.

    No SLM/LLM needed — regex patterns cover known credential formats.
    """

    name = "credential"
    primary_strategy = "rules"
    slm_prompt_template = ""
    llm_prompt_template = None

    def __init__(self) -> None:
        self.rule_fallback = CredentialGuardRuleChecker()
