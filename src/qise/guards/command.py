"""CommandGuard — rules-first guard detecting shell injection.

Hardwired deny patterns for dangerous commands, pipe chains,
privilege escalation, and obfuscation techniques.

SLM template defined for semantic variant detection (future).
No LLM template — rule + SLM coverage is sufficient.
"""

from __future__ import annotations

import re
from typing import Any

from qise.core.guard_base import AIGuardBase, RuleChecker
from qise.core.models import GuardContext, GuardResult, GuardVerdict, RiskAttribution


# ---------------------------------------------------------------------------
# Deny patterns
# ---------------------------------------------------------------------------

# Critical: almost always malicious — BLOCK
_CRITICAL_PATTERNS: list[tuple[str, str]] = [
    (r"rm\s+-rf\s+/", "Recursive force delete from root"),
    (r"curl\s+.*\|\s*(ba)?sh", "Curl pipe to shell"),
    (r"wget\s+.*\|\s*(ba)?sh", "Wget pipe to shell"),
    (r"curl\s+.*\|\s*bash", "Curl pipe to bash"),
    (r"mkfs\.", "Format filesystem"),
    (r"dd\s+if=.*of=/dev/", "Write raw data to device"),
    (r":\(\)\{.*:\(&\)\}", "Fork bomb"),
    (r">\s*/etc/", "Write to /etc"),
    (r"chmod\s+777", "Set world-writable permissions"),
    (r"chown\s+root", "Change ownership to root"),
]

# High: likely dangerous — BLOCK in enforce, WARN in observe
_HIGH_PATTERNS: list[tuple[str, str]] = [
    (r"\|\s*sudo", "Pipe to sudo"),
    (r"\|\s*(ba)?sh\b", "Pipe to shell"),
    (r"\|\s*zsh\b", "Pipe to zsh"),
    (r"`.*`", "Backtick command substitution"),
    (r"\$\([^)]+\)", "Command substitution $()"),
    (r"sudo\s+rm\b", "Sudo remove"),
    (r"sudo\s+chmod\b", "Sudo chmod"),
    (r"sudo\s+chown\b", "Sudo chown"),
    (r"\bsu\b\s*", "Switch user"),
    (r"\bpkexec\b", "PolicyKit execute"),
]

# Medium: potentially dangerous context — WARN
_MEDIUM_PATTERNS: list[tuple[str, str]] = [
    (r"\bsudo\b", "Sudo usage"),
    (r"\bsu\s+-", "Switch user with login shell"),
    (r"nc\s+-[le]", "Netcat listener/exec"),
    (r"/dev/tcp/", "Bash /dev/tcp network access"),
    (r"\bbase64\s+-d\b", "Base64 decode (potential obfuscation)"),
]


# ---------------------------------------------------------------------------
# RuleChecker
# ---------------------------------------------------------------------------


class CommandGuardRuleChecker(RuleChecker):
    """Deterministic shell command safety checks."""

    def check(self, context: GuardContext) -> GuardResult:
        command = self._extract_command(context)
        if not command:
            return GuardResult(guard_name="command", verdict=GuardVerdict.PASS)

        # Check critical patterns — always BLOCK
        for pattern, desc in _CRITICAL_PATTERNS:
            if re.search(pattern, command, re.IGNORECASE):
                return GuardResult(
                    guard_name="command",
                    verdict=GuardVerdict.BLOCK,
                    confidence=0.95,
                    message=f"Dangerous command: {desc}",
                    risk_attribution=RiskAttribution(
                        risk_source="command_injection",
                        failure_mode="unauthorized_action",
                        real_world_harm="system_compromise",
                        confidence=0.95,
                        reasoning=f"Command matches critical deny pattern: {desc}",
                    ),
                )

        # Check high patterns — WARN (let observe/enforce mode decide)
        for pattern, desc in _HIGH_PATTERNS:
            if re.search(pattern, command, re.IGNORECASE):
                return GuardResult(
                    guard_name="command",
                    verdict=GuardVerdict.WARN,
                    confidence=0.8,
                    message=f"Potentially dangerous command: {desc}",
                    risk_attribution=RiskAttribution(
                        risk_source="command_injection",
                        failure_mode="unauthorized_action",
                        real_world_harm="system_compromise",
                        confidence=0.8,
                        reasoning=f"Command matches high-risk pattern: {desc}",
                    ),
                )

        # Check medium patterns — WARN at lower confidence
        for pattern, desc in _MEDIUM_PATTERNS:
            if re.search(pattern, command, re.IGNORECASE):
                return GuardResult(
                    guard_name="command",
                    verdict=GuardVerdict.WARN,
                    confidence=0.6,
                    message=f"Command requires review: {desc}",
                )

        return GuardResult(guard_name="command", verdict=GuardVerdict.PASS)

    def _extract_command(self, context: GuardContext) -> str:
        """Extract command string from tool_args."""
        args = context.tool_args
        # Common key names for command arguments
        for key in ("command", "cmd", "script", "shell_command", "exec"):
            if key in args and isinstance(args[key], str):
                return args[key]
        # Fallback: concatenate all string values
        parts: list[str] = []
        for v in args.values():
            if isinstance(v, str):
                parts.append(v)
        return " ".join(parts)


# ---------------------------------------------------------------------------
# CommandGuard
# ---------------------------------------------------------------------------


class CommandGuard(AIGuardBase):
    """Rules-first guard detecting shell command injection.

    SLM template available for semantic variant detection
    (e.g., obfuscated commands that bypass regex).
    """

    name = "command"
    primary_strategy = "rules"

    slm_prompt_template = """Analyze this shell command for semantic variants of known dangerous patterns:

Command: {tool_args}

Does this command:
1. Pipe command output to shell execution
2. Download and execute remote code
3. Escalate privileges
4. Modify system files
5. Use obfuscation techniques (encoding, escaping, variable expansion)

Return JSON: {{"verdict": "safe"|"suspicious"|"malicious", "confidence": 0.0-1.0, "risk_source": "command_injection", "reasoning": "..."}}"""

    llm_prompt_template = None  # Not needed — rule + SLM sufficient

    def __init__(self) -> None:
        self.rule_fallback = CommandGuardRuleChecker()
