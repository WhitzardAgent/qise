"""FilesystemGuard — pure rules guard detecting path traversal and workspace violations.

Enforces workspace boundaries, blocks system directory writes,
and detects path traversal attempts.
"""

from __future__ import annotations

import os
import re

from qise.core.guard_base import AIGuardBase, RuleChecker
from qise.core.models import GuardContext, GuardResult, GuardVerdict, RiskAttribution

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_PATH_KEYS = frozenset({
    "path", "filepath", "file_path", "dir", "directory",
    "dest", "destination", "target", "filename", "output_path",
})

_OPERATION_KEYS = frozenset({"mode", "operation", "action"})

_DENY_PATHS = (
    "/etc", "/usr", "/bin", "/sbin", "/var", "/dev",
    "/proc", "/sys", "/boot", "/root",
)

_DEVICE_FILES = (
    "/dev/null", "/dev/urandom", "/dev/zero", "/dev/random",
    "/dev/full", "/dev/tty",
)

_DANGEROUS_OPS = frozenset({"delete", "remove", "truncate", "overwrite"})

_TRAVERSAL_PATTERN = re.compile(r"\.\.(/|\\)")


# ---------------------------------------------------------------------------
# RuleChecker
# ---------------------------------------------------------------------------


class FilesystemGuardRuleChecker(RuleChecker):
    """Deterministic filesystem safety checks."""

    def check(self, context: GuardContext) -> GuardResult:
        paths = self._extract_paths(context)
        operation = self._extract_operation(context)

        for path in paths:
            result = self._check_path(path, context, operation)
            if result is not None:
                return result

        return GuardResult(guard_name="filesystem", verdict=GuardVerdict.PASS)

    def _check_path(
        self, raw_path: str, context: GuardContext, operation: str | None
    ) -> GuardResult | None:
        normalized = os.path.normpath(raw_path)

        # 1. Device file blacklist
        for dev in _DEVICE_FILES:
            if normalized.startswith(dev):
                return GuardResult(
                    guard_name="filesystem",
                    verdict=GuardVerdict.BLOCK,
                    confidence=0.9,
                    message=f"Device file access blocked: {raw_path}",
                    risk_attribution=RiskAttribution(
                        risk_source="filesystem_violation",
                        failure_mode="unauthorized_action",
                        real_world_harm="system_compromise",
                        confidence=0.9,
                        reasoning=f"Access to device file: {raw_path}",
                    ),
                )

        # 2. System directory protection
        for deny in _DENY_PATHS:
            if normalized == deny or normalized.startswith(deny + "/"):
                return GuardResult(
                    guard_name="filesystem",
                    verdict=GuardVerdict.BLOCK,
                    confidence=0.95,
                    message=f"System directory access blocked: {raw_path}",
                    risk_attribution=RiskAttribution(
                        risk_source="filesystem_violation",
                        failure_mode="unauthorized_action",
                        real_world_harm="system_compromise",
                        confidence=0.95,
                        reasoning=f"Path targets protected directory: {deny}",
                    ),
                )

        # 3. Path traversal detection
        if _TRAVERSAL_PATTERN.search(raw_path):
            return GuardResult(
                guard_name="filesystem",
                verdict=GuardVerdict.BLOCK,
                confidence=0.9,
                message=f"Path traversal detected: {raw_path}",
                risk_attribution=RiskAttribution(
                    risk_source="filesystem_violation",
                    failure_mode="unauthorized_action",
                    real_world_harm="system_compromise",
                    confidence=0.9,
                    reasoning="Path contains directory traversal sequence (../)",
                ),
            )

        # 4. Workspace boundary enforcement
        if context.workspace_path:
            workspace_abs = os.path.abspath(context.workspace_path)
            path_abs = os.path.abspath(
                os.path.join(context.workspace_path, raw_path)
                if not os.path.isabs(raw_path)
                else raw_path
            )
            if not path_abs.startswith(workspace_abs + os.sep) and path_abs != workspace_abs:
                return GuardResult(
                    guard_name="filesystem",
                    verdict=GuardVerdict.BLOCK,
                    confidence=0.85,
                    message=f"Workspace boundary violation: {raw_path}",
                    risk_attribution=RiskAttribution(
                        risk_source="filesystem_violation",
                        failure_mode="unauthorized_action",
                        real_world_harm="data_corruption",
                        confidence=0.85,
                        reasoning=f"Path resolves outside workspace: {context.workspace_path}",
                    ),
                )

        # 5. Dangerous operation on system-adjacent path
        if operation and operation.lower() in _DANGEROUS_OPS:
            for deny in _DENY_PATHS:
                if normalized.startswith(deny):
                    return GuardResult(
                        guard_name="filesystem",
                        verdict=GuardVerdict.BLOCK,
                        confidence=0.95,
                        message=f"Dangerous operation '{operation}' on protected path: {raw_path}",
                        risk_attribution=RiskAttribution(
                            risk_source="filesystem_violation",
                            failure_mode="unauthorized_action",
                            real_world_harm="system_compromise",
                            confidence=0.95,
                            reasoning=f"Operation '{operation}' on path under {deny}",
                        ),
                    )

        return None

    def _extract_paths(self, context: GuardContext) -> list[str]:
        """Extract file paths from tool_args."""
        paths: list[str] = []
        for key in _PATH_KEYS:
            val = context.tool_args.get(key)
            if isinstance(val, str) and val:
                paths.append(val)
        if not paths:
            # Fallback: scan all string values for path-like content
            for val in context.tool_args.values():
                if isinstance(val, str) and ("/" in val or "\\" in val):
                    paths.append(val)
        return paths

    def _extract_operation(self, context: GuardContext) -> str | None:
        """Extract operation type from tool_args."""
        for key in _OPERATION_KEYS:
            val = context.tool_args.get(key)
            if isinstance(val, str):
                return val.lower()
        return None


# ---------------------------------------------------------------------------
# FilesystemGuard
# ---------------------------------------------------------------------------


class FilesystemGuard(AIGuardBase):
    """Pure rules guard detecting path traversal and workspace violations.

    No SLM/LLM needed — path rules are deterministic.
    """

    name = "filesystem"
    primary_strategy = "rules"
    slm_prompt_template = ""
    llm_prompt_template = None

    def __init__(self) -> None:
        self.rule_fallback = FilesystemGuardRuleChecker()
