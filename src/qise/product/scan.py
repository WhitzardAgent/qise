"""Preflight scanners for MCP configs, Agent skills, and Agent configs."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from qise.product.events import append_event, make_event, product_risk_category

_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}

_DANGEROUS_COMMANDS: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"\bcurl\b[^\n|;]*\|\s*(ba)?sh\b", re.IGNORECASE), "supply_chain.remote_exec", "curl pipe to shell"),
    (re.compile(r"\bwget\b[^\n|;]*\|\s*(ba)?sh\b", re.IGNORECASE), "supply_chain.remote_exec", "wget pipe to shell"),
    (re.compile(r"\brm\s+-rf\s+/", re.IGNORECASE), "command.rm_rf_root", "recursive delete from root"),
    (re.compile(r"\bchmod\s+777\b", re.IGNORECASE), "command.chmod_777", "world-writable permissions"),
    (
        re.compile(r"\b(?:bash|sh)\s+-c\s+['\"]?.*(?:curl|wget)", re.IGNORECASE),
        "supply_chain.remote_exec",
        "shell executes remote downloader",
    ),
]
_INJECTION_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    (
        re.compile(r"ignore (all )?(previous|prior) instructions", re.IGNORECASE),
        "tool_poisoning.ignore_previous",
        "instruction override",
    ),
    (
        re.compile(r"you are now (?:in )?(developer|system|admin) mode", re.IGNORECASE),
        "tool_poisoning.role_hijack",
        "role hijack instruction",
    ),
    (
        re.compile(r"send .* to https?://", re.IGNORECASE),
        "tool_poisoning.exfil_instruction",
        "possible exfiltration instruction",
    ),
    (re.compile(r"exfiltrat(e|ion)", re.IGNORECASE), "tool_poisoning.exfil_language", "exfiltration language"),
]
_SECRET_HARVESTING = [
    (
        re.compile(r"\b(?:process\.env|os\.environ|getenv)\b", re.IGNORECASE),
        "secret.env_access",
        "reads environment variables",
    ),
    (
        re.compile(r"\b(?:OPENAI|ANTHROPIC|AWS|GITHUB|GOOGLE|AZURE)_[A-Z0-9_]*(?:KEY|TOKEN|SECRET)\b"),
        "secret.named_key",
        "mentions named secret",
    ),
]
_SENSITIVE_ENV = ("API_KEY", "SECRET", "TOKEN", "PASSWORD", "PRIVATE_KEY", "ACCESS_KEY")
_SENSITIVE_FILES = ("/etc/passwd", "/etc/shadow", ".ssh/id_rsa", ".ssh/id_ed25519", ".env")
_OBFUSCATION_PATTERNS = [
    (re.compile(r"(?:[A-Za-z0-9+/]{80,}={0,2})"), "obfuscation.base64", "long base64-like blob"),
    (re.compile(r"(?:0x)?[0-9a-fA-F]{96,}"), "obfuscation.hex", "long hex-like blob"),
]
_SUSPICIOUS_DOMAINS = re.compile(
    r'https?://(?:[^\s/]+\.)?(?:evil|pastebin|ngrok|webhook|requestbin)\.[^\s)\]\'"]+',
    re.IGNORECASE,
)
_INTEGRITY_ALGORITHM_RE = re.compile(r"\bsha(?:256|384|512)-$", re.IGNORECASE)


@dataclass
class Finding:
    verdict: str
    category: str
    severity: str
    confidence: float
    message: str
    path: str = ""
    snippet: str = ""
    rule_id: str = ""
    evidence_type: str = "rule"


@dataclass
class ScanReport:
    target: str
    target_type: str
    verdict: str
    findings: list[Finding]
    recommendation: str


def _load_structured_file(path: Path) -> Any:
    text = path.read_text()
    if path.suffix.lower() in {".yaml", ".yml"}:
        return yaml.safe_load(text) or {}
    return json.loads(text)


def _iter_values(value: Any, prefix: str = ""):
    if isinstance(value, dict):
        for key, child in value.items():
            child_prefix = f"{prefix}.{key}" if prefix else str(key)
            yield child_prefix, key, child
            yield from _iter_values(child, child_prefix)
    elif isinstance(value, list):
        for idx, child in enumerate(value):
            child_prefix = f"{prefix}[{idx}]"
            yield child_prefix, str(idx), child
            yield from _iter_values(child, child_prefix)


def _snippet(text: str, start: int, end: int, *, window: int = 80) -> str:
    lo = max(0, start - window)
    hi = min(len(text), end + window)
    return " ".join(text[lo:hi].split())


def _looks_like_integrity_hash(text: str, start: int, end: int, *, path: str) -> bool:
    """True for package-manager integrity hashes such as integrity: sha512-..."""
    lower_path = path.lower()
    if any(name in lower_path for name in ("package-lock", "pnpm-lock", "yarn.lock")):
        return True

    prefix = text[max(0, start - 12):start]
    if _INTEGRITY_ALGORITHM_RE.search(prefix):
        return True

    window = text[max(0, start - 80): min(len(text), end + 24)].lower()
    return "integrity" in window and re.search(r"sha(?:256|384|512)-", window) is not None


def _finding(
    *,
    verdict: str,
    category: str,
    severity: str,
    confidence: float,
    message: str,
    path: str,
    snippet: str,
    rule_id: str,
    evidence_type: str = "rule",
) -> Finding:
    return Finding(verdict, category, severity, confidence, message, path, snippet, rule_id, evidence_type)


def _scan_text(text: str, *, path: str, target_type: str = "skill") -> list[Finding]:
    findings: list[Finding] = []
    lower_path = path.lower()
    install_context = any(token in lower_path for token in ("install", "postinstall", "setup", "package.json"))

    for pattern, rule_id, desc in _DANGEROUS_COMMANDS:
        match = pattern.search(text)
        if match:
            findings.append(_finding(
                verdict="block",
                category="skill_supply_chain" if target_type != "agent_config" else "agent_config",
                severity="critical" if "rm_rf" in rule_id else "high",
                confidence=0.92 if install_context else 0.88,
                message=f"Dangerous command: {desc}",
                path=path,
                snippet=_snippet(text, match.start(), match.end()),
                rule_id=rule_id,
            ))
    for pattern, rule_id, desc in _INJECTION_PATTERNS:
        match = pattern.search(text)
        if match:
            findings.append(_finding(
                verdict="warn",
                category="tool_poisoning",
                severity="medium",
                confidence=0.76,
                message=f"Suspicious instruction: {desc}",
                path=path,
                snippet=_snippet(text, match.start(), match.end()),
                rule_id=rule_id,
            ))
    for sensitive in _SENSITIVE_FILES:
        idx = text.find(sensitive)
        if idx >= 0:
            findings.append(_finding(
                verdict="warn",
                category="sensitive_files",
                severity="medium",
                confidence=0.72,
                message=f"References sensitive path: {sensitive}",
                path=path,
                snippet=_snippet(text, idx, idx + len(sensitive)),
                rule_id="file.sensitive_path",
            ))
    if target_type != "agent_config":
        for pattern, rule_id, desc in _SECRET_HARVESTING:
            match = pattern.search(text)
            if match:
                findings.append(_finding(
                    verdict="warn",
                    category="secret_leakage",
                    severity="medium",
                    confidence=0.7,
                    message=f"Possible secret harvesting: {desc}",
                    path=path,
                    snippet=_snippet(text, match.start(), match.end()),
                    rule_id=rule_id,
                ))
    domain = _SUSPICIOUS_DOMAINS.search(text)
    if domain:
        findings.append(_finding(
            verdict="warn",
            category="unsafe_network",
            severity="medium",
            confidence=0.68,
            message="Suspicious external callback or paste/webhook domain",
            path=path,
            snippet=_snippet(text, domain.start(), domain.end()),
            rule_id="network.suspicious_domain",
        ))
    for pattern, rule_id, desc in _OBFUSCATION_PATTERNS:
        for match in pattern.finditer(text):
            if rule_id == "obfuscation.base64" and _looks_like_integrity_hash(
                text, match.start(), match.end(), path=path
            ):
                continue
            findings.append(_finding(
                verdict="warn",
                category="skill_supply_chain",
                severity="medium",
                confidence=0.65,
                message=f"Possible obfuscation: {desc}",
                path=path,
                snippet=_snippet(text, match.start(), match.end(), window=16),
                rule_id=rule_id,
            ))
            break
    return findings


def _scan_shell_joining(value: str, *, path: str) -> list[Finding]:
    findings: list[Finding] = []
    if re.search(r"(?:&&|;|\|)", value):
        findings.append(_finding(
            verdict="warn",
            category="skill_supply_chain",
            severity="medium",
            confidence=0.66,
            message="MCP argument contains shell command chaining",
            path=path,
            snippet=value,
            rule_id="mcp.shell_chaining",
        ))
    return findings


def scan_mcp(path: Path) -> ScanReport:
    if not path.exists():
        raise FileNotFoundError(path)
    data = _load_structured_file(path)
    findings: list[Finding] = []

    for item_path, key, value in _iter_values(data):
        if isinstance(value, str):
            findings.extend(_scan_text(value, path=item_path, target_type="mcp_config"))
            if key.lower() in {"command", "args", "0", "1", "2", "3", "4"}:
                findings.extend(_scan_shell_joining(value, path=item_path))
        if key.lower() == "env" and isinstance(value, dict):
            for env_key in value:
                env_upper = str(env_key).upper()
                if any(token in env_upper for token in _SENSITIVE_ENV):
                    findings.append(_finding(
                        verdict="warn",
                        category="secret_leakage",
                        severity="medium",
                        confidence=0.72,
                        message=f"Sensitive environment variable exposed to MCP server: {env_key}",
                        path=f"{item_path}.{env_key}",
                        snippet=str(env_key),
                        rule_id="mcp.sensitive_env",
                    ))

    return _finalize_report(path, "mcp_config", findings)


def scan_skill(path: Path) -> ScanReport:
    if not path.exists():
        raise FileNotFoundError(path)

    findings: list[Finding] = []
    files = [path] if path.is_file() else [
        p for p in path.rglob("*")
        if p.is_file() and "node_modules" not in p.parts and ".git" not in p.parts
    ]
    for file_path in files:
        try:
            if file_path.stat().st_size > 512_000:
                continue
            text = file_path.read_text(errors="ignore")
        except Exception:
            continue
        rel = str(file_path.relative_to(path)) if path.is_dir() else str(file_path)
        findings.extend(_scan_text(text, path=rel, target_type="skill"))

    return _finalize_report(path, "skill", findings)


def scan_agent_config(agent: str) -> ScanReport:
    from qise.product.agents import AGENTS, AgentConfigManager, normalize_agent_key
    from qise.product.service import load_state

    key = normalize_agent_key(agent)
    spec = AGENTS.get(key)
    if spec is None:
        return _finalize_report(Path(agent), "agent_config", [
            _finding(
                verdict="block",
                category="agent_config",
                severity="high",
                confidence=1.0,
                message=f"Unknown agent: {agent}",
                path=agent,
                snippet=agent,
                rule_id="agent_config.unknown_agent",
            )
        ])

    manager = AgentConfigManager(spec)
    config_path = manager.locate_config(create=False)
    findings: list[Finding] = []
    state = load_state()
    protected = state.get("protected_agents", {})
    record = protected.get(key, {}) if isinstance(protected, dict) else {}

    if config_path is None:
        findings.append(_finding(
            verdict="warn",
            category="agent_config",
            severity="medium",
            confidence=0.8,
            message=f"{spec.display_name} config file was not found.",
            path=agent,
            snippet="",
            rule_id="agent_config.not_found",
        ))
        return _finalize_report(Path(agent), "agent_config", findings)

    text = config_path.read_text(errors="ignore")
    proxy_url = str(record.get("proxy_url") or manager.proxy_url)
    has_proxy = proxy_url in text or "127.0.0.1:8822" in text or "localhost:8822" in text

    if record and not has_proxy:
        findings.append(_finding(
            verdict="block",
            category="agent_config",
            severity="high",
            confidence=0.92,
            message="Qise state says this Agent is protected, but the config does not point to Qise proxy.",
            path=str(config_path),
            snippet=proxy_url,
            rule_id="agent_config.state_config_mismatch",
        ))
    elif not has_proxy:
        findings.append(_finding(
            verdict="warn",
            category="agent_config",
            severity="medium",
            confidence=0.75,
            message="Agent provider/base URL is not routed through Qise proxy.",
            path=str(config_path),
            snippet="base_url/provider not pointing to 127.0.0.1:8822",
            rule_id="agent_config.not_proxied",
        ))

    backup_path = str(record.get("backup_path") or "")
    if record and (not backup_path or not Path(backup_path).exists()):
        findings.append(_finding(
            verdict="warn",
            category="agent_config",
            severity="medium",
            confidence=0.8,
            message="Protected Agent has no readable Qise backup path recorded.",
            path=str(config_path),
            snippet=backup_path,
            rule_id="agent_config.missing_backup",
        ))
    if "# >>> qise protect" in text and not record:
        findings.append(_finding(
            verdict="warn",
            category="agent_config",
            severity="medium",
            confidence=0.76,
            message="Qise patch marker exists but no active protection state was recorded.",
            path=str(config_path),
            snippet="# >>> qise protect",
            rule_id="agent_config.untracked_patch",
        ))

    findings.extend(_scan_text(text, path=str(config_path), target_type="agent_config"))
    return _finalize_report(config_path, "agent_config", findings)


def _worst_finding(findings: list[Finding]) -> Finding | None:
    if not findings:
        return None
    return max(findings, key=lambda f: (_SEVERITY_RANK.get(f.severity, 0), f.confidence))


def _finalize_report(path: Path, target_type: str, findings: list[Finding]) -> ScanReport:
    verdict = "pass"
    if any(f.verdict == "block" for f in findings):
        verdict = "block"
    elif any(f.verdict == "warn" for f in findings):
        verdict = "warn"

    worst = _worst_finding(findings)
    if verdict == "pass":
        recommendation = "No obvious preflight risks found."
    elif verdict == "warn":
        recommendation = "Review the findings before enabling this integration."
    elif worst and worst.category == "agent_config":
        recommendation = "Restore or re-run Qise protection so local Agent config and Qise state match."
    else:
        recommendation = "Do not enable this integration until the blocking findings are removed."
    return ScanReport(str(path), target_type, verdict, findings, recommendation)


def record_scan_event(report: ScanReport) -> None:
    worst = _worst_finding(report.findings)
    severity = worst.severity if worst else "low"
    confidence = worst.confidence if worst else 1.0
    category = worst.category if worst else "skill_supply_chain"
    event = make_event(
        stage="preflight",
        source="scan",
        verdict=report.verdict,
        category=category,
        severity=severity,
        confidence=confidence,
        action_type=report.target_type,
        resource=report.target,
        evidence=[
            {
                "type": finding.evidence_type,
                "rule_id": finding.rule_id or finding.category,
                "message": finding.message,
                "path": finding.path,
                "snippet": finding.snippet,
                "confidence": finding.confidence,
            }
            for finding in report.findings
        ],
        recommendation=report.recommendation,
        blocked_by=[worst.rule_id or worst.category] if report.verdict == "block" and worst else None,
        raw_ref=report.target,
    )
    append_event(event)


def report_to_dict(report: ScanReport) -> dict[str, Any]:
    return {
        "target": report.target,
        "target_type": report.target_type,
        "verdict": report.verdict,
        "risk": {
            "category": product_risk_category(_worst_finding(report.findings).category) if report.findings else "None",
            "severity": _worst_finding(report.findings).severity if report.findings else "low",
        },
        "findings": [finding.__dict__ for finding in report.findings],
        "recommendation": report.recommendation,
    }


def render_report(report: ScanReport, *, json_output: bool = False) -> str:
    if json_output:
        return json.dumps(report_to_dict(report), indent=2, sort_keys=True)
    worst = _worst_finding(report.findings)
    risk = product_risk_category(worst.category) if worst else "None"
    severity = worst.severity if worst else "low"
    lines = [
        "Qise Preflight Scan",
        "",
        f"Target: {report.target}",
        f"Type: {report.target_type}",
        f"Verdict: {report.verdict.upper()}",
        f"Risk: {risk} / {severity}",
        "",
        "Evidence",
    ]
    if not report.findings:
        lines.append("  - none")
    for finding in report.findings:
        location = f" ({finding.path})" if finding.path else ""
        lines.append(f"  - [{finding.severity}] {finding.message}{location}")
        if finding.snippet:
            lines.append(f"    snippet: {finding.snippet}")
    lines.extend(["", "Recommendation", f"  {report.recommendation}"])
    return "\n".join(lines)
