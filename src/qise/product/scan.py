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
_SKIP_SCAN_DIRS = {
    ".git",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "build",
    "target",
    "cache",
    "caches",
    "logs",
}
_TEXT_SUFFIXES = {
    "",
    ".bash",
    ".cjs",
    ".conf",
    ".json",
    ".js",
    ".jsx",
    ".md",
    ".mjs",
    ".py",
    ".sh",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".yaml",
    ".yml",
    ".zsh",
}
_STRUCTURED_SUFFIXES = {".json", ".yaml", ".yml"}
_MCP_CONTENT_RE = re.compile(r"\b(?:mcpServers|mcp_servers|mcp-servers)\b", re.IGNORECASE)
_MAX_AUTO_FILES_PER_ROOT = 800


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


@dataclass
class ScanSkip:
    agent: str
    target_type: str
    reason: str


@dataclass
class ScanCollection:
    target: str
    target_type: str
    verdict: str
    reports: list[ScanReport]
    skipped: list[ScanSkip]
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


def _is_skipped_dir(path: Path) -> bool:
    return any(part.lower() in _SKIP_SCAN_DIRS for part in path.parts)


def _iter_scannable_files(path: Path, *, max_files: int = _MAX_AUTO_FILES_PER_ROOT) -> list[Path]:
    if path.is_file():
        return [path]

    files: list[Path] = []
    for candidate in path.rglob("*"):
        if len(files) >= max_files:
            break
        if not candidate.is_file() or _is_skipped_dir(candidate):
            continue
        if candidate.suffix.lower() not in _TEXT_SUFFIXES:
            continue
        try:
            if candidate.stat().st_size > 512_000:
                continue
        except OSError:
            continue
        files.append(candidate)
    return files


def _scan_files(path: Path, *, target_type: str) -> ScanReport:
    if not path.exists():
        raise FileNotFoundError(path)

    findings: list[Finding] = []
    for file_path in _iter_scannable_files(path):
        try:
            text = file_path.read_text(errors="ignore")
        except Exception:
            continue
        rel = str(file_path.relative_to(path)) if path.is_dir() else str(file_path)
        findings.extend(_scan_text(text, path=rel, target_type=target_type))

    return _finalize_report(path, target_type, findings)


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
    return _scan_files(path, target_type="skill")


def scan_agent_files(path: Path) -> ScanReport:
    return _scan_files(path, target_type="agent_files")


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


def _agent_roots(agent_key: str) -> list[Path]:
    from qise.product.agents import AGENTS, AgentConfigManager, _expand_agent_path

    spec = AGENTS.get(agent_key)
    if spec is None:
        return []

    roots: set[Path] = set()
    manager = AgentConfigManager(spec)
    config_path = manager.locate_config(create=False)
    if config_path is not None:
        roots.add(config_path.parent)

    for raw in spec.config_paths:
        candidate = _expand_agent_path(raw).parent
        if candidate.exists():
            roots.add(candidate)

    return sorted(roots)


def _looks_like_mcp_file(path: Path) -> bool:
    if path.suffix.lower() not in _STRUCTURED_SUFFIXES:
        return False
    lower_name = path.name.lower()
    if "mcp" in lower_name:
        return True
    try:
        if path.stat().st_size > 256_000:
            return False
        return _MCP_CONTENT_RE.search(path.read_text(errors="ignore")) is not None
    except OSError:
        return False


def _mcp_candidates(roots: list[Path]) -> list[Path]:
    candidates: set[Path] = set()
    for root in roots:
        for file_path in _iter_scannable_files(root):
            if _looks_like_mcp_file(file_path):
                candidates.add(file_path)
    return sorted(candidates)


def _parse_error_report(path: Path, target_type: str, exc: Exception) -> ScanReport:
    return _finalize_report(path, target_type, [
        _finding(
            verdict="warn",
            category=target_type,
            severity="medium",
            confidence=0.72,
            message=f"Could not parse {target_type}: {exc}",
            path=str(path),
            snippet="",
            rule_id=f"{target_type}.parse_error",
        )
    ])


def _collection_verdict(reports: list[ScanReport]) -> str:
    if any(report.verdict == "block" for report in reports):
        return "block"
    if any(report.verdict == "warn" for report in reports):
        return "warn"
    return "pass"


def _collection_recommendation(reports: list[ScanReport], skipped: list[ScanSkip]) -> str:
    verdict = _collection_verdict(reports)
    if not reports:
        return "No installed Agent assets were found to scan."
    if verdict == "block":
        return "Do not trust the flagged Agent assets until blocking findings are removed."
    if verdict == "warn":
        return "Review warning findings before relying on these Agent assets."
    if skipped:
        return "No obvious risks found in scanned assets; some asset categories were not found."
    return "No obvious preflight risks found across scanned Agent assets."


def scan_agent_assets(
    agent: str,
    *,
    include_skills: bool = True,
    include_mcp: bool = True,
    include_agent_config: bool = True,
) -> ScanCollection:
    from qise.product.agents import AGENTS, normalize_agent_key

    key = normalize_agent_key(agent)
    spec = AGENTS.get(key)
    reports: list[ScanReport] = []
    skipped: list[ScanSkip] = []

    if spec is None:
        reports.append(scan_agent_config(agent))
        return ScanCollection(
            target=key,
            target_type="agent",
            verdict=_collection_verdict(reports),
            reports=reports,
            skipped=skipped,
            recommendation=_collection_recommendation(reports, skipped),
        )

    roots = _agent_roots(key)
    if include_agent_config:
        reports.append(scan_agent_config(key))

    if include_skills:
        if roots:
            for root in roots:
                reports.append(scan_agent_files(root))
        else:
            skipped.append(ScanSkip(agent=key, target_type="agent_files", reason="No Agent config directory was found."))

    if include_mcp:
        candidates = _mcp_candidates(roots)
        if candidates:
            for candidate in candidates:
                try:
                    reports.append(scan_mcp(candidate))
                except Exception as exc:
                    reports.append(_parse_error_report(candidate, "mcp_config", exc))
        else:
            skipped.append(ScanSkip(agent=key, target_type="mcp_config", reason="No MCP config candidates were found."))

    return ScanCollection(
        target=key,
        target_type="agent",
        verdict=_collection_verdict(reports),
        reports=reports,
        skipped=skipped,
        recommendation=_collection_recommendation(reports, skipped),
    )


def scan_all_agent_assets(
    *,
    agents: list[str] | None = None,
    include_missing: bool = False,
    include_skills: bool = True,
    include_mcp: bool = True,
    include_agent_config: bool = True,
) -> ScanCollection:
    from qise.product.agents import detect_agents, normalize_agent_key

    detected = detect_agents(include_missing=include_missing)
    if agents:
        keys = [normalize_agent_key(agent) for agent in agents]
    else:
        keys = [
            str(row["key"])
            for row in detected
            if include_missing or row.get("installed") or row.get("protected")
        ]

    reports: list[ScanReport] = []
    skipped: list[ScanSkip] = []
    for key in keys:
        collection = scan_agent_assets(
            key,
            include_skills=include_skills,
            include_mcp=include_mcp,
            include_agent_config=include_agent_config,
        )
        reports.extend(collection.reports)
        skipped.extend(collection.skipped)

    if not keys:
        skipped.append(ScanSkip(agent="all", target_type="agent", reason="No installed Agents were detected."))

    return ScanCollection(
        target="all",
        target_type="all_agents",
        verdict=_collection_verdict(reports),
        reports=reports,
        skipped=skipped,
        recommendation=_collection_recommendation(reports, skipped),
    )


def iter_scan_reports(report: ScanReport | ScanCollection):
    if isinstance(report, ScanCollection):
        yield from report.reports
    else:
        yield report


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


def collection_to_dict(collection: ScanCollection) -> dict[str, Any]:
    return {
        "target": collection.target,
        "target_type": collection.target_type,
        "verdict": collection.verdict,
        "reports": [report_to_dict(report) for report in collection.reports],
        "skipped": [skip.__dict__ for skip in collection.skipped],
        "recommendation": collection.recommendation,
        "summary": {
            "reports": len(collection.reports),
            "block": sum(1 for report in collection.reports if report.verdict == "block"),
            "warn": sum(1 for report in collection.reports if report.verdict == "warn"),
            "pass": sum(1 for report in collection.reports if report.verdict == "pass"),
            "skipped": len(collection.skipped),
        },
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


def render_collection(collection: ScanCollection, *, json_output: bool = False) -> str:
    if json_output:
        return json.dumps(collection_to_dict(collection), indent=2, sort_keys=True)

    summary = collection_to_dict(collection)["summary"]
    lines = [
        "Qise Preflight Scan",
        "",
        f"Target: {collection.target}",
        f"Type: {collection.target_type}",
        f"Verdict: {collection.verdict.upper()}",
        (
            "Reports: "
            f"{summary['reports']} total, {summary['block']} block, "
            f"{summary['warn']} warn, {summary['pass']} pass, "
            f"{summary['skipped']} skipped"
        ),
        "",
        "Scanned assets",
    ]
    if not collection.reports:
        lines.append("  - none")
    for report in collection.reports:
        worst = _worst_finding(report.findings)
        risk = product_risk_category(worst.category) if worst else "None"
        severity = worst.severity if worst else "low"
        lines.append(
            f"  - [{report.verdict.upper()}] {report.target_type}: {report.target} "
            f"({risk} / {severity}, findings={len(report.findings)})"
        )
        for finding in report.findings[:3]:
            location = f" ({finding.path})" if finding.path else ""
            lines.append(f"      - [{finding.severity}] {finding.message}{location}")
        if len(report.findings) > 3:
            lines.append(f"      - ... {len(report.findings) - 3} more findings")

    if collection.skipped:
        lines.extend(["", "Skipped"])
        for item in collection.skipped:
            lines.append(f"  - {item.agent} {item.target_type}: {item.reason}")

    lines.extend(["", "Recommendation", f"  {collection.recommendation}"])
    return "\n".join(lines)
