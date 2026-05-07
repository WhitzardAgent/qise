"""JSONL security event store and schema for product CLI commands."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from qise.product.service import ensure_qise_home, events_path, now_iso

SCHEMA_VERSION = "0.1"

_PRODUCT_RISK_CATEGORIES = {
    "audit": "Suspicious Behavior Chain",
    "command": "Dangerous Commands",
    "command_injection": "Dangerous Commands",
    "dangerous_command": "Dangerous Commands",
    "credential": "Secret Leakage",
    "credential_exfil": "Secret Leakage",
    "secret_leakage": "Secret Leakage",
    "filesystem": "Sensitive Files",
    "sensitive_files": "Sensitive Files",
    "network": "Unsafe Network",
    "unsafe_network": "Unsafe Network",
    "prompt": "Prompt Injection",
    "prompt_injection": "Prompt Injection",
    "tool_sanity": "Tool Poisoning",
    "tool_poisoning": "Tool Poisoning",
    "supply_chain": "Skill Supply Chain",
    "skill_supply_chain": "Skill Supply Chain",
    "exfil": "Data Exfiltration",
    "data_exfiltration": "Data Exfiltration",
    "resource": "Resource Abuse",
    "resource_abuse": "Resource Abuse",
    "output": "Secret Leakage",
    "tool_policy": "Policy Violation",
    "agent_config": "Agent Configuration",
}


class EventAgent(BaseModel):
    name: str = ""
    type: str = ""
    session_id: str = ""


class EventAction(BaseModel):
    type: str = ""
    name: str = ""
    resource: str = ""


class EventRisk(BaseModel):
    category: str
    severity: str = "medium"
    confidence: float = 0.0


class EventDecision(BaseModel):
    verdict: str
    mode: str = "enforce"
    blocked_by: list[str] = Field(default_factory=list)


class EventEvidence(BaseModel):
    type: str = "rule"
    rule_id: str = ""
    message: str = ""
    path: str = ""
    snippet: str = ""
    guard: str = ""
    verdict: str = ""
    risk_source: str = ""
    confidence: float | None = None


class SecurityEvent(BaseModel):
    id: str = Field(default_factory=lambda: f"evt_{uuid.uuid4().hex[:16]}")
    schema_version: str = SCHEMA_VERSION
    timestamp: str = Field(default_factory=now_iso)
    stage: str
    source: str
    agent: EventAgent = Field(default_factory=EventAgent)
    action: EventAction
    risk: EventRisk
    decision: EventDecision
    evidence: list[EventEvidence] = Field(default_factory=list)
    recommendation: str = ""
    correlation_id: str = Field(default_factory=lambda: f"corr_{uuid.uuid4().hex[:12]}")
    raw_ref: str = ""


def product_risk_category(category: str) -> str:
    normalized = category.strip().lower().replace(" ", "_").replace("-", "_")
    return _PRODUCT_RISK_CATEGORIES.get(normalized, category.replace("_", " ").title() if category else "Unknown")


def _parse_timestamp(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return None


def parse_since(value: str | None) -> datetime | None:
    if not value:
        return None
    raw = value.strip().lower()
    try:
        amount = int(raw[:-1])
    except Exception:
        return _parse_timestamp(value)
    unit = raw[-1]
    if unit == "m":
        delta = timedelta(minutes=amount)
    elif unit == "h":
        delta = timedelta(hours=amount)
    elif unit == "d":
        delta = timedelta(days=amount)
    else:
        return _parse_timestamp(value)
    return datetime.now(UTC) - delta


def _safe_snippet(value: Any, *, max_len: int = 240) -> str:
    if value is None:
        return ""
    try:
        raw = value if isinstance(value, str) else json.dumps(value, sort_keys=True, default=str)
    except Exception:
        raw = str(value)
    raw = " ".join(raw.split())
    if len(raw) <= max_len:
        return raw
    return raw[: max_len - 3] + "..."


def make_event(
    *,
    stage: str,
    source: str,
    verdict: str,
    category: str,
    severity: str,
    confidence: float,
    action_type: str,
    action_name: str = "",
    resource: Any = "",
    agent_name: str = "",
    session_id: str = "",
    evidence: list[dict[str, Any]] | None = None,
    recommendation: str = "",
    mode: str = "enforce",
    blocked_by: list[str] | None = None,
    raw_ref: str = "",
) -> dict[str, Any]:
    category_label = product_risk_category(category)
    blocked = blocked_by if blocked_by is not None else ([category] if verdict == "block" else [])
    event = SecurityEvent(
        stage=stage,
        source=source,
        agent=EventAgent(name=agent_name, type=agent_name, session_id=session_id),
        action=EventAction(type=action_type, name=action_name, resource=_safe_snippet(resource)),
        risk=EventRisk(category=category_label, severity=severity, confidence=confidence),
        decision=EventDecision(verdict=verdict, mode=mode, blocked_by=blocked),
        evidence=[EventEvidence(**item) for item in evidence or []],
        recommendation=recommendation,
        raw_ref=raw_ref,
    )
    return event.model_dump(mode="json")


def _category_from_results(results: list[Any], fallback: str) -> str:
    for result in results:
        if not isinstance(result, dict):
            continue
        verdict = str(result.get("verdict", "")).lower()
        if verdict in {"block", "warn"}:
            risk_source = result.get("risk_source")
            if risk_source:
                return str(risk_source)
            guard = result.get("guard")
            if guard:
                return str(guard)
    return fallback


def _confidence_from_results(results: list[Any], fallback: float) -> float:
    confidences: list[float] = []
    for result in results:
        if not isinstance(result, dict):
            continue
        try:
            confidence = float(result.get("confidence"))
        except (TypeError, ValueError):
            continue
        if 0.0 <= confidence <= 1.0:
            confidences.append(confidence)
    return max(confidences) if confidences else fallback


def guard_event_from_results(
    *,
    stage: str,
    source: str,
    verdict: str,
    action_type: str,
    action_name: str = "",
    resource: Any = "",
    agent_name: str = "",
    session_id: str = "",
    blocked_by: str | None = None,
    warnings: list[str] | None = None,
    guard_results: list[dict[str, Any]] | None = None,
    recommendation: str = "",
) -> dict[str, Any]:
    """Build a product event from guard pipeline output.

    The event intentionally stores compact snippets, not full request/response
    bodies, so the local evidence trail remains useful without becoming a
    second copy of a user's private agent traffic.
    """
    results = guard_results or []
    normalized_verdict = "block" if verdict == "block" else "warn"
    category = blocked_by or _category_from_results(results, "guard")
    evidence: list[dict[str, Any]] = []
    for result in results:
        if not isinstance(result, dict):
            continue
        if str(result.get("verdict", "pass")).lower() == "pass":
            continue
        evidence.append({
            "type": "guard_result",
            "guard": str(result.get("guard", "")),
            "verdict": str(result.get("verdict", "")),
            "message": _safe_snippet(result.get("message", "")),
            "risk_source": str(result.get("risk_source", "")),
            "confidence": result.get("confidence"),
        })
    for warning in warnings or []:
        evidence.append({
            "type": "runtime",
            "message": _safe_snippet(warning),
        })
    resource_snippet = _safe_snippet(resource)
    if resource_snippet:
        evidence.append({
            "type": "runtime",
            "message": "Action/resource snippet captured by Qise.",
            "snippet": resource_snippet,
        })
    if not recommendation:
        recommendation = (
            "Qise blocked this action. Review the evidence before retrying or relaxing guard mode."
            if normalized_verdict == "block"
            else "Qise observed suspicious behavior. Review the evidence before continuing."
        )
    return make_event(
        stage=stage,
        source=source,
        verdict=normalized_verdict,
        category=category,
        severity="high" if normalized_verdict == "block" else "medium",
        confidence=_confidence_from_results(results, 1.0 if normalized_verdict == "block" else 0.6),
        action_type=action_type,
        action_name=action_name,
        resource=resource_snippet,
        agent_name=agent_name,
        session_id=session_id,
        evidence=evidence,
        recommendation=recommendation,
        blocked_by=[blocked_by] if normalized_verdict == "block" and blocked_by else None,
    )


def record_guard_event(**kwargs: Any) -> Path:
    """Append a WARN/BLOCK guard event to the local JSONL event store."""
    event = guard_event_from_results(**kwargs)
    return append_event(event)


def append_event(event: dict[str, Any]) -> Path:
    ensure_qise_home()
    normalized = SecurityEvent.model_validate(event).model_dump(mode="json")
    path = events_path()
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(normalized, sort_keys=True) + "\n")
    return path


def load_events(*, limit: int = 50, since: str | None = None) -> list[dict[str, Any]]:
    path = events_path()
    if not path.exists():
        return []

    since_dt = parse_since(since)
    events: list[dict[str, Any]] = []
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        try:
            event = SecurityEvent.model_validate(json.loads(line)).model_dump(mode="json")
        except Exception:
            continue
        if since_dt is not None:
            ts = _parse_timestamp(str(event.get("timestamp", "")))
            if ts is None or ts < since_dt:
                continue
        events.append(event)
    if limit > 0:
        events = events[-limit:]
    return events


def count_recent_events(hours: int = 24) -> tuple[int, int]:
    events = load_events(limit=0, since=f"{hours}h")
    blocks = 0
    warnings = 0
    for event in events:
        verdict = event.get("decision", {}).get("verdict")
        if verdict == "block":
            blocks += 1
        elif verdict == "warn":
            warnings += 1
    return blocks, warnings


def format_events(events: list[dict[str, Any]]) -> str:
    if not events:
        return "No security events yet."

    lines = []
    for event in events:
        risk = event.get("risk", {})
        decision = event.get("decision", {})
        action = event.get("action", {})
        evidence = event.get("evidence", [])
        action_label = action.get("name") or action.get("resource") or "-"
        lines.append(
            f"{event.get('timestamp', '')} {decision.get('verdict', 'unknown').upper():<5} "
            f"{risk.get('category', 'Unknown')} / {risk.get('severity', 'medium')} "
            f"[{event.get('source', '')}:{event.get('stage', '')}] "
            f"{action.get('type', '')}:{action_label} "
            f"id={event.get('id', '')}"
        )
        if evidence:
            first = evidence[0]
            message = first.get("message") or first.get("snippet")
            if message:
                lines.append(f"  Evidence: {message}")
        recommendation = event.get("recommendation")
        if recommendation:
            lines.append(f"  Recommendation: {recommendation}")
    return "\n".join(lines)
