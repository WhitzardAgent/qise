# Qise MVP Release Checklist

Use this checklist before tagging or publicly promoting a release. It keeps the first-week MVP honest: installable, protectable, explainable, restorable.

## 1. Fresh Install Smoke Test

```bash
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e ".[proxy]"
qise doctor
qise status
```

Pass criteria:

- `qise doctor` returns `ready` or `ready_with_warnings` with no errors.
- `qise status` shows Services, SLM, Protection, Agents, and Events sections.

## 2. Rule-Only Safety Loop

```bash
qise scan skill examples/skills/safe
qise scan skill examples/skills/dangerous || true
qise scan mcp examples/mcp-dangerous.json || true
qise check bash '{"command":"rm -rf /"}' || true
qise events --limit 10
```

Pass criteria:

- Safe fixture passes.
- Dangerous Skill/MCP and dangerous command produce BLOCK/WARN events with evidence.
- Qise still works without SLM configured.

## 3. Optional Local SLM Loop

```bash
qise slm start
qise slm status
qise doctor
```

Pass criteria:

- `qise slm status` shows configured `yes`, provider `Ollama`, and verification `ready`.
- If the model is not ready, the error is understandable and `qise slm stop` returns Qise to rule-only mode.

## 4. Agent Protect/Restore Loop

Run at least one real Agent path before promotion.

```bash
qise protect codex
qise status
qise scan agent-config codex
qise restore codex
qise stop
```

For OpenClaw:

```bash
qise protect openclaw
qise status
qise scan agent-config openclaw
qise restore openclaw
qise stop
```

Pass criteria:

- Config backup is created under `~/.qise/backups/...`.
- Agent config points to `http://127.0.0.1:8822/agent/<agent>/v1` while protected.
- Restore returns the original config exactly.

## 5. Proxy Runtime Loop

```bash
qise protect <agent>
# Start and use the protected Agent normally.
qise events --limit 20
qise status
```

Pass criteria:

- Requests flow through Qise proxy.
- Dangerous tool calls are blocked or warned according to guard mode.
- Events include source, stage, decision, evidence, recommendation, and event id.

## 6. GitHub Hygiene

```bash
git status --short
pytest tests/test_product_cli.py tests/test_ollama_compat.py tests/test_model_router_real.py
ruff check src/qise tests
```

Pass criteria:

- No secrets, local `shield.yaml`, event logs, model caches, or internal planning docs are staged.
- Public docs describe Claude Code native Anthropic `/v1/messages` support only when parser, proxy, streaming, protect, restore, and event evidence tests pass.
- README quickstart, SLM commands, OpenClaw/Codex/Claude Code docs, and release notes are consistent.
