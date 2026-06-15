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

## 6. Desktop Release

### One-time repository setup

Keep the updater private key backed up outside the repository. The current local key path is:

```text
~/.tauri/qise-updater.key
```

Add its content to the GitHub repository secret `TAURI_SIGNING_PRIVATE_KEY`. With GitHub CLI:

```bash
gh secret set TAURI_SIGNING_PRIVATE_KEY < ~/.tauri/qise-updater.key
```

The current key has no password, so `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` may remain unset. If the key is replaced with a password-protected key, add that password as the second secret. Never commit or print the private key in logs.

### Prepare and trigger a stable release

All release-bearing files must use the same semantic version. For Qise 0.2.0:

```bash
python scripts/check_release_version.py --expected 0.2.0
PYTHONPATH=src pytest tests/test_release_version.py tests/test_cli.py tests/test_product_cli.py -q
npm test --prefix src-ui
npm run build --prefix src-ui
cargo test --manifest-path src-tauri/Cargo.toml
git status --short
```

Commit and push the release-ready source, then create the matching tag:

```bash
git push origin main
git tag -a v0.2.0 -m "Qise v0.2.0"
git push origin v0.2.0
```

The `Publish Desktop Release` workflow builds Windows x64 and macOS Apple Silicon, signs updater artifacts, generates `latest.json`, and creates a draft GitHub Release.

Before publishing the draft, confirm it contains:

- macOS DMG for first installation.
- macOS updater archive and `.sig`.
- Windows x64 NSIS installer and `.sig`.
- `latest.json` with `darwin-aarch64` and `windows-x86_64`.

Publish the draft as a stable, non-prerelease Release. Publishing also triggers the existing PyPI workflow. Verify the public updater manifest:

```bash
curl -fsSL https://github.com/WhitzardAgent/qise/releases/latest/download/latest.json
```

Users of an earlier 0.2.0 desktop build must manually install this updater-enabled 0.2.0 build once. Test end-to-end automatic updating with the next higher signed version.

## 7. GitHub Hygiene

```bash
git status --short
pytest tests/test_product_cli.py tests/test_ollama_compat.py tests/test_model_router_real.py
ruff check src/qise tests
```

Pass criteria:

- No secrets, local `shield.yaml`, event logs, model caches, or internal planning docs are staged.
- Public docs describe Claude Code native Anthropic `/v1/messages` support only when parser, proxy, streaming, protect, restore, and event evidence tests pass.
- README quickstart, SLM commands, OpenClaw/Codex/Claude Code docs, and release notes are consistent.
