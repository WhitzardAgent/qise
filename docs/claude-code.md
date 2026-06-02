# Claude Code Integration

Qise supports Claude Code through the Anthropic Messages API path:

```text
Claude Code -> http://127.0.0.1:8822/agent/claude-code/v1/messages -> Anthropic upstream
```

## What Qise Protects

- Parses Anthropic `/v1/messages` requests, including top-level `system`, `messages`, `tools`, `tool_result`, and `tool_use` content blocks.
- Injects Qise security context into the Anthropic top-level `system` field.
- Checks user content, tool results, and tool descriptions before forwarding to Anthropic.
- Checks non-streaming Anthropic responses for text output and `tool_use` calls.
- Checks streaming Anthropic `tool_use` blocks by buffering the tool input JSON until the block is complete, then releasing or blocking the block.

## Setup

Make sure Claude Code works before adding Qise, then keep your Anthropic key available:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
qise protect claude-code --base-url https://api.anthropic.com
qise status
```

If your Claude Code setup uses `apiKeyHelper`, you can keep it. Qise patches `~/.claude/settings.json` to set `env.ANTHROPIC_BASE_URL` to the local proxy and stores a restorable backup under `~/.qise/backups/claude-code/...`.

## Restore

```bash
qise restore claude-code
qise stop
```

`qise restore claude-code` restores the backed-up Claude Code settings file. `qise stop` stops the Qise-managed proxy and bridge services.

## Notes

- Use `https://api.anthropic.com` as the upstream base URL for the native Anthropic API.
- Qise forwards `ANTHROPIC_API_KEY` as `X-Api-Key` and `ANTHROPIC_AUTH_TOKEN` as `Authorization: Bearer ...` for Anthropic Messages traffic.
- Qise preserves Anthropic headers such as `anthropic-version` and `anthropic-beta`, and adds `anthropic-version: 2023-06-01` when a native Anthropic request does not include one.
