# Claude Code Status

Claude Code support is experimental in the current MVP.

## Current Limitation

The verified Qise proxy path is OpenAI-compatible `/v1/chat/completions` traffic. Claude Code commonly uses Anthropic-native `/v1/messages` traffic, which is not complete in this MVP.

## Command

```bash
qise protect claude-code --experimental
```

Qise requires `--experimental` so users do not mistake this for complete native Claude Code protection.

## Recommendation

Do not market Claude Code as fully supported until Anthropic-native request/response parsing, proxying, event evidence, and restore behavior are implemented and verified.
