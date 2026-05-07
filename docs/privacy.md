# Privacy

Qise MVP is local-first.

## Local Files

Default local state:

```text
~/.qise/state.json
~/.qise/events.jsonl
~/.qise/backups/
~/.qise/logs/
```

You can redirect this for testing:

```bash
export QISE_HOME=/tmp/qise-demo
```

## What Events Store

Events store compact evidence snippets such as:

- blocked command snippets
- scan finding paths
- rule ids
- short recommendations

Events should not become a copy of full model traffic. Proxy and bridge event writers intentionally summarize guard results.

## Backups

`qise protect` stores full Agent config backups so restore can work. Treat `~/.qise/backups/` as sensitive if your Agent config contains provider names, endpoint URLs, or environment variable names.

## Removing Local Data

```bash
qise restore all
qise stop
rm -rf ~/.qise
```
