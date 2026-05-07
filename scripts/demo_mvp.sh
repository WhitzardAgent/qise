#!/usr/bin/env bash
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
if [[ -n "${PYTHON:-}" ]]; then
  PYTHON_BIN="$PYTHON"
elif [[ -n "${VIRTUAL_ENV:-}" && -x "$VIRTUAL_ENV/bin/python" ]]; then
  PYTHON_BIN="$VIRTUAL_ENV/bin/python"
elif [[ -n "${CONDA_PREFIX:-}" && -x "$CONDA_PREFIX/bin/python" ]]; then
  PYTHON_BIN="$CONDA_PREFIX/bin/python"
else
  PYTHON_BIN="python3"
fi
DEMO_ROOT="$(mktemp -d /tmp/qise-demo-mvp.XXXXXX)"

cleanup() {
  rm -rf "$DEMO_ROOT"
}
trap cleanup EXIT

export QISE_HOME="$DEMO_ROOT/qise-home"
export QISE_AGENT_HOME="$DEMO_ROOT/agent-home"
export QISE_NO_START_SERVICES=1
export PYTHONPATH="$ROOT_DIR/src${PYTHONPATH:+:$PYTHONPATH}"

qise() {
  "$PYTHON_BIN" -m qise "$@"
}

mkdir -p "$QISE_AGENT_HOME/.codex"
cat > "$QISE_AGENT_HOME/.codex/config.toml" <<'EOF'
model_provider = "demo"

[model_providers.demo]
name = "Demo Provider"
base_url = "https://api.demo.example/v1"
env_key = "DEMO_API_KEY"
EOF

printf '\n== Qise MVP Demo ==\n'
printf 'Temporary QISE_HOME: %s\n' "$QISE_HOME"
printf 'Temporary fake Codex config: %s\n\n' "$QISE_AGENT_HOME/.codex/config.toml"

printf '== 1. Doctor ==\n'
qise doctor || true

printf '\n== 2. Protect fake Codex config ==\n'
qise protect codex

printf '\n== 3. Status ==\n'
qise status

printf '\n== 4. Trigger a blocked command check ==\n'
set +e
qise check bash '{"command":"rm -rf /"}'
check_code=$?
set -e
printf 'Expected non-zero exit code from blocked command: %s\n' "$check_code"

printf '\n== 5. Events ==\n'
qise events --limit 10

printf '\n== 6. Restore ==\n'
qise restore codex

printf '\n== 7. Restored config ==\n'
cat "$QISE_AGENT_HOME/.codex/config.toml"

printf '\nDemo complete. Real Codex config was not touched.\n'
