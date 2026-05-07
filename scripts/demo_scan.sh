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
DEMO_HOME="$(mktemp -d /tmp/qise-demo-scan.XXXXXX)"

cleanup() {
  rm -rf "$DEMO_HOME"
}
trap cleanup EXIT

export QISE_HOME="$DEMO_HOME/qise-home"
export PYTHONPATH="$ROOT_DIR/src${PYTHONPATH:+:$PYTHONPATH}"

qise() {
  "$PYTHON_BIN" -m qise "$@"
}

cd "$ROOT_DIR"

printf '\n== Qise Preflight Scan Demo ==\n'
printf 'Temporary QISE_HOME: %s\n\n' "$QISE_HOME"

printf '== 1. Safe Skill ==\n'
qise scan skill examples/skills/safe

printf '\n== 2. Dangerous Skill ==\n'
set +e
qise scan skill examples/skills/dangerous
skill_code=$?
set -e
printf 'Expected non-zero exit code from dangerous skill: %s\n' "$skill_code"

printf '\n== 3. Dangerous MCP ==\n'
set +e
qise scan mcp examples/mcp-dangerous.json
mcp_code=$?
set -e
printf 'Expected non-zero exit code from dangerous MCP: %s\n' "$mcp_code"

printf '\n== 4. Event Summary ==\n'
qise events --limit 10

printf '\n== 5. Raw JSON Events ==\n'
qise events --limit 3 --json

printf '\nScan demo complete.\n'
