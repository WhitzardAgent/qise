#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="$ROOT_DIR/src-tauri/resources/bin"
WORK_DIR="$ROOT_DIR/src-tauri/target/pyinstaller-work"
SPEC_DIR="$ROOT_DIR/src-tauri/target/pyinstaller-spec"
CONFIG_DIR="$ROOT_DIR/src-tauri/target/pyinstaller-config"
OUT_BIN="$OUT_DIR/qise"

mkdir -p "$OUT_DIR" "$WORK_DIR" "$SPEC_DIR" "$CONFIG_DIR"

if [[ -n "${QISE_DESKTOP_PYTHON:-}" ]]; then
  PYTHON_CMD=("$QISE_DESKTOP_PYTHON")
elif command -v conda >/dev/null 2>&1 && conda run -n qise python -c "import qise" >/dev/null 2>&1; then
  PYTHON_CMD=(conda run -n qise python)
else
  PYTHON_CMD=(python3)
fi

if ! "${PYTHON_CMD[@]}" -c "import qise" >/dev/null 2>&1; then
  echo "Qise Desktop runtime build failed: selected Python cannot import qise." >&2
  echo "Set QISE_DESKTOP_PYTHON to a Python that has Qise installed, or run from the qise conda env." >&2
  exit 1
fi

if ! "${PYTHON_CMD[@]}" -m PyInstaller --version >/dev/null 2>&1; then
  echo "Qise Desktop runtime build failed: PyInstaller is not installed in the selected Python." >&2
  echo "Install it with: ${PYTHON_CMD[*]} -m pip install pyinstaller" >&2
  exit 1
fi

PYINSTALLER_CONFIG_DIR="$CONFIG_DIR" "${PYTHON_CMD[@]}" -m PyInstaller \
  --clean \
  --noconfirm \
  --onefile \
  --name qise \
  --paths "$ROOT_DIR/src" \
  --add-data "$ROOT_DIR/src/qise/data:qise/data" \
  --collect-submodules qise \
  --distpath "$OUT_DIR" \
  --workpath "$WORK_DIR" \
  --specpath "$SPEC_DIR" \
  "$ROOT_DIR/src/qise/__main__.py"

chmod +x "$OUT_BIN"
"$OUT_BIN" version >/dev/null
echo "Built bundled Qise runtime: $OUT_BIN"
