#!/bin/bash
# setup_slm.sh — Install Ollama + pull qwen3:4b for local SLM deployment
#
# Usage:
#   chmod +x scripts/setup_slm.sh
#   ./scripts/setup_slm.sh
#
# This script:
#   1. Checks if Ollama is installed, installs if missing
#   2. Pulls qwen3:4b model (~2.4GB, 4B params)
#   3. Starts Ollama server (default http://localhost:11434)
#   4. Verifies the model responds to a test prompt
#
# After running, configure shield.yaml:
#   models:
#     slm:
#       base_url: "http://localhost:11434/v1"
#       model: "qwen3:4b"
#       timeout_ms: 5000

set -euo pipefail

MODEL="${QISE_SLM_MODEL:-qwen3:4b}"
OLLAMA_URL="${OLLAMA_HOST:-http://localhost:11434}"

echo "=== Qise Local SLM Setup ==="
echo "Model: ${MODEL}"
echo ""

# --- Step 1: Check / Install Ollama ---
if command -v ollama &>/dev/null; then
    echo "[1/4] Ollama already installed: $(ollama --version 2>/dev/null || echo 'version unknown')"
else
    echo "[1/4] Ollama not found — installing..."
    curl -fsSL https://ollama.com/install.sh | sh
    echo "Ollama installed successfully."
fi

# --- Step 2: Start Ollama server ---
echo "[2/4] Starting Ollama server..."
if curl -sf "${OLLAMA_URL}/api/tags" &>/dev/null; then
    echo "  Ollama server already running at ${OLLAMA_URL}"
else
    ollama serve &
    OLLAMA_PID=$!
    echo "  Waiting for Ollama server..."
    for i in $(seq 1 30); do
        if curl -sf "${OLLAMA_URL}/api/tags" &>/dev/null; then
            echo "  Ollama server ready (PID ${OLLAMA_PID})"
            break
        fi
        sleep 1
    done
    if ! curl -sf "${OLLAMA_URL}/api/tags" &>/dev/null; then
        echo "ERROR: Ollama server failed to start within 30s"
        exit 1
    fi
fi

# --- Step 3: Pull model ---
echo "[3/4] Pulling model '${MODEL}' (this may take a few minutes)..."
ollama pull "${MODEL}"
echo "  Model '${MODEL}' pulled successfully."

# --- Step 4: Verify ---
echo "[4/4] Verifying model responds..."
RESPONSE=$(curl -sf "${OLLAMA_URL}/v1/chat/completions" \
    -H "Content-Type: application/json" \
    -d "{\"model\":\"${MODEL}\",\"messages\":[{\"role\":\"user\",\"content\":\"Say OK\"}],\"max_tokens\":10}" \
    2>/dev/null || echo "")

if echo "${RESPONSE}" | grep -q '"content"'; then
    echo "  Model responds correctly!"
else
    echo "  WARNING: Model did not return expected response."
    echo "  Response: ${RESPONSE:0:200}"
fi

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Configure your shield.yaml:"
echo "  models:"
echo "    slm:"
echo "      base_url: \"http://localhost:11434/v1\""
echo "      model: \"${MODEL}\""
echo "      timeout_ms: 5000"
echo ""
echo "Or set environment variables:"
echo "  export QISE_SLM_BASE_URL=http://localhost:11434/v1"
echo "  export QISE_SLM_MODEL=${MODEL}"
