#!/bin/bash
# Build all Docker images for Qise sandbox testing
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "=== Building Qise Sandbox Images ==="
echo "Project root: $PROJECT_ROOT"
echo ""

# Build Qise Proxy
echo "[1/4] Building qise-proxy..."
docker build -t qise-proxy -f "$SCRIPT_DIR/Dockerfile.qise-proxy" "$PROJECT_ROOT"

# Build Hermes Agent
echo "[2/4] Building hermes..."
docker build -t qise-hermes -f "$SCRIPT_DIR/Dockerfile.hermes" "$PROJECT_ROOT"

# Build NexAU Agent
echo "[3/4] Building nexau..."
docker build -t qise-nexau -f "$SCRIPT_DIR/Dockerfile.nexau" "$PROJECT_ROOT"

# Build OpenAI Agents
echo "[4/4] Building openai-agents..."
docker build -t qise-openai-agents -f "$SCRIPT_DIR/Dockerfile.openai-agents" "$PROJECT_ROOT"

echo ""
echo "=== All images built successfully ==="
docker images | grep qise-
