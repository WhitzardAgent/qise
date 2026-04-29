#!/bin/bash
# Run all sandbox tests for Qise + real Agent frameworks
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=========================================="
echo "  Qise Real Agent Sandbox Tests"
echo "=========================================="
echo ""

# Step 1: Build images
echo "[1/5] Building images..."
bash "$SCRIPT_DIR/build.sh"

# Step 2: Start Qise Proxy
echo ""
echo "[2/5] Starting Qise Proxy..."
docker compose -f "$SCRIPT_DIR/docker-compose.yml" up -d qise-proxy

# Wait for proxy to be healthy
echo "Waiting for proxy to be ready..."
for i in $(seq 1 30); do
    if docker compose -f "$SCRIPT_DIR/docker-compose.yml" exec -T qise-proxy \
        python -c "import httpx; r=httpx.get('http://localhost:8822/v1/models', timeout=5); exit(0 if r.status_code<500 else 1)" 2>/dev/null; then
        echo "Proxy is ready!"
        break
    fi
    echo "  Waiting... ($i/30)"
    sleep 2
done

# Step 3: Start Agent containers
echo ""
echo "[3/5] Starting Agent containers..."
docker compose -f "$SCRIPT_DIR/docker-compose.yml" up -d hermes nexau openai-agents

# Step 4: Apply network restrictions
echo ""
echo "[4/5] Applying network restrictions..."
if [ "$(id -u)" -eq 0 ]; then
    bash "$SCRIPT_DIR/restrict_network.sh"
else
    echo "  Skipping (requires root). Run manually: sudo bash $SCRIPT_DIR/restrict_network.sh"
fi

# Step 5: Run tests
echo ""
echo "[5/5] Running tests..."
echo ""

echo "--- Hermes Tests ---"
docker compose -f "$SCRIPT_DIR/docker-compose.yml" exec -T hermes \
    python /opt/qise-tests/test_hermes.py 2>&1 || echo "Hermes tests had failures"

echo ""
echo "--- NexAU Tests ---"
docker compose -f "$SCRIPT_DIR/docker-compose.yml" exec -T nexau \
    python -m pytest /opt/qise-tests/test_nexau.py -v 2>&1 || echo "NexAU tests had failures"

echo ""
echo "--- OpenAI Agents Tests ---"
docker compose -f "$SCRIPT_DIR/docker-compose.yml" exec -T openai-agents \
    python -m pytest /opt/qise-tests/test_openai_agents.py -v 2>&1 || echo "OpenAI Agents tests had failures"

echo ""
echo "=========================================="
echo "  All tests complete"
echo "=========================================="
echo ""
echo "To clean up: docker compose -f $SCRIPT_DIR/docker-compose.yml down -v"
