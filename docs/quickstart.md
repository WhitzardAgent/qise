# Quick Start

Get Qise running in 5 minutes — from install to first security check.

## 1. Install

```bash
pip install qise
```

## 2. Your First Security Check

```python
from qise import Shield

shield = Shield.from_config()

# Check a dangerous command — BLOCKED
result = shield.pipeline.run_egress({
    "tool_name": "bash",
    "tool_args": {"command": "rm -rf /"},
})
print(result.verdict)      # "block"
print(result.blocked_by)   # "command"

# Check a safe command — PASSED
result = shield.pipeline.run_egress({
    "tool_name": "bash",
    "tool_args": {"command": "ls -la"},
})
print(result.verdict)      # "pass"
```

Or use the CLI:

```bash
qise check bash '{"command": "rm -rf /"}'
# {"verdict": "block", "blocked_by": "command", ...}

qise check bash '{"command": "ls"}'
# {"verdict": "pass", ...}
```

## 3. Configure (Optional)

Generate a config file:

```bash
qise init
```

Edit `shield.yaml` to customize guard modes:

```yaml
guards:
  config:
    command:
      mode: enforce    # Block dangerous commands
    prompt:
      mode: enforce    # Block injection attempts (needs SLM)
    credential:
      mode: enforce    # Block credential leaks
```

## 4. Integrate with Your Agent

### Generic SDK

```python
from qise import Shield
from qise.core.models import GuardContext

shield = Shield.from_config()
result = shield.pipeline.run_egress(GuardContext(
    tool_name="bash",
    tool_args={"command": "rm -rf /tmp/*"},
))
if result.should_block:
    raise RuntimeError(f"Blocked: {result.blocked_by}")
```

### LangGraph

```python
from qise import Shield
from qise.adapters.langgraph import QiseLangGraphWrapper

shield = Shield.from_config()
wrapper = QiseLangGraphWrapper(shield)
safe_tools = [wrapper.wrap_tool_call(tool) for tool in my_tools]
```

### OpenAI Agents SDK

```python
from qise import Shield
from qise.adapters.openai_agents import QiseOpenAIAgentsGuardrails

shield = Shield.from_config()
guardrails = QiseOpenAIAgentsGuardrails(shield)
agent = Agent(guardrails=[guardrails.input_guardrail, guardrails.output_guardrail])
```

### NexAU

```python
from qise import Shield
from qise.adapters.nexau import QiseNexauMiddleware

shield = Shield.from_config()
middleware = QiseNexauMiddleware(shield)
agent = NexAUAgent(middlewares=[middleware])
```

## 5. Proxy Mode (Zero-Code)

```bash
qise proxy start --port 8822 --upstream https://api.openai.com
```

Then point your agent's API endpoint to `http://localhost:8822/v1`.

## What's Next?

- [Architecture](architecture.md) — System design and pipeline details
- [Guard Specifications](guards.md) — All 14 guards explained
- [Integration Guide](integration.md) — Proxy, MCP, and SDK modes
- [Performance](performance.md) — Latency benchmarks
- [Threat Model](threat-model.md) — Threats Qise addresses
