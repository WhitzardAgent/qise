# Integration Guide

Qise offers three integration modes, ranging from zero-code desktop usage to developer-friendly programmatic access.

## Integration Modes at a Glance

| Mode | Code Required | Defense Depth | Best For |
|------|--------------|---------------|----------|
| **Proxy Mode** | 0 lines | Full (4 layers) | Desktop users, non-developers |
| **MCP Mode** | 0 lines | Partial (hard defense only) | MCP ecosystem users |
| **SDK Mode** | 1-5 lines | Full (4 layers) + lowest latency | Agent developers |

---

## Mode A: Proxy Mode (Zero-Code, Recommended)

Qise starts a local HTTP proxy that intercepts all traffic between the Agent and its LLM API. By parsing the OpenAI-compatible API format, it can inspect requests and responses in real-time.

### How It Works

```
Agent ──API Request──▶ Qise Proxy ──Forwarded Request──▶ LLM API
                          │                                    │
                          │ Guard Pipeline                     │
                          │ • Check injection in messages      │
                          │ • Inject security context          │
                          │ • Parse tool_use / tool_result     │
                          │                                    │
                       Agent ◀──Modified Response── Qise Proxy ◀──API Response──
```

### Desktop App Setup (One-Click)

1. Install Qise desktop app
2. Click "Enable Protection" in system tray
3. Qise automatically:
   - Starts the local proxy server
   - Backs up your Agent's current API configuration
   - Switches the API endpoint to `http://localhost:8822/v1`
   - Stores your original API key securely
4. Your Agent now routes through Qise — protection is active

### Proxy Takeover (inspired by cc-switch)

The proxy takeover process:

```
Before:
  Agent config → api_key: "sk-ant-xxx" → endpoint: "https://api.anthropic.com"

After Takeover:
  Agent config → api_key: "QISE_MANAGED" → endpoint: "http://localhost:8822/v1"
  Qise stores:  original_key = "sk-ant-xxx", original_endpoint = "https://api.anthropic.com"

On Exit / Crash Recovery:
  Agent config → api_key: "sk-ant-xxx" → endpoint: "https://api.anthropic.com"  # Auto-restored
```

### What the Proxy Inspects

| API Event | Proxy Action | Guards Triggered |
|-----------|-------------|-----------------|
| Request with `messages` | Check user_input for injection | PromptGuard |
| Request with `tools` | Check tool descriptions for poisoning | ToolSanityGuard |
| Response with `tool_use` | Check tool call arguments | CommandGuard, FilesystemGuard, NetworkGuard, ExfilGuard |
| Response with reasoning | Analyze chain of thought | ReasoningGuard |
| Request with `tool_result` | Check tool output for injection | PromptGuard |
| Response with text | Check for credential/KB leaks | CredentialGuard, OutputGuard |
| Any request | Inject security context into system message | SecurityContextProvider |

### Guard Decision → Proxy Action

| Guard Verdict | Proxy Action |
|---------------|-------------|
| PASS | Forward request/response unchanged |
| WARN | Add warning header, forward unchanged |
| BLOCK | Return error response to Agent, don't forward |
| ESCALATE | Pause, invoke LLM deep analysis, then decide |

### SSE Streaming Support

For agents using streaming responses (SSE), the proxy:
1. Buffers the streaming response incrementally
2. Analyzes tool_use calls as they appear in the stream
3. For text content, performs output checks on completed chunks
4. Does NOT block streaming for text-only responses (low latency impact)

### Supported Agents (Proxy Mode)

| Agent | API Format | Proxy Support |
|-------|-----------|---------------|
| Claude Code | OpenAI-compatible | Full |
| Codex (OpenAI) | OpenAI-compatible | Full |
| Gemini CLI | OpenAI-compatible | Full |
| OpenClaw | OpenAI-compatible | Full |
| Hermes | OpenAI-compatible | Full |
| Custom agents | OpenAI-compatible | Full |

### CLI Proxy Mode

For users who prefer CLI over the desktop app:

```bash
# Start Qise proxy
qise proxy start --port 8822 --config shield.yaml

# Manually configure your agent to use the proxy
export OPENAI_API_BASE="http://localhost:8822/v1"

# Or let Qise auto-configure
qise proxy takeover --agent claude_code
```

---

## Mode B: MCP Mode (Zero-Code, Limited)

Qise registers as an MCP server in the Agent's configuration. The Agent can call Qise's security check tools voluntarily.

### Setup

**Desktop App**: Click "Register MCP" → Qise automatically adds itself to the Agent's MCP configuration.

**Manual**: Add to your Agent's MCP configuration:

```json
{
  "mcpServers": {
    "qise": {
      "command": "python",
      "args": ["-m", "qise.mcp_server"],
      "env": {
        "QISE_CONFIG": "/path/to/shield.yaml"
      }
    }
  }
}
```

### MCP Tools

| Tool | Description | Parameters |
|------|-------------|-----------|
| `qise_check_tool_call` | Check a tool call before execution | `tool_name`, `tool_args` |
| `qise_check_content` | Check incoming content for injection | `content`, `trust_boundary` |
| `qise_check_output` | Check agent output for leaks | `output_text` |
| `qise_get_security_context` | Get security context for current operation | `tool_name`, `tool_args` |

### MCP Limitations

| Limitation | Impact | Mitigation |
|-----------|--------|-----------|
| No trajectory access | Can't detect multi-turn attacks | Use Proxy Mode for full coverage |
| No reasoning access | ReasoningGuard unavailable | Use Proxy Mode for full coverage |
| No auto-interception | Agent must voluntarily call tools | Combine with SecurityContextProvider injection via AGENTS.md |
| No security context injection | Soft defense layer unavailable | Manually add security rules to CLAUDE.md/AGENTS.md |

### Recommended MCP Usage

MCP mode works best when combined with manual security context injection:

1. Register Qise as MCP server (for hard defense checks)
2. Add security context to CLAUDE.md / AGENTS.md (for soft defense)

```markdown
# Add to CLAUDE.md or AGENTS.md

## Security Rules
- Before executing any shell command, call qise_check_tool_call
- Before processing tool results, call qise_check_content
- Before sending output, call qise_check_output
- Call qise_get_security_context for security guidance
```

---

## Mode C: SDK Mode (Code Integration)

For developers who want the deepest integration and lowest latency.

### Generic Python SDK

```python
from qise import Shield
from qise.core.models import GuardContext

shield = Shield.from_config()

# Check a tool call before execution
result = shield.pipeline.run_egress(GuardContext(
    tool_name="bash",
    tool_args={"command": "rm -rf /tmp/*"},
))

if result.should_block:
    print(f"Blocked: {result.blocked_by}")
```

### Nanobot

```python
from qise import Shield
from qise.adapters.nanobot import QiseNanobotHook

shield = Shield.from_config()
hook = QiseNanobotHook(shield)
loop = AgentLoop(hooks=[hook])
```

| Feature | Supported |
|---------|-----------|
| Ingress (tool result check) | Yes |
| Egress (tool call check) | Yes |
| Output (leak detection) | Yes |
| Security context injection | Yes |
| Reasoning access | Yes (via agent_reasoning) |

### Hermes

```python
from qise import Shield
from qise.adapters.hermes import QiseHermesPlugin

shield = Shield.from_config()
plugin = QiseHermesPlugin(shield)
plugin.register(ctx)
```

| Feature | Supported |
|---------|-----------|
| Ingress (tool result check) | Yes (transform_tool_result) |
| Egress (tool call check) | Yes (pre_tool_call → {"action": "skip"}) |
| Output (leak detection) | Yes (post_llm_call) |
| Security context injection | — |
| Reasoning access | — |

### NexAU

```python
from qise import Shield
from qise.adapters.nexau import QiseNexauMiddleware

shield = Shield.from_config()
middleware = QiseNexauMiddleware(shield)
agent = NexAUAgent(middlewares=[middleware])
```

| Feature | Supported |
|---------|-----------|
| Ingress (tool result check) | Yes (after_tool) |
| Egress (tool call check) | Yes (after_model, before_tool) |
| Output (leak detection) | Yes (after_agent) |
| Security context injection | Yes (before_model) |
| Reasoning access | Yes (after_model) |

6 middleware hooks: before/after_agent, before/after_model, before/after_tool.

### LangGraph

```python
from qise import Shield
from qise.adapters.langgraph import QiseLangGraphWrapper

shield = Shield.from_config()
wrapper = QiseLangGraphWrapper(shield)

# Wrap tools for ToolNode
safe_tools = [wrapper.wrap_tool_call(tool) for tool in my_tools]

# Or async version
safe_tools = [wrapper.awrap_tool_call(tool) for tool in my_async_tools]

# Add pre-model hook for SecurityContext injection
graph.add_node("pre_model", wrapper.qise_pre_model_hook)
```

| Feature | Supported |
|---------|-----------|
| Ingress | — |
| Egress (tool call check) | Yes (wrap_tool_call / awrap_tool_call) |
| Output | — |
| Security context injection | Yes (qise_pre_model_hook) |
| Reasoning access | — |

BLOCK strategy: raises `ToolException` (if langgraph installed) or `RuntimeError`.

### OpenAI Agents SDK

```python
from qise import Shield
from qise.adapters.openai_agents import QiseOpenAIAgentsGuardrails

shield = Shield.from_config()
guardrails = QiseOpenAIAgentsGuardrails(shield)

agent = Agent(
    name="my-agent",
    guardrails=[
        guardrails.input_guardrail,
        guardrails.output_guardrail,
    ],
)

# Or wrap tools individually
for tool in tools:
    tool = guardrails.wrap_tool(tool)
```

| Feature | Supported |
|---------|-----------|
| Ingress (input check) | Yes (input_guardrail, tool_output_guardrail) |
| Egress (tool call check) | Yes (tool_input_guardrail) |
| Output (leak detection) | Yes (output_guardrail) |
| Security context injection | — |
| Reasoning access | — |

BLOCK strategy: returns `GuardrailFunctionOutput(tripwire_triggered=True)`.

### Custom Adapter

All adapters inherit from `AgentAdapter` and use `IngressCheckMixin` / `EgressCheckMixin`:

```python
from qise.adapters.base import AgentAdapter, EgressCheckMixin, IngressCheckMixin

class MyFrameworkAdapter(AgentAdapter, IngressCheckMixin, EgressCheckMixin):

    def __init__(self, shield):
        super().__init__(shield)

    def install(self):
        """Register your hooks here."""
        pass

    def uninstall(self):
        """Remove your hooks here."""
        pass

    # IngressCheckMixin provides:
    #   check_user_input(content, trust_boundary, session_id)
    #   check_tool_result(content, tool_name, session_id)

    # EgressCheckMixin provides:
    #   check_tool_call(tool_name, tool_args, session_id, **kwargs)
    #   check_output(text, session_id)
    #   _get_security_rules(tool_name, tool_args)
```

---

## Adapter Architecture

All 5 adapters share a common base:

```
AgentAdapter (ABC)
├── install() / uninstall()
│
├── IngressCheckMixin
│   ├── check_user_input()  → Ingress pipeline
│   └── check_tool_result() → Ingress pipeline
│
└── EgressCheckMixin
    ├── check_tool_call()   → Egress pipeline (auto-fills active_security_rules)
    └── check_output()      → Output pipeline
```

Each adapter maps framework-specific hooks to these mixin methods. No monkey-patching — only official Hook/Plugin/Middleware APIs.
```

---

## Desktop App Integration

The Qise desktop app manages all three modes through a visual interface:

### System Tray

| Action | What It Does |
|--------|-------------|
| Toggle Protection | Enable/disable proxy mode for selected agents |
| View Status | Current protection state, blocked event count |
| Switch Mode | observe / enforce / off for quick switching |
| Quick Settings | SLM on/off, key guard toggles |

### Proxy Panel

- Select which agents to protect (Claude Code, Codex, Gemini CLI, etc.)
- Configure proxy port and API forwarding
- View real-time intercepted requests and guard decisions
- Manual takeover/release for each agent

### MCP Panel

- Auto-register/unregister Qise to agent MCP configs
- View which agents have Qise MCP enabled
- Configure MCP tool permissions

### Policy Editor

- Visual toggle for each guard (observe/enforce/off)
- Threshold sliders for AI-first guards
- YAML threat pattern editor with syntax highlighting
- Security context DSL template management
- Import/export policies

---

## Configuration Reference

### shield.yaml

```yaml
version: "1.0"

# Integration mode
integration:
  mode: proxy  # proxy | mcp | sdk
  proxy:
    port: 8822
    target_agents:
      - claude_code
      - codex
    auto_takeover: true
    crash_recovery: true
  mcp:
    auto_register: true

# Model configuration
models:
  slm:
    base_url: "http://localhost:8822/v1"
    model: "AgentDoG-Qwen3-4B"
    timeout_ms: 200
  llm:
    base_url: "https://api.anthropic.com"
    model: "claude-sonnet-4-5"
    timeout_ms: 5000
  embedding:
    base_url: "http://localhost:8822/v1"
    model: "text-embedding-3-small"

# Guard configuration
guards:
  enabled:
    - prompt
    - command
    - reasoning
  config:
    prompt:
      mode: observe
      slm_confidence_threshold: 0.7
    command:
      mode: enforce
    reasoning:
      mode: observe
      threshold_adjustment_factor: 0.3

# Data paths
data:
  threat_patterns_dir: "./data/threat_patterns"
  security_contexts_dir: "./data/security_contexts"
  baselines_dir: "./data/baselines"

# Logging
logging:
  level: INFO
  format: json
  output: stderr
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `QISE_CONFIG` | Path to shield.yaml | `./shield.yaml` |
| `QISE_INTEGRATION_MODE` | Integration mode override | From config |
| `QISE_PROXY_PORT` | Proxy server port | 8822 |
| `QISE_SLM_BASE_URL` | SLM API endpoint | From config |
| `QISE_SLM_MODEL` | SLM model name | From config |
| `QISE_LLM_BASE_URL` | LLM API endpoint | From config |
| `QISE_LLM_MODEL` | LLM model name | From config |
| `QISE_LOG_LEVEL` | Log level | From config |
| `QISE_MODE` | Global guard mode override | From config |
