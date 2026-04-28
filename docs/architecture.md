# Architecture

Qise is organized as a layered system with three integration modes ranging from zero-code desktop usage to developer-friendly programmatic access.

## System Overview

```
┌──────────────────────────────────────────────────────────────────────────┐
│                         Desktop App (Tauri 2)                            │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │  System Tray │ Guard Dashboard │ Policy Editor │ Threat Explorer   │  │
│  │  One-click toggle │ Real-time events │ YAML editor │ Pattern lib   │  │
│  └────────────────────────────────────────────────────────────────────┘  │
├──────────────────────────────────────────────────────────────────────────┤
│                         Integration Layer                                │
│                                                                          │
│  ┌── Mode A: Proxy Mode (Zero-Code) ──────────────────────────────────┐ │
│  │  API Proxy: 拦截 Agent ↔ LLM 的请求流                              │ │
│  │  • Request 拦截: 在 Agent 请求中注入安全上下文                      │ │
│  │  • Response 拦截: 检查 LLM 响应中的危险指令/行为                    │ │
│  │  • Tool Call 拦截: 解析 tool_use 请求, 运行 Guard Pipeline          │ │
│  │  • Tool Result 拦截: 检查 tool_result 中的注入内容                  │ │
│  │  适用于: Claude Code, Codex, Gemini CLI 等 OpenAI-compatible API    │ │
│  └────────────────────────────────────────────────────────────────────┘ │
│                                                                          │
│  ┌── Mode B: MCP Mode (Zero-Code) ────────────────────────────────────┐ │
│  │  MCP Server: 注册为 Agent 的 MCP 工具提供方                        │ │
│  │  • 自动注册到 Agent 的 MCP 配置文件                                 │ │
│  │  • 提供 security_check / security_context 等工具                    │ │
│  │  • 适用于: 所有支持 MCP 的 Agent 框架                               │ │
│  │  限制: 无轨迹访问, 无推理访问, 无自动拦截                           │ │
│  └────────────────────────────────────────────────────────────────────┘ │
│                                                                          │
│  ┌── Mode C: SDK Mode (Code Integration) ─────────────────────────────┐ │
│  │  Framework Adapters: 注册 Hook/Plugin 到 Agent 框架                │ │
│  │  • OpenClaw Plugin │ Hermes Plugin │ Nanobot Hook │ OpenHands Hook  │ │
│  │  • 完整轨迹访问 │ 推理访问 │ 安全上下文注入 │ 自动拦截              │ │
│  │  适用于: 愿意修改 Agent 代码的开发者                                │ │
│  └────────────────────────────────────────────────────────────────────┘ │
│                                                                          │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌── Soft Defense Layer ──────────────────────────────────────────────┐ │
│  │  SecurityContextProvider    ReasoningGuard                         │ │
│  ├────────────────────────────────────────────────────────────────────┤ │
│  │  Guard Pipeline (Hard Defense)                                     │ │
│  │                                                                    │ │
│  │  Ingress:  PromptGuard → ToolSanityGuard → ContextGuard            │ │
│  │            → SupplyChainGuard                                      │ │
│  │  Egress:   CommandGuard → FilesystemGuard → NetworkGuard           │ │
│  │            → ExfilGuard → ResourceGuard → ToolPolicyGuard           │ │
│  │  Output:   CredentialGuard → AuditGuard → OutputGuard               │ │
│  ├────────────────────────────────────────────────────────────────────┤ │
│  │  Shared Services                                                   │ │
│  │  ModelRouter │ ThreatPatternLoader │ BaselineManager                │ │
│  │  SessionTracker │ EventLogger                                      │ │
│  └────────────────────────────────────────────────────────────────────┘ │
│                                                                          │
│  ┌── Data Layer ──────────────────────────────────────────────────────┐ │
│  │  threat_patterns/ │ security_contexts/ │ baselines/                 │ │
│  │  risk_rules/      │ eval_datasets/                                │ │
│  └────────────────────────────────────────────────────────────────────┘ │
│                                                                          │
│  ┌── Model Layer ─────────────────────────────────────────────────────┐ │
│  │  SLM (≤4B, <50ms) │ LLM (8B-70B, <2s) │ Embedding (<10ms)         │ │
│  └────────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────────┘
```

## Three Integration Modes

Qise 的核心设计原则：**用户不需要改一行 Agent 代码就能获得基本防护**。

### Mode A: Proxy Mode (推荐，零代码)

**灵感来源**: cc-switch 的 Proxy Takeover 模式。

**原理**: Qise 启动一个本地 HTTP 代理服务器，拦截 Agent 与 LLM 之间的所有 API 请求。通过解析 OpenAI-compatible API 的请求/响应格式，在流量层面实现安全检查。

```
Agent (Claude Code / Codex / Gemini CLI)
    │
    │ API Request (OpenAI-compatible format)
    ▼
┌─────────────────────────────────────────┐
│         Qise API Proxy                  │
│                                         │
│  1. Request Interceptor                 │
│     • 解析 messages, tool_use 请求      │
│     • Ingress Pipeline: 检查 user_input │
│       和 tool_result 中的注入           │
│     • 注入安全上下文到 system message   │
│                                         │
│  2. Response Interceptor                │
│     • 解析 assistant response           │
│     • Egress Pipeline: 检查 tool_call   │
│       参数（命令、文件、网络）           │
│     • ReasoningGuard: 分析推理过程      │
│                                         │
│  3. Tool Result Interceptor             │
│     • 解析 tool_result                  │
│     • Ingress Pipeline: 检查工具结果    │
│       中的间接注入                      │
│     • Output Pipeline: 检查凭据泄露     │
│                                         │
│  4. Guard Decision                      │
│     • BLOCK → 返回错误响应给 Agent      │
│     • WARN → 添加警告到响应, 继续转发   │
│     • PASS → 透明转发到 LLM             │
└─────────────────────────────────────────┘
    │
    │ Forwarded Request
    ▼
  LLM API (Anthropic / OpenAI / etc.)
```

**关键能力**:

| 能力 | 实现方式 |
|------|---------|
| 轨迹访问 | 从请求中提取完整 messages 数组 |
| 推理访问 | 从 assistant response 中提取 reasoning/thinking 内容 |
| 安全上下文注入 | 在请求的 system message 中追加安全规则 |
| 拦截能力 | BLOCK 时返回错误响应，阻止 tool 执行 |
| Tool Call 检测 | 解析 `tool_use` 类型的 assistant message |
| Tool Result 检测 | 解析 `tool_result` 类型的 user message |

**Proxy 接管方式** (借鉴 cc-switch):
1. 自动备份 Agent 当前 API 配置
2. 将 API endpoint 改为 `http://localhost:PORT/v1`
3. 代理存储原始 API key，转发时使用
4. 退出时自动恢复原始配置
5. 崩溃恢复: 启动时检测未恢复的配置并自动修复

**适用 Agent**: 所有使用 OpenAI-compatible API 的 Agent（Claude Code, Codex, Gemini CLI 等）

**优势**: 零代码, 完整轨迹访问, 自动拦截
**劣势**: 需要理解 API 协议细节; 流式响应(SSE)处理复杂; 对非 OpenAI-compatible 的 Agent 不适用

### Mode B: MCP Mode (零代码，能力受限)

**原理**: Qise 作为 MCP Server 注册到 Agent 的 MCP 配置中。Agent 可以主动调用 Qise 提供的安全检查工具。

```
Agent
  │
  ├── 自主调用 qise_check_tool_call (调用工具前)
  ├── 自主调用 qise_check_content (收到外部内容时)
  ├── 自主调用 qise_check_output (输出前)
  └── 自主调用 qise_get_security_context (获取安全上下文)
        │
        ▼
  Qise MCP Server → Guard Pipeline → 返回检查结果
```

**MCP 工具列表**:

| 工具 | 功能 | 返回 |
|------|------|------|
| `qise_check_tool_call` | 检查工具调用安全性 | PASS/WARN/BLOCK + RiskAttribution |
| `qise_check_content` | 检查内容注入风险 | PASS/WARN/BLOCK + RiskAttribution |
| `qise_check_output` | 检查输出泄露 | PASS/WARN + redacted output |
| `qise_get_security_context` | 获取当前场景安全规则 | Security context text |

**关键限制**:
- **无轨迹访问**: MCP 协议无法获取完整对话历史
- **无推理访问**: 无法访问 Agent 的推理过程
- **无自动拦截**: Agent 必须主动调用检查工具（可以被绕过）
- **无安全上下文注入**: 无法自动向 Agent observation 注入安全提示

**适用 Agent**: 所有支持 MCP 的 Agent 框架

**优势**: 通用性最强, 零代码
**劣势**: 防护依赖 Agent 自觉调用; 无法获取完整上下文; 无法自动拦截

### Mode C: SDK Mode (需要改代码，能力最全)

**原理**: 直接在 Agent 代码中注册 Qise 的 Hook/Plugin，获得最完整的防护能力。

```python
# Nanobot 示例
from qise import Shield
from qise.adapters.nanobot import NanobotShieldHook

shield = Shield.from_config("shield.yaml")
await bot.run(message, hooks=[NanobotShieldHook(shield)])
```

**关键能力**:

| 能力 | 说明 |
|------|------|
| 完整轨迹 | 直接访问 session.messages |
| 推理访问 | 直接访问 Agent 的 chain of thought |
| 自动拦截 | 在 Hook 中直接阻断 tool 执行 |
| 安全上下文注入 | 直接修改 Agent context |
| 最低延迟 | 同进程调用，无网络开销 |

**适用 Agent**: OpenClaw, Hermes, Nanobot, OpenHands（需要各自适配器）

**优势**: 能力最全, 延迟最低
**劣势**: 需要修改 Agent 代码

### 模式选择指南

| 用户类型 | 推荐模式 | 理由 |
|---------|---------|------|
| 桌面用户，不想改代码 | Mode A (Proxy) | 一键启用，自动防护 |
| 使用 MCP 生态的 Agent | Mode B (MCP) | 无需配置，但防护有限 |
| Agent 开发者 | Mode C (SDK) | 能力最全，延迟最低 |
| 企业部署 | Mode A + Mode C | Proxy 全局覆盖 + SDK 关键路径深度防护 |

## Desktop Application

### 技术栈 (参考 cc-switch)

| 组件 | 技术 | 说明 |
|------|------|------|
| 桌面框架 | Tauri 2 | Rust 后端 + Web 前端，体积小，性能高 |
| 前端 | React + TypeScript + TailwindCSS | 组件化 UI |
| UI 组件 | shadcn/ui | 一致的设计语言 |
| 数据存储 | SQLite (via rusqlite) | 本地数据持久化 |
| 代理服务 | axum + hyper + rustls | 本地 HTTPS 代理 |
| SLM 服务 | Python subprocess / vLLM | 本地模型服务 |
| 国际化 | i18next | 中/英/日 |

### 桌面应用功能

**System Tray**:
- 一键开关防护（Toggle Protection）
- 当前防护状态指示（绿/黄/红）
- 被拦截事件计数
- 快速切换防护模式（observe/enforce）

**Guard Dashboard**:
- 实时安全事件流（最近拦截/警告）
- 风险趋势图（按时间/类型）
- 各 Guard 运行状态（延迟/准确率）
- 会话安全评分

**Policy Editor**:
- 可视化 Guard 配置（模式切换、阈值调整）
- YAML 威胁模式编辑器（带语法高亮和校验）
- 安全上下文 DSL 模板管理
- 防护策略导入/导出

**Threat Explorer**:
- 威胁模式库浏览和搜索
- 攻击示例可视化
- 防护链路展示（哪个 Guard 拦截了什么）
- 红队测试结果

**Integration Panel**:
- Proxy 模式配置（选择 Agent、API endpoint）
- MCP 模式配置（自动注册/注销到 Agent 配置）
- SDK 模式指南（代码片段、安装指引）

**Model Management**:
- SLM 部署/下载管理
- LLM API 配置
- 模型性能监控

### Desktop 与 Security Engine 的交互

```
Tauri Frontend (React)
    │
    │ Tauri IPC (invoke)
    ▼
Tauri Backend (Rust)
    │
    ├── Proxy Server (axum) ──────┐
    │   请求拦截/转发             │
    │                             │
    ├── Config Manager ───────────┤
    │   Agent 配置修改/恢复       │
    │                             │
    ├── SQLite Database ──────────┤
    │   事件存储/策略存储         │
    │                             │
    └── HTTP Bridge ──────────────┤
        调用 Python Security Engine│
                                  │
                                  ▼
                    Python Security Engine (qise-core)
                    Guard Pipeline │ ModelRouter │ ThreatPatternLoader
```

Tauri Rust 后端负责:
1. 代理服务器（高性能 HTTP 代理，拦截 API 流量）
2. Agent 配置管理（修改/恢复配置文件）
3. 桌面 UI 交互（系统托盘、窗口管理）
4. 数据持久化（SQLite 存储事件和策略）

Python Security Engine 负责:
1. Guard Pipeline 执行（AI 模型调用、规则检查）
2. SLM/LLM 推理（需要 Python ML 生态）
3. 威胁模式加载和匹配
4. 基线管理

两者通过 HTTP Bridge 通信（Rust → localhost HTTP → Python），保持解耦。

## Core Interfaces

### GuardContext

All guards receive the same context object, populated by the integration layer:

```python
class GuardContext(BaseModel):
    # What the agent is about to do
    tool_name: str
    tool_args: dict[str, Any]
    trust_boundary: TrustBoundary | None = None

    # Trajectory context (critical for AI understanding)
    session_trajectory: list[dict] = []        # Conversation history summary
    tool_call_history: list[ToolCallRecord] = []  # Prior tool calls this session
    iteration_count: int = 0                    # Loop detection counter

    # Tool metadata (for tool poisoning detection)
    tool_description: str | None = None
    tool_source: str | None = None

    # Agent reasoning (for ReasoningGuard)
    agent_reasoning: str | None = None          # Agent's chain of thought

    # Execution environment
    workspace_path: str | None = None
    session_id: str | None = None
    user_id: str | None = None

    # Integration mode that produced this context
    integration_mode: Literal["proxy", "mcp", "sdk"] = "sdk"

    # Framework-specific data
    framework_metadata: dict[str, Any] = {}
```

不同集成模式填充 GuardContext 的能力:

| 字段 | Proxy Mode | MCP Mode | SDK Mode |
|------|-----------|---------|---------|
| tool_name | ✅ 从 tool_use 解析 | ✅ 用户提供 | ✅ 直接获取 |
| tool_args | ✅ 从 tool_use 解析 | ✅ 用户提供 | ✅ 直接获取 |
| trust_boundary | ✅ 根据来源推断 | ❌ 需用户指定 | ✅ 直接获取 |
| session_trajectory | ✅ 从 messages 解析 | ❌ | ✅ 直接获取 |
| tool_call_history | ⚠️ 从当前会话推断 | ❌ | ✅ 直接获取 |
| agent_reasoning | ⚠️ 从 response 解析 | ❌ | ✅ 直接获取 |
| tool_description | ⚠️ 从 tools 字段获取 | ❌ | ✅ 直接获取 |
| integration_mode | "proxy" | "mcp" | "sdk" |

### GuardResult

Every guard returns a structured result:

```python
class GuardVerdict(str, Enum):
    PASS = "pass"            # No issue detected
    WARN = "warn"            # Suspicious but not blocked (observe mode)
    ESCALATE = "escalate"    # Escalate to LLM deep analysis
    BLOCK = "block"          # Action blocked
    APPROVE = "approve"      # Requires human approval

class RiskAttribution(BaseModel):
    risk_source: str         # e.g., "indirect_injection", "tool_poison"
    failure_mode: str        # e.g., "unauthorized_action", "data_leakage"
    real_world_harm: str     # e.g., "financial_loss", "system_compromise"
    confidence: float        # 0.0-1.0
    reasoning: str           # Model's reasoning (explainability)

class GuardResult(BaseModel):
    guard_name: str
    verdict: GuardVerdict
    confidence: float = 1.0
    message: str = ""
    remediation: str = ""
    risk_attribution: RiskAttribution | None = None
    transformed_args: dict[str, Any] | None = None  # For arg sanitization
    model_used: str | None = None
    latency_ms: int | None = None
    threshold_adjustments: dict[str, float] | None = None  # ReasoningGuard signal
```

### AIGuardBase

The base class for all guards. Even rule-only guards inherit from it (setting `primary_strategy="rules"`):

```python
class AIGuardBase:
    name: str
    primary_strategy: Literal["ai", "rules"] = "ai"
    slm_prompt_template: str
    llm_prompt_template: str | None = None
    rule_fallback: RuleChecker | None = None
    slm_confidence_threshold: float = 0.7

    def check(self, context: GuardContext) -> GuardResult:
        """Three-layer decision: Rule fast-path → SLM → LLM → Rule fallback"""

        # Layer 0: Deterministic rule fast-path (0ms overhead)
        if self.rule_fallback:
            rule_result = self.rule_fallback.check(context)
            if rule_result.verdict in (GuardVerdict.BLOCK, GuardVerdict.PASS):
                return rule_result

        # Layer 1: SLM fast-screen (<50ms)
        try:
            slm_result = self._slm_check(context)
            if slm_result.confidence >= self.slm_confidence_threshold:
                if slm_result.verdict != GuardVerdict.ESCALATE:
                    return slm_result
        except ModelUnavailableError:
            pass  # Degrade to rules

        # Layer 2: LLM deep analysis (<2s)
        if self.llm_prompt_template:
            try:
                return self._llm_check(context)
            except ModelUnavailableError:
                pass

        # Layer 3: Rule fallback (never fail-open)
        if self.rule_fallback:
            return self.rule_fallback.check_safe_default(context)

        return GuardResult(
            guard_name=self.name,
            verdict=GuardVerdict.WARN,
            message="Security models unavailable, applying safe defaults",
        )
```

### Shield (Entry Point)

The `Shield` class is the main entry point. It owns the pipeline, model router, and configuration:

```python
class Shield:
    """Main entry point for Qise security framework."""

    pipeline: GuardPipeline
    model_router: ModelRouter
    context_provider: SecurityContextProvider
    config: ShieldConfig

    @classmethod
    def from_config(cls, path: str | Path) -> "Shield": ...

    async def check(self, context: GuardContext) -> PipelineResult:
        """Run all applicable guards and return aggregate result."""

    async def check_tool_call(self, tool_name: str, tool_args: dict, **kwargs) -> PipelineResult:
        """Convenience method that builds GuardContext and runs check."""

    def get_security_context(self, tool_name: str, tool_args: dict, env: EnvironmentContext) -> str:
        """Get rendered security context for injection into agent observation."""
```

## Pipeline Architecture

Guards are organized into three pipelines, executed in order:

### Ingress Pipeline (Data → Agent)

Runs when external data enters the agent's context:

```
user_input / tool_result / web_content / mcp_response / knowledge_base
    │
    ├── PromptGuard      → detect injection intent in incoming content
    ├── ToolSanityGuard  → detect poisoned tool descriptions
    ├── ContextGuard     → detect memory/KB poisoning + hash integrity
    └── SupplyChainGuard → verify Skill/MCP/KB integrity
```

### Egress Pipeline (Agent → World)

Runs before the agent executes an action:

```
agent_action (tool_call / command / file_write / network_request)
    │
    ├── CommandGuard     → detect dangerous shell commands
    ├── FilesystemGuard  → enforce workspace boundaries
    ├── NetworkGuard     → enforce network policies (SSRF, denylist)
    ├── ExfilGuard       → detect data exfiltration intent
    ├── ResourceGuard    → enforce budgets, detect loops
    └── ToolPolicyGuard  → enforce tool access policies
```

### Output Pipeline (Audit)

Runs after action execution or on agent output:

```
agent_output / tool_response
    │
    ├── CredentialGuard  → detect credentials in output
    ├── AuditGuard       → log events, reconstruct attack chains
    └── OutputGuard      → detect KB content leaks, PII exposure
```

### Pipeline Execution Rules

1. **Short-circuit on BLOCK**: If any guard returns BLOCK, the pipeline stops immediately
2. **Collect WARNs**: All WARN results are collected and returned together
3. **ESCALATE triggers LLM**: A guard returning ESCALATE causes the pipeline to invoke LLM deep analysis
4. **ReasoningGuard is cross-cutting**: It adjusts thresholds of other guards but doesn't block independently

## Model Layer

### ModelRouter

The model router manages connections to SLM, LLM, and embedding models:

```python
class ModelRouter:
    slm_client: OpenAICompatibleClient    # Local SLM, <50ms
    llm_client: OpenAICompatibleClient    # Cloud/local LLM, <2s
    embedding_client: OpenAICompatibleClient  # Vector model, <10ms

    async def slm_check(self, prompt: str) -> ModelResponse: ...
    async def llm_deep_analysis(self, prompt: str, trajectory: list[dict]) -> ModelResponse: ...
    async def similar_attacks(self, embedding: list[float], top_k: int = 5) -> list[ThreatPattern]: ...
```

All clients use the OpenAI-compatible API format, enabling any provider:
- Local: vLLM, Ollama, llama.cpp server
- Cloud: Anthropic, OpenAI, Azure, any OpenAI-compatible endpoint

### Latency Budget

| Path | Guards | Latency | Frequency |
|------|--------|---------|-----------|
| Rule fast-path | A2, A3, A6, C1 | <1ms | ~60% of calls |
| SLM fast-screen | B1-B4, A1, A4, A5, C3, D2 | 30-50ms | ~35% of calls |
| LLM deep analysis | B1-B4, A4, C2 | 1-3s | <5% of calls |

### Model Selection

| Purpose | Recommended Models | Deployment |
|---------|-------------------|------------|
| SLM fast-screen | AgentDoG-Qwen3-4B, Phi-4-mini, custom-trained SLM | Local GPU/CPU |
| LLM deep analysis | Claude Sonnet, GPT-4o-mini, Qwen2.5-72B | Cloud API / Local |
| Embedding retrieval | text-embedding-3-small, bge-large | Local / Cloud |

## Data Layer

### Threat Pattern Loading

```python
class ThreatPatternLoader:
    """Loads YAML threat patterns and makes them available to guards and models."""

    def load_all(self, pattern_dir: Path) -> list[ThreatPattern]: ...
    def get_examples_for_prompt(self, category: str, count: int = 3) -> list[dict]: ...
    def get_rule_signatures(self, category: str) -> list[RuleSignature]: ...
```

### Baseline Management

```python
class BaselineManager:
    """Manages hash baselines for tools, knowledge bases, and memory."""

    def record_tool_baseline(self, tool_name: str, description: str) -> BaselineRecord: ...
    def check_tool_baseline(self, tool_name: str, description: str) -> BaselineCheckResult: ...
    def record_kb_baseline(self, doc_id: str, content: str) -> BaselineRecord: ...
    def check_kb_baseline(self, doc_id: str, content: str) -> BaselineCheckResult: ...
```

## Session Tracking

```python
class SessionTracker:
    """Tracks security state across a session for cross-turn analysis."""

    def record_guard_result(self, result: GuardResult) -> None: ...
    def get_risk_score(self) -> float: ...
    def get_recent_verdicts(self, count: int = 5) -> list[GuardResult]: ...
    def is_under_attack(self) -> bool: ...
```

## Configuration

Qise uses a single `shield.yaml` configuration file (也可通过桌面 UI 可视化编辑):

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
    auto_takeover: true  # 自动修改 Agent API 配置
    crash_recovery: true  # 崩溃时自动恢复配置

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
      mode: observe  # observe | enforce | off
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

### Mode Hierarchy

Each guard can operate in one of three modes:
- **observe**: Log only, never block (recommended for initial deployment)
- **enforce**: Block on high-confidence detections, warn on medium
- **off**: Guard is disabled entirely

Mode can be set per-guard in configuration or through the desktop UI, allowing gradual trust building.
