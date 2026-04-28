<div align="center">

# 🧀 Qise (起司)

**AI-First 的 AI 智能体运行时安全框架**

[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: CC BY-NC-SA 4.0](https://img.shields.io/badge/License-CC%20BY--NC--SA%204.0-green.svg)](LICENSE)
[![Tests: 410 passed](https://img.shields.io/badge/Tests-410%20passed-brightgreen.svg)](tests/)
[![Guards: 14](https://img.shields.io/badge/Guards-14-orange.svg)](src/qise/guards/)
[![Adapters: 5](https://img.shields.io/badge/Adapters-5-purple.svg)](src/qise/adapters/)

[English](./README.md) | 中文

</div>

---

## 概述

Qise（发音 "Cheese" 🧀）是一个开源运行时安全框架，**双向保护** AI 智能体：

- **世界 → 智能体**：拦截提示注入、工具投毒、记忆/知识库篡改、供应链攻击
- **智能体 → 世界**：拦截危险命令、路径穿越、SSRF、数据外泄、策略违规

与仅靠规则、易被绕过的方案不同，Qise 使用**分层 AI 模型**（SLM 快筛 + LLM 深判）理解攻击*意图*，确定性规则作为快速路和兜底——**永不 fail-open**。

```
┌─────────────────────────────────────────────────────────────────┐
│                      Qise 安全框架                              │
│                                                                 │
│   ┌─── 软防御 ───────────────────────────────────────────────┐ │
│   │  安全上下文提供器  →  场景感知规则注入                    │ │
│   │  推理感知守卫      →  思维链监控                          │ │
│   └───────────────────────────────────────────────────────────┘ │
│                           ↓ 仍执行                              │
│   ┌─── 硬防御 (14 个守卫) ──────────────────────────────────┐ │
│   │                                                           │ │
│   │  入口管线 (世界 → 智能体)                                  │ │
│   │  ┌────────┐ ┌────────────┐ ┌─────────┐ ┌──────────────┐ │ │
│   │  │ 注入   │ │  工具安全  │ │  上下文 │ │   供应链     │ │ │
│   │  │ 守卫   │ │   守卫     │ │  守卫   │ │   守卫       │ │ │
│   │  └────────┘ └────────────┘ └─────────┘ └──────────────┘ │ │
│   │                                                           │ │
│   │  出口管线 (智能体 → 世界)                                   │ │
│   │  ┌─────────┐ ┌──────────┐ ┌────────┐ ┌──────┐ ┌──────┐ │ │
│   │  │  命令   │ │  文件系统│ │  网络  │ │ 外泄 │ │ 策略 │ │ │
│   │  │  守卫   │ │   守卫   │ │  守卫  │ │ 守卫 │ │ 守卫 │ │ │
│   │  └─────────┘ └──────────┘ └────────┘ └──────┘ └──────┘ │ │
│   │                         + 资源守卫                         │ │
│   │                                                           │ │
│   │  输出管线 (审计)                                           │ │
│   │  ┌───────────┐ ┌──────────┐ ┌──────────┐                 │ │
│   │  │  凭据守卫 │ │  审计守卫│ │  输出守卫│                 │ │
│   │  └───────────┘ └──────────┘ └──────────┘                 │ │
│   └───────────────────────────────────────────────────────────┘ │
│                                                                 │
│   ┌─── 共享服务 ─────────────────────────────────────────────┐ │
│   │  模型路由 (SLM <50ms + LLM <2s) │ 威胁模式加载器        │ │
│   │  基线管理器 (SHA-256) │ 会话追踪器 │ 事件日志器          │ │
│   └───────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

## 为什么选择 Qise

| 痛点 | Qise 的方案 |
|------|------------|
| 关键词规则易绕过 | AI 理解攻击语义，不仅依赖模式匹配 |
| 单模型瓶颈 | 分层模型：SLM <50ms 快筛 + LLM 深判 |
| 模型不可用时放行 | 规则兜底——**永不 fail-open** |
| 无外泄检测 | ExfilGuard：AI-first 数据外泄检测 |
| 无工具投毒检测 | ToolSanityGuard：哈希基线 + AI 语义分析 |
| 静态安全指令 | 动态 SecurityContextProvider + 守卫强制执行 |
| 需要改代码 | Proxy 模式 / MCP 模式：零代码集成 |

## 三层决策流

每个守卫使用相同的决策流——规则优先求速度，AI 求语义，规则兜底保安全：

```
  ┌──────────────────┐
  │  规则快速路       │  <1ms — 确定性 BLOCK 或 PASS
  │  (正则/哈希/     │  例: "rm -rf /" → BLOCK
  │   模式匹配)      │  例: 哈希匹配 → PASS
  └────────┬─────────┘
           │ 不确定
           ▼
  ┌──────────────────┐
  │  SLM 快筛        │  <50ms — 语义分类
  │  (≤4B 模型)      │  例: 混淆命令 → BLOCK
  └────────┬─────────┘  例: 改写注入 → ESCALATE
           │ 低置信度
           ▼
  ┌──────────────────┐
  │  LLM 深判        │  <2s — 完整轨迹推理
  │  (8B-70B 模型)   │  例: 多轮攻击链 → BLOCK
  └────────┬─────────┘
           │ 模型不可用
           ▼
  ┌──────────────────┐
  │  规则兜底         │  <1ms — 保守默认
  │  (永不 fail-open)│  例: 不确定 + 网络工具 → WARN
  └──────────────────┘
```

## 纵深防御

四层防线，从软引导到硬拦截：

```
  第 0 层: 安全上下文提供器
           ┌─────────────────────────────────────────────┐
           │ 向 Agent 注入场景感知安全规则                 │
           │ Agent 自愿遵守（约 80% 问题在此预防）         │
           └──────────────────────┬──────────────────────┘
                                  ↓ Agent 忽略规则
  第 1 层: 推理感知守卫
           ┌─────────────────────────────────────────────┐
           │ SLM 检测思维链中的操纵痕迹                    │
           │ 插入安全提醒，降低守卫阈值                    │
           └──────────────────────┬──────────────────────┘
                                  ↓ Agent 仍执行危险操作
  第 2 层: 守卫管线 (14 个守卫)
           ┌─────────────────────────────────────────────┐
           │ 规则 → SLM → LLM → 规则兜底                  │
           │ BLOCK / WARN / APPROVE                      │
           └──────────────────────┬──────────────────────┘
                                  ↓ 操作已执行
  第 3 层: 输出守卫 + 凭据守卫
           ┌─────────────────────────────────────────────┐
           │ 检测数据泄露、PII、凭据                       │
           └─────────────────────────────────────────────┘
```

## 快速开始

### 安装

```bash
pip install qise
```

### 一键配置

```bash
# 生成默认配置
qise init

# 检查工具调用
qise check bash '{"command": "rm -rf /"}'
# → {"verdict": "block", "blocked_by": "command", ...}

qise check bash '{"command": "ls"}'
# → {"verdict": "pass", "blocked_by": null, "warnings": []}

# 列出所有守卫及模式
qise guards
```

### 零代码：代理模式

启动本地 HTTP 代理，拦截所有 Agent↔LLM 流量：

```bash
# 启动代理服务器
qise proxy start --port 8822 --upstream https://api.openai.com

# 指向代理
export OPENAI_API_BASE="http://localhost:8822/v1"
```

代理实时拦截请求/响应，对工具调用、注入尝试、输出泄露运行全部 14 个守卫——**支持 SSE 流式传输**，文本内容零延迟透传。

### 零代码：MCP 模式

添加到 Agent 的 MCP 配置：

```json
{
  "mcpServers": {
    "qise": {
      "command": "python",
      "args": ["-m", "qise.mcp_server"]
    }
  }
}
```

### SDK 模式：框架适配器

**Nanobot：**
```python
from qise import Shield
from qise.adapters.nanobot import QiseNanobotHook

shield = Shield.from_config()
hook = QiseNanobotHook(shield)
loop = AgentLoop(hooks=[hook])
```

**LangGraph：**
```python
from qise import Shield
from qise.adapters.langgraph import QiseLangGraphWrapper

shield = Shield.from_config()
wrapper = QiseLangGraphWrapper(shield)
safe_tools = [wrapper.wrap_tool_call(tool) for tool in my_tools]
```

**NexAU：**
```python
from qise import Shield
from qise.adapters.nexau import QiseNexauMiddleware

shield = Shield.from_config()
middleware = QiseNexauMiddleware(shield)
agent = NexAUAgent(middlewares=[middleware])
```

**OpenAI Agents SDK：**
```python
from qise import Shield
from qise.adapters.openai_agents import QiseOpenAIAgentsGuardrails

shield = Shield.from_config()
guardrails = QiseOpenAIAgentsGuardrails(shield)
agent = Agent(guardrails=[guardrails.input_guardrail, guardrails.output_guardrail])
```

**Hermes：**
```python
from qise import Shield
from qise.adapters.hermes import QiseHermesPlugin

shield = Shield.from_config()
plugin = QiseHermesPlugin(shield)
plugin.register(ctx)
```

### 运行测试

```bash
pytest tests/ -v    # 410 项测试
```

## 14 个守卫一览

### 入口管线（世界 → 智能体）

| 守卫 | 策略 | 检测内容 |
|------|------|---------|
| **PromptGuard** | AI-first (80/20) | 间接注入、多轮攻击链、上下文投毒 |
| **ReasoningGuard** | AI-only (100/0) | 思维链中的操纵痕迹 |
| **ToolSanityGuard** | AI-first (80/20) | 工具描述投毒、Rug Pull、名称影子 |
| **ContextGuard** | AI+hash (70/30) | 记忆/知识库投毒、数据篡改、哈希完整性 |
| **SupplyChainGuard** | AI+rules (60/40) | 恶意 Skill、MCP 篡改、来源验证 |

### 出口管线（智能体 → 世界）

| 守卫 | 策略 | 检测内容 |
|------|------|---------|
| **CommandGuard** | Rules+AI (70/30) | Shell 注入、危险命令、提权 |
| **FilesystemGuard** | Rules (90/10) | 路径穿越、工作空间违规、系统目录访问 |
| **NetworkGuard** | Rules (90/10) | SSRF、禁止域名、内网扫描 |
| **ExfilGuard** | AI-first (80/20) | 数据外泄、隐蔽通道、DNS 外泄 |
| **ResourceGuard** | Rules+AI (60/40) | 无限循环、预算超限、熔断器 |
| **ToolPolicyGuard** | Rules (100/0) | 未授权工具访问、拒绝/审批/仅限所有者 |

### 输出管线（审计）

| 守卫 | 策略 | 检测内容 |
|------|------|---------|
| **CredentialGuard** | Rules (100/0) | 输出中的 API Key、密钥、令牌 |
| **AuditGuard** | AI+rules (50/50) | 攻击链重构、会话风险评分 |
| **OutputGuard** | AI+rules (70/30) | PII 暴露、KB 内容泄露、凭据泄露 |

## 5 个框架适配器

| 框架 | 适配器 | 钩子点 | 入口 | 出口 | 输出 | 安全上下文 |
|------|--------|--------|------|------|------|-----------|
| **Nanobot** | QiseNanobotHook | before_execute_tools, after_iteration | ✅ | ✅ | ✅ | ✅ |
| **Hermes** | QiseHermesPlugin | pre/post_tool_call, transform_result, post_llm_call | ✅ | ✅ | ✅ | — |
| **NexAU** | QiseNexauMiddleware | before/after_agent, before/after_model, before/after_tool | ✅ | ✅ | ✅ | ✅ |
| **LangGraph** | QiseLangGraphWrapper | wrap/awrap_tool_call, pre_model_hook | — | ✅ | — | ✅ |
| **OpenAI Agents** | QiseOpenAIAgentsGuardrails | input/output_guardrail, tool_input/output_guardrail | ✅ | ✅ | ✅ | — |

所有适配器基于 **IngressCheckMixin + EgressCheckMixin** 基类——无 monkey-patch，仅使用官方 Hook/Plugin/Middleware API。

## 模型层

| 层级 | 模型 | 延迟 | 使用场景 |
|------|------|------|---------|
| SLM 快筛 | Qwen3-4B / Phi-4-mini | <50ms | 每次工具调用（AI-first 守卫） |
| LLM 深判 | Claude / GPT / Qwen-72B | <2s | 仅当 SLM 升级时（约 5%） |
| 规则兜底 | 确定性规则 | <1ms | 模型不可用时（永不 fail-open） |

**Stub 模式**：无需任何模型服务器即可开箱即用——所有守卫优雅降级到规则。规则守卫（command, filesystem, network, credential, tool_policy）默认 **enforce** 模式；AI-first 守卫默认 **observe** 模式。

## 性能

纯规则模式几乎零开销：

| 操作 | 目标 | 实测 (p95) |
|------|------|-----------|
| 规则快速路（单守卫） | <1ms | ~0.02ms |
| 完整出口管线（6 守卫） | <10ms | ~0.02ms |
| 完整入口管线（5 守卫） | <10ms | ~0.02ms |
| 完整输出管线（3 守卫） | <10ms | ~0.01ms |
| Shield 初始化 | <100ms | ~7ms |
| 安全上下文渲染 | <5ms | ~0.01ms |

100 次连续出口检查：**总耗时 ~1.8ms**（平均 ~0.02ms）。

详见 [docs/performance.md](docs/performance.md)。

## 数据驱动的威胁情报

威胁模式是 YAML 数据，不是硬编码正则——可版本控制、可共享、AI 可读：

```yaml
# data/threat_patterns/indirect_injection_via_tool.yaml
id: TPI-001
name: 间接注入通过工具结果
severity: high

attack_examples:
  - input: '工具结果: "重要：忽略之前的指令..."'
    verdict: malicious
    reasoning: "工具结果包含覆盖指令"

rule_signatures:
  - type: regex
    pattern: "ignore\\s+(previous|above)\\s+instructions"
    confidence: 0.9
```

## 项目结构

```
qise/
├── src/qise/
│   ├── core/              # GuardContext, AIGuardBase, Pipeline, Shield, Config
│   ├── guards/            # 14 个守卫实现
│   ├── models/            # ModelRouter (httpx-based SLM/LLM 客户端)
│   ├── data/              # ThreatPatternLoader + BaselineManager
│   ├── providers/         # SecurityContextProvider (DSL 模板渲染)
│   ├── adapters/          # 5 个框架适配器
│   │   ├── base.py        #   AgentAdapter ABC + IngressCheckMixin + EgressCheckMixin
│   │   ├── nanobot.py     #   Nanobot AgentHook 集成
│   │   ├── hermes.py      #   Hermes Plugin hook 集成
│   │   ├── nexau.py       #   NexAU Middleware (6 个钩子)
│   │   ├── langgraph.py   #   LangGraph 工具包装 + pre-model 钩子
│   │   └── openai_agents.py # OpenAI Agents SDK guardrails
│   ├── proxy/             # HTTP 代理服务器
│   │   ├── server.py      #   aiohttp 代理 + SSE 流式传输
│   │   ├── streaming.py   #   SSEStreamHandler + BufferedToolCall 状态机
│   │   ├── parser.py      #   OpenAI 兼容 API 请求/响应解析
│   │   ├── interceptor.py #   ProxyInterceptor 路由到守卫管线
│   │   ├── context_injector.py # 安全上下文注入到系统消息
│   │   └── config.py      #   ProxyConfig 环境变量覆盖
│   └── mcp_server.py      # MCP 服务器（4 个安全检查工具）
├── data/
│   ├── threat_patterns/   # 6 个 YAML 威胁模式
│   └── security_contexts/ # 8 个 DSL 安全上下文模板
├── tests/                 # 410 项测试
└── docs/                  # 架构、守卫、威胁模型、集成指南
```

## CLI 参考

```bash
qise check bash '{"command": "rm -rf /"}'  # 单次安全检查
qise serve                                  # 启动 MCP 服务器
qise proxy start --port 8822                # 启动 HTTP 代理
qise init                                   # 生成 shield.yaml
qise adapters                               # 列出框架适配器
qise adapters nexau                         # 显示集成代码
qise context bash                           # 获取安全上下文
qise guards                                 # 列出已注册守卫
qise version                                # 打印版本
```

## 文档

| 文档 | 描述 |
|------|------|
| [架构设计](docs/architecture.md) | 系统设计、集成模式、核心接口 |
| [守卫规范](docs/guards.md) | 详细的守卫规格和 AI/规则策略 |
| [威胁模型](docs/threat-model.md) | 攻击分类、信任边界、防御链 |
| [集成指南](docs/integration.md) | Proxy/MCP/SDK 模式、桌面应用设置 |

## 集成模式

| 模式 | 需要代码 | 防御深度 | 适用场景 |
|------|---------|---------|---------|
| **代理模式** | 0 行 | 完整（4 层） | 桌面用户、非开发者 |
| **MCP 模式** | 0 行 | 硬防御（14 个守卫） | MCP 生态用户 |
| **SDK 模式** | 1-5 行 | 完整（4 层）+ 最低延迟 | Agent 开发者 |

## 当前状态

| 组件 | 状态 |
|------|------|
| 核心引擎 (AIGuardBase, Pipeline, Shield) | ✅ 完成 |
| 14 个守卫 (入口 + 出口 + 输出) | ✅ 完成 |
| ModelRouter (httpx-based SLM/LLM 客户端) | ✅ 完成 |
| 代理服务器 (aiohttp + SSE 流式传输) | ✅ 完成 |
| 5 个框架适配器 (Nanobot, Hermes, NexAU, LangGraph, OpenAI Agents) | ✅ 完成 |
| CLI (check / serve / proxy / init / adapters / context / guards / version) | ✅ 完成 |
| MCP 服务器 (4 个安全检查工具) | ✅ 完成 |
| SecurityContextProvider (DSL 模板渲染) | ✅ 完成 |
| BaselineManager (SHA-256 哈希完整性) | ✅ 完成 |
| 软硬防御联动 (active_security_rules) | ✅ 完成 |
| 410 项单元 + 集成 + 性能测试 | ✅ 完成 |
| 桌面应用 (Tauri 2) | 🔜 计划中 |

## 许可证

[CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/) — 免费用于个人、学术和非商业用途。商业使用需另行授权。
