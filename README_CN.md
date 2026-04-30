<div align="center">

# 🧀 Qise (起司)

**AI-First 的 AI 智能体运行时安全框架**

[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: CC BY-NC-SA 4.0](https://img.shields.io/badge/License-CC%20BY--NC--SA%204.0-green.svg)](LICENSE)
[![Tests: 461+ passed](https://img.shields.io/badge/Tests-461%2B%20passed-brightgreen.svg)](tests/)
[![Guards: 14](https://img.shields.io/badge/Guards-14-orange.svg)](src/qise/guards/)
[![Adapters: 5](https://img.shields.io/badge/Adapters-5-purple.svg)](src/qise/adapters/)
[![Desktop: Tauri 2](https://img.shields.io/badge/Desktop-Tauri%202-blue.svg)](src-tauri/)

[English](./README.md) | 中文

</div>

---

## 概述

Qise（发音 "Cheese" 🧀）是一个开源运行时安全框架，**双向保护** AI 智能体：

- **世界 → 智能体**：拦截提示注入、工具投毒、记忆/知识库篡改、供应链攻击
- **智能体 → 世界**：拦截危险命令、路径穿越、SSRF、数据外泄、策略违规

与仅靠规则、易被绕过的方案不同，Qise 使用**分层 AI 模型**（SLM 快筛 + LLM 深判）理解攻击*意图*，确定性规则作为快速路和兜底——**永不 fail-open**。

## 系统架构

```
Agent (Claude Code / Codex / Gemini CLI / 自定义)
    │
    │ API 请求 (OpenAI 兼容格式)
    ▼
┌─────────────────────────────────────────────────────────┐
│                Tauri 2 桌面应用                          │
│  ┌───────────────────────────────────────────────────┐  │
│  │  系统托盘 │ Guard 仪表盘 │ 配置编辑器           │  │
│  │  Agent 面板 │ 事件日志(WS) │ 状态栏              │  │
│  └───────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────┤
│  Rust 代理 (axum, 端口 8822)                           │
│  • 请求/响应拦截                                        │
│  • SSE 流式透传                                         │
│  • Guard Pipeline 集成                                  │
│  • 代理接管 (环境变量 + 配置文件)                        │
├─────────────────────────────────────────────────────────┤
│  Python Bridge (aiohttp, 端口 8823)                     │
│  • Guard Pipeline 执行                                  │
│  • SLM/LLM 推理 (httpx)                                │
│  • WebSocket 事件推送 (/v1/bridge/events/stream)        │
│  • 7 HTTP 端点 + 1 WS 端点                              │
├─────────────────────────────────────────────────────────┤
│  Guard Pipeline (14 个 Guard)                           │
│  入站: Prompt → ToolSanity → Context → SupplyChain      │
│  出站: Command → FS → Network → Exfil → Resource        │
│  输出: Credential → Audit → Output                       │
│  软防御: SecurityContextProvider + ReasoningGuard         │
├─────────────────────────────────────────────────────────┤
│  模型层                                                  │
│  SLM: Ollama qwen3:4b (本地, <2s)                       │
│  LLM: 云端 API (Claude/GPT/Qwen, <5s)                   │
│  规则: 确定性兜底 (<1ms)                                  │
└─────────────────────────────────────────────────────────┘
    │
    │ 转发请求
    ▼
  上游 LLM API
```

---

## 快速开始

### 1. 安装 Python 引擎

```bash
git clone https://github.com/morinop/qise.git
cd qise
pip install -e ".[dev]"
```

### 2. 一键初始化

```bash
# 生成默认配置
qise init

# 检查工具调用
qise check bash '{"command": "rm -rf /"}'
# → {"verdict": "block", "blocked_by": "command", ...}

qise check bash '{"command": "ls"}'
# → {"verdict": "pass", "blocked_by": null, "warnings": []}

# 列出所有 Guard 及其模式
qise guards
```

### 3. 部署本地 SLM（推荐）

Qise 开箱即用仅依赖规则，但 AI-first Guard 需要 SLM。本地 Ollama 延迟 <2s：

```bash
# 一键安装: 安装 Ollama + 拉取 qwen3:4b (~2.4GB)
chmod +x scripts/setup_slm.sh
./scripts/setup_slm.sh
```

或手动安装：
```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen3:4b
ollama serve
```

然后配置 `shield.yaml`：
```yaml
models:
  slm:
    base_url: "http://localhost:11434/v1"
    model: "qwen3:4b"
    timeout_ms: 5000
```

### 4. 零代码: 代理模式

启动本地 HTTP 代理，拦截 Agent↔LLM 的所有流量：

```bash
# 启动代理服务器
qise proxy start --port 8822 --upstream https://api.openai.com

# 将 Agent 指向代理
export OPENAI_API_BASE="http://localhost:8822/v1"
```

代理实时拦截请求/响应，对所有工具调用、注入尝试和输出泄露运行 14 个 Guard——支持 **SSE 流式透传**，零延迟文本传输。

### 5. 桌面应用（一键安全）

```bash
# 前置: Node.js + Rust
cd src-tauri && cargo tauri dev
```

**功能:**
- **系统托盘**: 一键开关保护，状态指示灯，菜单文本自动切换
- **Guard 仪表盘**: 实时安全事件，模式切换 (observe/enforce/off)
- **配置编辑器**: 可视化 shield.yaml 编辑 (SLM, LLM, Guards, Integration)
- **Agent 面板**: 检测已安装 Agent，一键代理接管 + 崩溃恢复
- **事件日志**: WebSocket 实时推送，All/Blocked/Warnings 过滤
- **状态栏**: 阻断/警告计数，SLM 状态 (local/cloud/unavailable)，延迟

### 6. 零代码: MCP 模式

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

### 7. SDK 模式: 框架适配器

```python
from qise import Shield

# Nanobot
from qise.adapters.nanobot import QiseNanobotHook
shield = Shield.from_config()
hook = QiseNanobotHook(shield)

# LangGraph
from qise.adapters.langgraph import QiseLangGraphWrapper
wrapper = QiseLangGraphWrapper(shield)
safe_tools = [wrapper.wrap_tool_call(tool) for tool in my_tools]

# OpenAI Agents SDK
from qise.adapters.openai_agents import QiseOpenAIAgentsGuardrails
guardrails = QiseOpenAIAgentsGuardrails(shield)
agent = Agent(guardrails=[guardrails.input_guardrail, guardrails.output_guardrail])
```

---

## 为什么选择 Qise

| 问题 | Qise 的方案 |
|------|-----------|
| 关键词规则易被绕过 | AI 理解攻击语义，不仅匹配模式 |
| 单模型瓶颈 | 分层模型: SLM <50ms 快筛 + LLM 深判 |
| 模型不可用时放行 | 规则兜底——**永不 fail-open** |
| 无外泄检测 | ExfilGuard: AI-first 数据外泄检测 |
| 无工具投毒检测 | ToolSanityGuard: 哈希基线 + AI 语义分析 |
| 静态安全指令 | 动态 SecurityContextProvider + Guard 强制执行 |
| 需要改代码 | Proxy/MCP 模式: 零代码集成 |
| 云端 SLM 延迟 14-30s | 本地 Ollama qwen3:4b: <2s/调用 |

## 配置参考 (shield.yaml)

```yaml
version: "1.0"

integration:
  mode: proxy          # proxy | mcp | sdk
  proxy:
    port: 8822
    auto_takeover: true
    crash_recovery: true

models:
  slm:
    base_url: "http://localhost:11434/v1"   # Ollama
    model: "qwen3:4b"
    timeout_ms: 5000
  llm:
    base_url: "https://api.anthropic.com"
    model: "claude-sonnet-4-5"
    timeout_ms: 5000

guards:
  enabled: [prompt, command, credential, reasoning, filesystem, network,
            exfil, resource, audit, tool_sanity, context, output, tool_policy, supply_chain]
  config:
    prompt:
      mode: observe           # observe | enforce | off
      slm_confidence_threshold: 0.7
      skip_slm_on_rule_pass: false
    command:
      mode: enforce
    exfil:
      mode: observe
      skip_slm_on_rule_pass: true
      slm_override_rule_warn_threshold: 0.8
```

环境变量覆盖: `QISE_SLM_BASE_URL`, `QISE_SLM_MODEL`, `QISE_SLM_API_KEY`, `QISE_LLM_BASE_URL`, `QISE_PROXY_PORT`, `QISE_MODE`。

## 开发

```bash
pip install -e ".[dev]"     # 安装开发依赖
pytest tests/ -v             # 运行 461+ 测试
ruff check .                 # 代码检查
ruff format .                # 代码格式化
mypy src/qise               # 类型检查
cd src-tauri && cargo tauri dev    # 运行桌面应用
cd src-tauri && cargo tauri build  # 构建桌面应用
```

## 14 个 Guard 一览

### 入站 Pipeline (世界 → 智能体)

| Guard | 策略 | 检测目标 |
|-------|------|---------|
| **PromptGuard** | AI-first (80/20) | 间接注入、多轮攻击、上下文投毒 |
| **ToolSanityGuard** | AI-first (80/20) | 工具描述投毒、Rug Pull、名称影子 |
| **ContextGuard** | AI+hash (70/30) | 记忆/KB 投毒、数据篡改、哈希完整性 |
| **SupplyChainGuard** | AI+rules (60/40) | 恶意 Skill、MCP 篡改、来源验证 |

### 出站 Pipeline (智能体 → 世界)

| Guard | 策略 | 检测目标 |
|-------|------|---------|
| **ReasoningGuard** | AI-only (100/0) | 推理链操纵痕迹、阈值调整 |
| **CommandGuard** | Rules+AI (70/30) | Shell 注入、危险命令、权限提升 |
| **FilesystemGuard** | Rules (90/10) | 路径穿越、工作区越界、系统目录访问 |
| **NetworkGuard** | Rules (90/10) | SSRF、禁用域名、内网扫描 |
| **ExfilGuard** | AI-first (80/20) | 数据外泄、隐蔽通道、DNS 外泄 |
| **ResourceGuard** | Rules+AI (60/40) | 无限循环、预算超支、熔断器 |
| **ToolPolicyGuard** | Rules (100/0) | 未授权工具访问、拒绝/审批/仅限所有者 |

### 输出 Pipeline (审计)

| Guard | 策略 | 检测目标 |
|-------|------|---------|
| **CredentialGuard** | Rules (100/0) | API Key、密钥、Token 泄露 |
| **AuditGuard** | AI+rules (50/50) | 攻击链重构、会话风险评分 |
| **OutputGuard** | AI+rules (70/30) | PII 暴露、KB 内容泄露 |

## 评估结果

| 指标 | 仅规则 | SLM + 规则 | 变化 |
|------|--------|-----------|------|
| **精确率** | 0.643 | **1.000** | +0.357 |
| **召回率** | 0.973 | **1.000** | +0.027 |
| **F1** | 0.774 | **1.000** | +0.226 |
| **误报率** | 0.400 | **0.000** | +0.400 (越低越好) |

## 许可证

[CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/) — 个人、学术和非商业用途免费。商业用途需另行授权。
