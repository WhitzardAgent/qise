<div align="center">

# Qise

**给 AI 编程 Agent 使用的本地优先安全层。**

Qise 可以帮助你在使用 Codex、OpenClaw、Claude Code 以及自定义 Agent 时，增加一层本地安全防护：扫描集成、把模型流量接入本地 Guard Proxy、拦截高风险动作，并留下可解释的安全事件记录。

[English](./README.md) | [快速开始](./docs/quickstart.md) | [安装](./docs/install.md) | [架构](./docs/architecture.md) | [隐私](./docs/privacy.md)

</div>

---

## Qise 是什么

AI 编程 Agent 可以读文件、执行 shell 命令、调用 MCP server、安装 skill、使用 memory，并把数据发送给模型 API。这些能力很有用，但也带来了新的安全边界：被投毒的工具描述、恶意 skill、提示注入、不安全命令或意外密钥泄露，都可能造成真实的本地风险。

Qise 是为这个边界设计的轻量本地安全层。它不是模型服务商，也不会替代你正在使用的 Agent。它运行在你的机器上，作为现有 Agent 的旁路防护。

在常用的 proxy 模式下，调用链是：

```text
AI Agent -> Qise local proxy -> 你原本使用的模型 API
```

Qise 可以：

- 在工具调用到达系统前进行检查。
- 阻断危险命令，例如破坏性 shell 操作。
- 对可疑文件、网络、凭据和数据外传行为发出警告或拦截。
- 在信任 skill、MCP config、Agent config 前进行预检扫描。
- 向 Agent/模型请求注入本地安全上下文。
- 记录本地 JSONL 安全事件，包含证据和处置建议。
- 可选接入本地小模型，通过 Ollama 或其他 OpenAI-compatible endpoint 做第二层语义审查。
- 同时提供 CLI 和桌面 UI，并复用同一个产品引擎。

Qise 是 local-first 的。默认情况下，产品状态、备份和事件都保存在 `~/.qise/`。事件记录只保存紧凑证据片段，不保存完整模型流量。

## 适合谁使用

如果你有以下需求，可以使用 Qise：

- 正在使用 AI 编程 Agent，希望在命令、文件、网络请求或工具调用真正触达本机前增加一道防线。
- 会安装第三方 skill 或 MCP server，希望启用前先扫描。
- 正在开发 Agent，希望把 Guard 接入 LangGraph、OpenAI Agents SDK 等框架。
- 希望用桌面控制台查看防护状态、预检扫描、事件、Guard 模式、本地 SLM、备份和系统诊断。

## 当前状态

Qise 目前处于 alpha/MVP 阶段。在 PyPI 发布前，推荐从源码安装。

| 模块 | 当前能力 | 状态 |
| --- | --- | --- |
| CLI | `doctor`、`status`、`agents`、`scan`、`check`、`events`、`protect`、`restore`、`stop`、`slm`、`run` | MVP 可用 |
| Proxy 防护 | 支持 OpenAI-compatible `/v1/chat/completions` 流量和 Anthropic `/v1/messages` 流量的本地 proxy | MVP 可用 |
| 预检扫描 | 扫描 skill、MCP config、Agent config 和自动检测到的 Agent 资产 | MVP 可用 |
| Guard 引擎 | 14 个 Guard，覆盖 ingress、egress 和 output 三条流水线 | MVP 可用 |
| 事件日志 | 本地 JSONL 事件，包含风险、证据、判定、建议和 correlation ID | MVP 可用 |
| 本地 SLM | 通过 Ollama 或自定义 OpenAI-compatible endpoint 启用可选语义审查层 | MVP 可用 |
| Runtime Observer | 用户态 wrapper，记录进程、stdout/stderr、文件 diff 和尽力解析的网络证据 | MVP |
| 桌面应用 | Tauri 2 + React UI，调用同一套 Qise CLI | 源码构建 MVP |
| Claude Code | 原生 Anthropic `/v1/messages` proxy，支持请求/响应解析、安全上下文注入和 streaming `tool_use` 检查 | MVP 可用 |

## 项目结构

仓库分为几层：

```text
src/qise/              Python 产品引擎、CLI、proxy、bridge、guards、adapters
src/qise/guards/       Prompt、command、credential、filesystem、network、exfil 等 Guard
src/qise/product/      面向用户的流程：protect、restore、scan、status、doctor、events、SLM
src/qise/proxy/        OpenAI-compatible 与 Anthropic Messages 本地 proxy 和 streaming 支持
src/qise/bridge/       桌面 UI/Guard 控制使用的本地 bridge
src/qise/adapters/     SDK/框架集成片段和适配器
src-ui/                React + TypeScript 桌面前端
src-tauri/             Tauri 2 Rust 桌面外壳和 IPC 命令
src-proxy/             Rust proxy 实验/运行时组件
data/                  威胁模式、安全上下文、prompt 示例
docs/                  更深入的安装、架构、隐私、事件和集成文档
examples/              安全/危险示例 skill、MCP config 和 Agent 示例
tests/                 Guard、proxy、CLI 和产品流程的 Python 测试
```

一个重要设计点是：桌面应用没有另写一套安全引擎。它通过 Tauri IPC 调用同一个 Python `qise` CLI，因此 CLI 和 UI 的行为保持一致。

## 环境要求

CLI 需要：

- Python 3.11 或更新版本。
- 当前 demo 脚本需要 macOS 或 Linux shell。
- 只有在保护真实 Codex/OpenClaw/Claude Code/custom Agent 时，才需要真实 Agent 安装。

从源码运行桌面应用还需要：

- 上面的 CLI 环境。
- Node.js 18 或更新版本。
- Rust stable toolchain。
- 只有构建打包版桌面运行时时，才需要 PyInstaller。

## 从源码安装

在终端运行：

```bash
git clone https://github.com/opq-qise/qise.git
cd qise
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e ".[proxy]"
qise doctor
```

每条命令的作用：

| 命令 | 为什么运行它 |
| --- | --- |
| `git clone ...` | 下载 Qise 源代码。 |
| `cd qise` | 进入项目目录。 |
| `python3.11 -m venv .venv` | 创建一个隔离的 Python 环境。 |
| `source .venv/bin/activate` | 激活环境，让 `python` 和 `pip` 使用这个环境。 |
| `pip install -e ".[proxy]"` | 以 editable 模式安装 Qise，并安装 proxy 运行时依赖。 |
| `qise doctor` | 检查 Python、Qise import、配置、本地端口、事件日志、可选 SLM 和已检测 Agent。 |

如果要开发和跑测试，安装 dev extra：

```bash
pip install -e ".[dev,proxy]"
```

## 第一次安全 Demo

第一次使用建议从这里开始。这个 demo 使用临时目录，不会触碰你真实的 Codex 配置。

```bash
bash ./scripts/demo_mvp.sh
```

这个 demo 会执行：

| 步骤 | 发生什么 |
| --- | --- |
| Doctor | 运行准备状态检查。 |
| Protect fake Codex | 创建并 patch 一个临时 Codex 配置。 |
| Status | 显示 Qise 服务、受保护 Agent、事件路径和 SLM 状态。 |
| Dangerous check | 运行 `qise check bash '{"command":"rm -rf /"}'`，预期 Qise 会阻断。 |
| Events | 打印解释这次阻断的本地安全事件。 |
| Restore | 恢复临时 fake Codex 配置。 |

也可以运行预检扫描 demo：

```bash
bash ./scripts/demo_scan.sh
```

它会扫描一个安全 skill、一个危险 skill 和一个危险 MCP config，然后展示 Qise 记录的事件。

## 手动 CLI 入门

安装完成后，可以用下面这组命令快速感受产品流程：

```bash
qise version
qise doctor
qise status
qise agents
qise scan skill examples/skills/safe
qise scan skill examples/skills/dangerous || true
qise scan mcp examples/mcp-dangerous.json || true
qise check bash '{"command":"rm -rf /"}' || true
qise events --limit 10
```

这些命令的含义：

| 命令 | 做什么 |
| --- | --- |
| `qise version` | 打印当前安装的 Qise 版本。 |
| `qise doctor` | 运行本地诊断，并告诉你缺少什么或哪些配置尚未完成。 |
| `qise status` | 查看服务、已保护 Agent、已检测 Agent、SLM 状态和最近事件数量。 |
| `qise agents` | 检测本机支持的 Agent CLI/config，例如 Codex、OpenClaw 或 Claude Code。 |
| `qise scan skill ...` | 在信任或安装某个 skill 前扫描它的目录或文件。 |
| `qise scan mcp ...` | 扫描 MCP JSON/YAML 配置中的危险命令、暴露环境变量、注入文本和可疑 callback。 |
| `qise check bash ...` | 手动对一次工具调用运行 Guard 流水线检查。示例命令应该被阻断。 |
| `qise events --limit 10` | 以可读格式查看最近的本地安全事件。 |

示例里的 `|| true` 是因为 Qise 遇到 blocking 风险时会用非零退出码表示拦截。对危险测试输入来说，这是预期行为。

机器可读输出：

```bash
qise status --json
qise events --limit 10 --json
qise scan mcp examples/mcp-dangerous.json --json || true
```

## 保护真实 Agent

保护的意思是：Qise 会备份你的 Agent 配置，把 Agent 的模型 base URL patch 到本地 Qise proxy，启动 Qise 管理的服务，并记录备份路径，方便之后恢复。

保护真实 Agent 前，请确认：

- 你的 Agent 在不接入 Qise 时已经可以正常工作。
- 模型服务商 API key 仍然存在于 Agent 使用的环境里，例如 OpenAI-compatible Agent 使用 `OPENAI_API_KEY`，Claude Code 使用 `ANTHROPIC_API_KEY`。
- 如果 Qise 无法从 Agent 配置中推断模型 API base URL，你知道上游模型 API 地址。

保护 Codex：

```bash
qise protect codex
qise status
qise events --limit 10
```

会发生什么：

| 命令 | 做什么 |
| --- | --- |
| `qise protect codex` | 定位 Codex 配置，尽量推断原始上游 API，在 `~/.qise/backups/codex/...` 创建备份，把 Codex patch 到 Qise proxy，并启动 proxy/bridge 服务。 |
| `qise status` | 确认哪些 Agent 处于保护状态，以及备份、配置、事件文件在哪里。 |
| `qise events --limit 10` | 查看 scan、proxy、CLI check 或 Runtime Observer 产生的最近拦截/告警。 |

如果 Qise 无法推断上游服务商，手动传入：

```bash
qise protect codex --base-url https://api.openai.com/v1
```

保护 OpenClaw：

```bash
qise protect openclaw
```

保护 Claude Code：

```bash
export ANTHROPIC_API_KEY=sk-ant-...
qise protect claude-code --base-url https://api.anthropic.com
qise status
```

会发生什么：

| 命令 | 做什么 |
| --- | --- |
| `export ANTHROPIC_API_KEY=...` | 让 Claude Code 和 Qise 管理的 proxy 进程都能读取你的 Anthropic key。如果你已经使用 `apiKeyHelper`，可以继续使用；Qise 也会保留 Claude Code 请求里带来的 key。 |
| `qise protect claude-code --base-url https://api.anthropic.com` | 备份 `~/.claude/settings.json`，把 `env.ANTHROPIC_BASE_URL` 设置为本地 Qise proxy，记录原始 Anthropic upstream，并启动 Qise 服务。 |
| `qise status` | 确认 Claude Code 已受保护，并查看备份路径。 |

保护自定义 OpenAI-compatible Agent：

```bash
qise protect custom --base-url https://api.openai.com/v1
```

对 custom Agent，Qise 会启动 proxy 并打印本地 proxy URL。把你的 Agent base URL 指向：

```text
http://127.0.0.1:8822/v1
```

恢复和停止：

```bash
qise restore codex
qise restore all
qise stop
```

| 命令 | 做什么 |
| --- | --- |
| `qise restore codex` | 从 Qise 备份记录恢复 Codex 配置。 |
| `qise restore all` | 恢复所有当前记录为被 Qise 保护过的 Agent。 |
| `qise stop` | 停止 Qise 管理的 proxy 和 bridge 后台服务。 |

恢复后，Qise 仍会把备份保留在 `~/.qise/backups/`，方便你检查前后差异。

## CLI 命令地图

| 命令 | 适合什么时候用 |
| --- | --- |
| `qise init` | 生成本地 `shield.yaml` 配置文件。 |
| `qise doctor` | 诊断本机准备状态。 |
| `qise status` | 查看服务、防护、SLM、Agent 和事件状态。 |
| `qise agents` | 检测已安装的受支持 Agent。 |
| `qise protect <agent>` | 备份并把 Agent 接入 Qise。 |
| `qise restore <agent|all>` | 恢复被 Qise 修改过的 Agent 配置。 |
| `qise stop` | 停止 Qise 管理的后台服务。 |
| `qise scan all` | 自动扫描检测到的 Agent 资产。 |
| `qise scan agent <agent>` | 扫描某个 Agent 的配置、skill 文件和 MCP 候选配置。 |
| `qise scan skill <path>` | 扫描 skill 目录或文件。 |
| `qise scan mcp <path>` | 扫描 MCP JSON/YAML 配置。 |
| `qise scan agent-config <agent>` | 检查已安装 Agent 配置是否接入 Qise，以及是否与 Qise 状态一致。 |
| `qise check <tool> <json>` | 手动运行一次 Guard 流水线检查。 |
| `qise events` | 读取本地安全事件。 |
| `qise slm start/status/stop` | 配置或禁用可选本地 SLM 审查层。 |
| `qise run --agent <name> -- <cmd>` | 在 Runtime Observer 下运行命令。 |
| `qise guards` | 列出已注册 Guard、流水线、策略和模式。 |
| `qise context <tool>` | 预览某个工具对应的安全上下文文本。 |
| `qise proxy start` | 手动启动本地 OpenAI-compatible/Anthropic proxy。 |
| `qise bridge start` | 启动桌面/Guard 控制流程使用的本地 bridge。 |
| `qise serve --transport stdio` | 以 MCP server 形式启动 Qise。 |
| `qise adapters <name>` | 打印支持框架的 SDK 集成片段。 |

## Guard 流水线

Qise 通过三条流水线运行检查：

| 流水线 | 方向 | 示例风险 |
| --- | --- | --- |
| Ingress | 外部世界到 Agent | 提示注入、工具投毒、上下文投毒、供应链指令。 |
| Egress | Agent 到外部世界 | 危险 shell 命令、不安全文件访问、风险网络调用、数据外传、资源滥用、工具策略违规。 |
| Output | Agent 到用户/日志 | 凭据泄露、敏感输出、审计信号。 |

当前 Guard 集合包括：

| Guard | 主要用途 |
| --- | --- |
| `prompt` | 检测直接和间接提示注入。 |
| `tool_sanity` | 检测被投毒或可疑的工具描述。 |
| `context` | 检测 memory/knowledge-base 投毒模式。 |
| `supply_chain` | 检测高风险 skill、MCP server 和供应链资产。 |
| `command` | 阻断危险 shell 命令和命令注入模式。 |
| `filesystem` | 保护 workspace/path 边界和系统路径。 |
| `network` | 对可疑域名、类似 SSRF 的目标和风险网络访问进行告警/阻断。 |
| `exfil` | 检测可能的数据外传。 |
| `resource` | 检测资源滥用模式。 |
| `tool_policy` | 执行配置的工具 allow/deny 策略。 |
| `credential` | 检测输出或工具数据中的 secret/credential。 |
| `audit` | 记录审计型告警信号。 |
| `output` | 检查最终输出中的敏感或高风险内容。 |
| `reasoning` | 在可用时，对模型/工具推理信号进行可选语义审查。 |

低误报的 rules-first Guard 默认是 `enforce`。AI-first Guard 默认是 `observe`，除非你启用并调优本地 SLM 层。

## 可选本地 SLM

Qise 默认可以只靠规则运行。SLM 层用于补充语义审查，处理单纯规则不容易覆盖的场景。

启动默认本地 SLM 设置：

```bash
qise slm start
qise slm status
```

默认情况下，Qise 使用本机 Ollama 的 `http://localhost:11434/v1` 和 `qwen3:4b`。首次运行时，如果缺少 Ollama 或模型，Qise 可以尝试自动安装和拉取。

使用其他模型：

```bash
qise slm start --model llama3.2:3b
```

使用自定义 OpenAI-compatible SLM endpoint：

```bash
qise slm start --base-url http://localhost:8000/v1 --model my-security-model
```

禁用 Qise SLM 配置：

```bash
qise slm stop
```

禁用 Qise SLM 配置，但保持模型服务运行：

```bash
qise slm stop --keep-server
```

如果 Qise proxy/protection 已经在运行，修改 SLM 状态后需要重新启动防护：

```bash
qise stop
qise protect codex
```

## Runtime Observer

Runtime Observer 是轻量用户态 wrapper。它会记录运行的命令、进程证据、stdout/stderr 摘要、工作目录文件变化、尽力解析的网络 endpoint，以及可把 runtime/proxy 证据串起来的 `correlation_id`。

示例：

```bash
qise run --agent codex -- codex
qise events --stage runtime --limit 10
```

指定工作目录：

```bash
qise run --agent codex --cwd /path/to/project -- codex
```

它不是内核级审计，而是用较低配置成本提供有用的本地运行证据。

## 桌面应用

桌面应用是 Tauri 2 + React + TypeScript，对同一套 Qise CLI 做可视化封装。

它包含这些页面：

- Home status 和已检测 Agent。
- Agent Shield：保护、恢复和停止 Qise 服务。
- Preflight Scan：扫描全部 Agent、单个 Agent、skill 路径、MCP config 或 Agent config。
- Security Events：查看最近本地事件。
- Protection Rules：在 bridge 运行时查看和调整 Guard 模式。
- Local SLM：启动、停止和检查可选模型层。
- System Doctor：可视化运行准备状态诊断。
- Runtime Observer：生成 `qise run` 命令并查看 runtime 事件。
- Backup & Restore：查看备份位置并恢复修改过的配置。
- Integrations：加载 Nanobot、Hermes、NexAU、LangGraph 和 OpenAI Agents SDK 的 adapter 片段。
- Settings 和 Advanced Lab：编辑配置，并手动运行 Guard/context 检查。

以开发模式运行桌面应用：

```bash
pip install -e ".[dev,proxy]"
npm --prefix src-ui install
src-ui/node_modules/.bin/tauri dev
```

每条命令的作用：

| 命令 | 为什么运行它 |
| --- | --- |
| `pip install -e ".[dev,proxy]"` | 让桌面 shell 可以调用 Python `qise` CLI，并安装开发/测试依赖。 |
| `npm --prefix src-ui install` | 安装 React、Vite、TypeScript、Tailwind 和 Tauri CLI 前端依赖。 |
| `src-ui/node_modules/.bin/tauri dev` | 启动 Tauri 桌面外壳；配置里的 `beforeDevCommand` 会启动 Vite UI server。 |

从源码构建打包版桌面应用：

```bash
pip install -e ".[dev,proxy]"
python -m pip install pyinstaller
npm --prefix src-ui install
src-ui/node_modules/.bin/tauri build
```

Tauri build 会运行 `scripts/build-desktop-runtime.sh`，把 Python Qise runtime 打包到 `src-tauri/resources/bin/qise`，然后构建 React 前端和桌面安装包。

如果你已经有独立的 Qise binary，可以让桌面应用使用它：

```bash
export QISE_BINARY=/path/to/qise
```

## SDK 和框架适配器

Qise 也可以接入 Agent 框架内部。打印集成片段：

```bash
qise adapters
qise adapters langgraph
qise adapters openai-agents
qise adapters nanobot
qise adapters hermes
qise adapters nexau
```

如果你正在开发 Agent，并希望在工具、输入、输出或框架 hook 周围做进程内检查，使用 adapter。若你希望零代码保护一个现有 OpenAI-compatible Agent 或 Claude Code，则优先使用 proxy 模式。

## 配置

Qise 可以直接用默认配置运行，也可以生成配置文件：

```bash
qise init
```

这会在当前目录创建 `shield.yaml`。你可以用它配置 proxy、模型 endpoint、数据路径、日志和 Guard 模式。

常用环境变量：

| 变量 | 用途 |
| --- | --- |
| `QISE_HOME` | 覆盖 Qise 状态目录。默认是 `~/.qise`。 |
| `QISE_AGENT_HOME` | 测试/demo 时覆盖 Agent home/config 查找路径。 |
| `QISE_PROXY_UPSTREAM_URL` | Proxy 模式的上游模型 API base URL。 |
| `QISE_PROXY_UPSTREAM_API_KEY` | 传给 Qise proxy 的上游模型 API key。 |
| `OPENAI_API_BASE` | fallback 上游 base URL。 |
| `OPENAI_API_KEY` | Agent 和 Qise 常用的模型服务商 API key 环境变量。 |
| `ANTHROPIC_BASE_URL` | Claude Code 或原生 Anthropic client 使用的 Anthropic 上游 base URL。 |
| `ANTHROPIC_API_KEY` | Anthropic API key。Qise 会在 `/v1/messages` 转发时作为 `X-Api-Key` 发送。 |
| `ANTHROPIC_AUTH_TOKEN` | Anthropic auth token。Qise 会在 `/v1/messages` 转发时作为 `Authorization: Bearer ...` 发送。 |
| `QISE_SLM_BASE_URL` | 覆盖 SLM endpoint。 |
| `QISE_SLM_MODEL` | 覆盖 SLM 模型名。 |
| `QISE_BINARY` | 桌面应用使用的 Qise 可执行文件路径。 |

## Qise 创建的本地文件

默认位置：

```text
~/.qise/state.json       # 当前服务、受保护 Agent、SLM 状态
~/.qise/events.jsonl     # 本地安全事件
~/.qise/backups/         # patch Agent 配置前创建的备份
~/.qise/logs/            # Qise 管理的 proxy/bridge stdout 和 stderr 日志
```

常用查看命令：

```bash
qise status
qise events --limit 20
ls ~/.qise/backups
```

## 常见问题

`qise doctor` 提示 "Proxy upstream is not configured yet."

在保护真实 Agent 之前，这是正常的。只有当 Qise 要转发模型流量时，才需要上游模型 API。可以使用：

```bash
qise protect codex --base-url https://api.openai.com/v1
```

`qise protect codex` 无法推断 provider。

手动传入上游地址：

```bash
qise protect codex --base-url https://api.openai.com/v1
```

`qise protect claude-code` 无法推断 Anthropic upstream。

手动传入：

```bash
qise protect claude-code --base-url https://api.anthropic.com
```

Qise 修改了 Agent 配置，你想撤销。

```bash
qise restore all
qise stop
```

桌面应用找不到 Qise。

先确认同一个 shell 里 CLI 可用：

```bash
qise version
```

必要时设置：

```bash
export QISE_BINARY=/path/to/qise
```

扫描命令返回非零退出码。

这通常表示 Qise 找到了 blocking 问题。可以用 `--json` 查看结构化细节，或查看最新事件：

```bash
qise events --limit 5
```

## 当前限制

- 在包发布完成前，源码安装是主要支持路径。
- Proxy 模式当前主要面向 OpenAI-compatible chat/completions 流量和 Anthropic Messages `/v1/messages` 流量。
- Runtime Observer 是用户态 wrapper，不是 OS/kernel 级审计。
- 当前 MVP 的桌面应用以源码构建为主。
- 本地 SLM 的质量和延迟取决于你选择的模型与服务。

## 了解更多

- [安装](./docs/install.md)
- [快速开始](./docs/quickstart.md)
- [架构](./docs/architecture.md)
- [Guards](./docs/guards.md)
- [Codex 集成](./docs/codex.md)
- [OpenClaw 集成](./docs/openclaw.md)
- [Claude Code 集成](./docs/claude-code.md)
- [预检扫描](./docs/preflight-scan.md)
- [事件](./docs/events.md)
- [Runtime Observer](./docs/runtime-observer.md)
- [故障排查](./docs/troubleshooting.md)
- [隐私](./docs/privacy.md)
