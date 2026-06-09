<div align="center">

# Qise

**给 AI 编程 Agent 使用的本地优先安全层。**

Qise 可以帮助你在使用 Codex、OpenClaw、Claude Code 以及自定义 Agent 时，增加一层本地安全防护：扫描高风险集成、把模型流量接入本地 Guard Proxy、拦截危险动作，并留下可读的本地安全事件记录。

[English](./README.md) | [快速开始](./docs/quickstart.md) | [安装](./docs/install.md) | [架构](./docs/architecture.md) | [隐私](./docs/privacy.md)

</div>

> [!IMPORTANT]
> 本项目仍处于活跃开发阶段，可能包含尚未发现的缺陷。欢迎通过 Issue 和 PR 提交反馈与贡献。
---

## 从这里开始

Qise 有三个入口：

| 你是 | 建议从哪里开始 | 原因 |
| --- | --- | --- |
| 普通 Agent 用户 | 桌面应用 | 不需要记命令，就可以检测 Agent、开启保护、扫描配置、查看事件。 |
| 终端/CLI 用户 | `qise` CLI | 可以扫描、保护 Agent、查看事件，并把检查流程写进脚本。 |
| Agent 开发者 | SDK / adapters | 可以把 Qise 检查接入 LangGraph、OpenAI Agents SDK、Nanobot、Hermes 或 NexAU。 |

桌面应用和 CLI 使用同一套 Python Qise 产品引擎。UI 不是另一套实现，所以 CLI 和 UI 的保护行为会保持一致。

## Qise 能做什么

AI 编程 Agent 可以读文件、执行 shell 命令、调用 MCP server、安装 skill、使用 memory，并把数据发送给模型 API。这些能力很有用，但也带来了新的本地安全边界：被投毒的工具描述、恶意 skill、提示注入、不安全命令或意外密钥泄露，都可能造成真实的本机风险。

Qise 运行在你的机器上，作为现有 Agent 的旁路防护。它不是模型服务商，也不会替代你正在使用的 Agent。

在常用的 proxy 模式下，调用链是：

```text
AI Agent -> Qise local proxy -> 你原本使用的模型 API
```

Qise 可以：

- 检测 Codex、OpenClaw、Claude Code 等受支持 Agent。
- 在修改 Agent 配置前自动备份。
- 把 Agent 流量接入本地 Guard Proxy。
- 在工具调用真正触达系统前进行检查。
- 阻断危险命令，例如破坏性 shell 操作。
- 对可疑文件、网络、凭据和数据外传行为发出警告或拦截。
- 在信任 skill、MCP config、Agent config 前进行预检扫描。
- 向 Agent/模型请求注入本地安全上下文。
- 记录本地 JSONL 安全事件，包含风险、证据、判定和建议。
- 可选接入本地小模型，通过 Ollama 或其他 OpenAI-compatible endpoint 做第二层语义审查。

Qise 是 local-first 的。默认情况下，产品状态、备份和事件都保存在 `~/.qise/`。事件记录只保存紧凑证据片段，不保存完整模型流量。

## 当前状态

Qise 目前处于 alpha/MVP 阶段。macOS 桌面应用可以在 Mac 上构建，Windows 测试安装包可以通过 GitHub Actions 的 Windows runner 构建。PyPI 发布、安装包签名和正式发布流程仍在完善中。

| 模块 | 当前能力 | 状态 |
| --- | --- | --- |
| 桌面应用 | Tauri 2 + React UI，调用同一套 Qise CLI/产品引擎 | 源码构建 MVP |
| CLI | `doctor`、`status`、`agents`、`scan`、`check`、`events`、`protect`、`restore`、`stop`、`slm`、`run` | MVP 可用 |
| Proxy 防护 | 支持 OpenAI-compatible `/v1/chat/completions` 和 Anthropic `/v1/messages` 的本地 proxy | MVP 可用 |
| Claude Code | 原生 Anthropic Messages proxy，支持请求/响应解析、安全上下文注入和 streaming `tool_use` 检查 | MVP 可用 |
| 预检扫描 | 扫描 skill、MCP config、Agent config 和自动检测到的 Agent 资产 | MVP 可用 |
| Guard 引擎 | 14 类 Guard，覆盖 ingress、egress 和 output 三条流水线 | MVP 可用 |
| 事件日志 | 本地 JSONL 事件，包含风险、证据、判定、建议和 correlation ID | MVP 可用 |
| 本地 SLM | 通过 Ollama 或自定义 OpenAI-compatible endpoint 启用可选语义审查层 | MVP 可用 |
| Runtime Observer | 用户态 wrapper，记录进程、stdout/stderr、文件 diff 和尽力解析的网络证据 | MVP |
| SDK/adapters | Nanobot、Hermes、NexAU、LangGraph 和 OpenAI Agents SDK 适配器 | 开发者 MVP |

## 安装桌面应用

桌面应用是作为产品试用 Qise 的最简单方式。它包含防护状态、Agent 检测、一键保护、预检扫描、事件日志、Guard 规则、本地 SLM、备份恢复、系统诊断和 SDK 片段等页面。

### 方式 A：安装仓库中的预构建应用

仓库使用以下目录保存测试安装包：

```text
installers/
├── macos/
│   └── Qise_0.2.0_aarch64.dmg
└── windows/
    └── Qise_0.2.0_x64-setup.exe
```

macOS：

1. 打开 `installers/macos/Qise_0.2.0_aarch64.dmg`。
2. 把 `Qise.app` 拖到 `Applications`。
3. 打开 `Qise.app`。

如果当前构建还没有经过 Apple 公证，macOS 首次打开可能会拦截。可以右键 `Qise.app`，选择 `打开`，然后确认；也可以在 `系统设置 -> 隐私与安全性` 中允许打开。

Windows：

1. 打开 `installers/windows/` 中的 `Qise_*_x64-setup.exe`。
2. 按安装向导完成安装。
3. 从开始菜单打开 Qise。

Windows 测试安装包尚未签名，因此 Windows SmartScreen 可能显示未知发布者警告。

### 方式 B：从源码构建 macOS App

在终端运行：

```bash
git clone https://github.com/WhitzardAgent/qise.git
cd qise
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev,proxy]"
python -m pip install pyinstaller
npm --prefix src-ui install
src-ui/node_modules/.bin/tauri build
```

每条命令的作用：

| 命令 | 为什么运行它 |
| --- | --- |
| `git clone ...` | 下载 Qise 源代码。 |
| `cd qise` | 进入项目目录。 |
| `python3.11 -m venv .venv` | 创建一个隔离的 Python 环境。 |
| `source .venv/bin/activate` | 让 `python` 和 `pip` 使用这个环境。 |
| `pip install -e ".[dev,proxy]"` | 安装 Qise CLI/产品引擎，以及开发和 proxy 依赖。 |
| `python -m pip install pyinstaller` | 安装用于把 Python Qise runtime 打进桌面应用的工具。 |
| `npm --prefix src-ui install` | 安装 React、Vite、TypeScript 和 Tauri 前端依赖。 |
| `src-ui/node_modules/.bin/tauri build` | 构建内置 Qise runtime、React UI、`.app` 和 `.dmg`。 |

构建成功后，重点看这两个文件：

```text
src-tauri/target/release/bundle/macos/Qise.app
src-tauri/target/release/bundle/dmg/Qise_0.2.0_aarch64.dmg
```

DMG 文件名中的版本号和 CPU 架构可能会变化。Apple Silicon 上通常是 `aarch64`。

安装本地构建版：

1. 打开 `src-tauri/target/release/bundle/dmg/Qise_0.2.0_aarch64.dmg`。
2. 把 `Qise.app` 拖进 `Applications`。
3. 打开 `Qise.app`。

构建过程还会生成内置 CLI runtime：

```text
src-tauri/resources/bin/qise
```

这个二进制文件是构建产物，不应该提交到 Git。

### 方式 C：通过 GitHub Actions 构建 Windows EXE

Windows 安装包必须在 Windows 环境中生成。将项目推送到 GitHub 的 `main` 分支后，`.github/workflows/windows-desktop.yml` 会：

1. 在 GitHub 的 `windows-latest` runner 中安装 Python、Node.js 和 Rust。
2. 使用 PyInstaller 生成内置 `qise.exe` runtime。
3. 使用 Tauri 生成 NSIS `Qise_*_x64-setup.exe`。
4. 上传 Actions artifact。
5. 把安装包自动提交回 `installers/windows/`。

首次使用前，在 GitHub 仓库进入 `Settings -> Actions -> General -> Workflow permissions`，选择 `Read and write permissions`。如果 `main` 有分支保护，还需要允许 GitHub Actions 写入，或者从 Actions 页面手动下载 artifact。

当 Windows workflow 成功并自动提交安装包后，本地运行：

```bash
git pull --ff-only origin main
ls -lh installers/windows
```

普通 GitHub 仓库单个文件限制为 100 MiB。如果安装包超过该大小，应改用 GitHub Releases 或 Git LFS。

### 以开发模式运行桌面应用

适合你正在修改 UI 或快速测试时使用：

```bash
source .venv/bin/activate
npm --prefix src-ui install
src-ui/node_modules/.bin/tauri dev
```

## 第一次使用桌面应用

1. 打开 `Qise.app`。
2. 在首页点击 `Detect Agents`。
3. 进入 `Agent Shield`。
4. 选择 Codex、OpenClaw 或 Claude Code 等 Agent。
5. 检查上游模型 API 地址。
6. 点击 `Protect`。
7. 像平时一样使用你的 Agent。
8. 回到 Qise，打开 `Security Events` 查看告警和拦截记录。

如果保护 Claude Code，请确认 Anthropic key 在环境中可用：

```bash
export ANTHROPIC_API_KEY=sk-ant-...
```

Claude Code 的上游地址通常是：

```text
https://api.anthropic.com
```

如果要撤销 Qise 修改，可以在桌面应用里使用 `Backup & Restore` 或 `Agent Shield`。也可以用 CLI：

```bash
qise restore all
qise stop
```

## 从源码安装 CLI

如果你更喜欢终端，可以把 Qise 安装成 Python 包：

```bash
git clone https://github.com/WhitzardAgent/qise.git
cd qise
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e ".[proxy]"
qise doctor
```

每条命令的作用：

| 命令 | 为什么运行它 |
| --- | --- |
| `git clone ...` | 下载仓库。 |
| `cd qise` | 进入项目目录。 |
| `python3.11 -m venv .venv` | 创建一个干净的 Python 环境。 |
| `source .venv/bin/activate` | 激活这个环境。 |
| `pip install -e ".[proxy]"` | 以 editable 模式安装 Qise，并安装 proxy 运行时依赖。 |
| `qise doctor` | 检查 Python、Qise import、配置、本地端口、事件日志、可选 SLM 和已检测 Agent。 |

如果要开发和跑测试：

```bash
pip install -e ".[dev,proxy]"
```

## 第一次安全 CLI Demo

这个 demo 使用临时目录，不会触碰你真实的 Codex 配置：

```bash
bash ./scripts/demo_mvp.sh
```

它会运行准备状态检查、保护一个 fake Codex 配置、阻断危险命令、打印事件，并恢复临时配置。

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

## 用 CLI 保护真实 Agent

保护的意思是：Qise 会备份你的 Agent 配置，把 Agent 的模型 base URL patch 到本地 Qise proxy，启动 Qise 管理的服务，并记录备份路径，方便之后恢复。

保护真实 Agent 前，请确认：

- 你的 Agent 在不接入 Qise 时已经可以正常工作。
- 模型服务商 API key 仍然存在于 Agent 使用的环境里。
- 如果 Qise 无法从 Agent 配置中推断模型 API base URL，你知道上游模型 API 地址。

保护 Codex：

```bash
qise protect codex
qise status
qise events --limit 10
```

如果 Qise 无法推断上游服务商：

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

Claude Code 相关命令的作用：

| 命令 | 做什么 |
| --- | --- |
| `export ANTHROPIC_API_KEY=...` | 让 Claude Code 和 Qise 管理的 proxy 进程都能读取你的 Anthropic key。 |
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

如果 Qise proxy/protection 已经在运行，修改 SLM 状态后需要重新启动防护：

```bash
qise stop
qise protect codex
```

## SDK 和框架适配器

Qise 也可以接入 Agent 框架内部。这部分主要面向正在开发 Agent 或工具的开发者。

打印集成片段：

```bash
qise adapters
qise adapters langgraph
qise adapters openai-agents
qise adapters nanobot
qise adapters hermes
qise adapters nexau
```

LangGraph 示例：

```python
from qise import Shield
from qise.adapters.langgraph import QiseLangGraphWrapper

shield = Shield.from_config()
wrapper = QiseLangGraphWrapper(shield)
safe_tools = [wrapper.wrap_tool_call(tool) for tool in my_tools]
```

OpenAI Agents SDK 示例：

```python
from qise import Shield
from qise.adapters.openai_agents import QiseOpenAIAgentsGuardrails

shield = Shield.from_config()
guardrails = QiseOpenAIAgentsGuardrails(shield)
agent = Agent(
    name="my-agent",
    guardrails=[guardrails.input_guardrail, guardrails.output_guardrail],
)
```

如果你正在开发 Agent，并希望在工具、输入、输出或框架 hook 周围做进程内检查，使用 adapter。若你希望零代码保护一个现有 OpenAI-compatible Agent 或 Claude Code，则优先使用 proxy 模式。

## 集成模式

| 模式 | 需要写代码吗 | 适合谁 |
| --- | --- | --- |
| 桌面应用 | 0 行 | 希望用可视化控制台的普通用户。 |
| Proxy mode | 0 行 | 可以把模型流量指向本地 base URL 的现有 Agent。 |
| MCP mode | 0 行 | 可以把 Qise 作为 MCP server 调用的 Agent。 |
| SDK mode | 1-5 行 | 正在构建 Agent 框架或自定义工具的开发者。 |

## 项目结构

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

- 当前仓库中的 macOS 和 Windows 安装包均为未签名测试构建。
- Proxy 模式当前主要面向 OpenAI-compatible chat/completions 流量和 Anthropic Messages `/v1/messages` 流量。
- Runtime Observer 是用户态 wrapper，不是 OS/kernel 级审计。
- 本地 SLM 的质量和延迟取决于你选择的模型与服务。
- Windows EXE 由 GitHub Actions 的 Windows runner 生成，不能直接在 macOS 上进行最终安装测试。

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

## License

[CC BY-NC-SA 4.0](./LICENSE) - 免费用于个人、学术和非商业用途。商业使用需要单独授权。
