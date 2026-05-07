<div align="center">

# Qise

**给 AI 编程 Agent 使用的轻量本地安全层。**

保护 Codex、OpenClaw 和 OpenAI-compatible Agent，拦截危险命令、密钥泄露、敏感文件访问、可疑网络请求、提示注入和高风险第三方 Skill/MCP。

[English](./README.md) | [快速开始](./docs/quickstart.md) | [安装](./docs/install.md) | [事件](./docs/events.md) | [隐私](./docs/privacy.md)

</div>

---

## 30 秒 Demo

运行一个不会碰真实 Agent 配置的本地 demo：

```bash
git clone https://github.com/opq-qise/qise.git
cd qise
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e ".[proxy]"
./scripts/demo_mvp.sh
```

你会看到 Qise 保护一个临时 Codex 配置、阻断危险命令、写入安全事件，并恢复配置。

## 当前 Qise 能做什么

| 产品面 | 能力 | 当前状态 |
| --- | --- | --- |
| `qise protect codex` | 备份 Codex 配置，接管到本地 Qise proxy，可恢复 | MVP 已验证 |
| `qise scan skill/mcp` | 安装前扫描第三方 Skill 和 MCP 配置 | MVP 已验证 |
| `qise events` | 查看带证据和建议的本地安全事件 | MVP 已验证 |

Qise 不是模型服务商。Proxy 模式下，Qise 位于 Agent 和 Agent 原本使用的模型 API 之间：

```text
Agent -> Qise local proxy -> upstream model API
```

`qise protect codex` 会优先从 Codex 现有配置推断上游模型 API 和 API-key 环境变量。只有推断失败，或者保护自定义 OpenAI-compatible Agent 时，才需要手动传 `--base-url <provider-url>`。

## 安装

第一版 PyPI 发布前，推荐源码安装：

```bash
git clone https://github.com/opq-qise/qise.git
cd qise
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e ".[proxy]"
qise doctor
```

更多安装和排障见 [docs/install.md](./docs/install.md)。

## 快速开始

```bash
qise doctor
qise status
qise scan skill examples/skills/safe
qise scan skill examples/skills/dangerous || true
qise scan mcp examples/mcp-dangerous.json || true
qise check bash '{"command":"rm -rf /"}' || true
qise events --limit 10
```

保护真实 Codex：

```bash
qise protect codex
qise status
qise events --limit 10
qise restore codex
qise stop
```

`protect` 会先备份 Agent 配置，备份保存在 `~/.qise/backups/...`。

## Demo 脚本

```bash
./scripts/demo_mvp.sh   # 使用临时 fake Codex 配置演示 protect/check/events/restore
./scripts/demo_scan.sh  # 扫描安全和危险 fixture
```

两个脚本都会使用临时 `QISE_HOME` 和 `QISE_AGENT_HOME`，可以反复运行。

## Agent 支持状态

| Agent | 命令 | 说明 |
| --- | --- | --- |
| Codex | `qise protect codex` | 当前主验证路径 |
| OpenClaw | `qise protect openclaw` | JSON 配置 patch 已实现，建议用你的真实安装再验收 |
| Custom OpenAI-compatible | `qise protect custom --base-url <url>` | 手动指定上游模型 API |
| Claude Code | `qise protect claude-code --experimental` | 实验支持；Anthropic native `/v1/messages` proxy 尚未完成 |

## 安全事件

```bash
qise events --limit 10
qise events --limit 10 --json
```

事件包含 `id`、`stage`、`source`、`risk.category`、`decision.verdict`、`evidence`、`recommendation` 和 `correlation_id`。

## 本地优先隐私

默认数据目录：

```text
~/.qise/state.json
~/.qise/events.jsonl
~/.qise/backups/
~/.qise/logs/
```

事件只记录紧凑证据片段，不保存完整模型流量。详见 [docs/privacy.md](./docs/privacy.md)。

## 已验证范围

当前 MVP 验证范围是本地 CLI/product 闭环：protect/restore、OpenAI-compatible chat-completions proxy 拦截、preflight scan、可解释事件。OS 级进程观察、桌面 app 打包分发、Claude Code 原生 Anthropic API 拦截属于后续阶段。
