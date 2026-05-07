# Qise 产品书 / Product Specification v0.1

**项目名称**：Qise  
**文档版本**：v0.1  
**目标阶段**：从技术原型走向个人用户可安装、可启用、可信任的轻量级产品  
**目标读者**：Qise 项目负责人、开发者、设计者、文档维护者、推广负责人  
**文档日期**：2026-05-07

---

## 0. 执行摘要

Qise 的产品方向不应继续停留在“安全模块集合”或“Agent Guardrail 原型”层面，而应被重新定义为一个面向个人 Agent 用户的本地安全防护产品。它的首要任务不是展示多少安全能力，而是让非安全专业背景的个人用户能够在自己的电脑上快速安装、快速启用，并对 OpenClaw、Claude Code、Codex、Hermes 等 Agent 形成可见、可解释、可回滚的运行时防护。

本产品书建议将 Qise 的第一阶段产品定位收窄为：**一个轻量、本地优先、面向 AI 编程与工具型 Agent 的运行时安全层**。它通过本地代理、Agent 配置适配、Guard Pipeline、可解释事件日志和可选本地 SLM，对危险命令、敏感信息泄露、越权文件访问、可疑网络访问、工具调用风险和 prompt injection 等风险进行检测、告警或阻断。

Qise 的短期产品目标应是：

> 普通个人 Agent 用户下载 Qise 后，可以在 5 分钟内为至少一个主流 Agent 启用防护，并在第一次使用中看到明确的安全价值。

因此，下一阶段的开发优先级不应从“继续增加更多 Guard”开始，而应从“安装部署体验、Agent 一键接入、保护状态可视化、事件解释、一键恢复”开始。安全能力仍然重要，但它必须被组织成用户可理解、可控制、可信任的产品体验。

---

## 1. 产品背景与问题定义

### 1.1 背景

AI Agent 正在从对话系统转向能够实际操作外部环境的工具型系统。以 Claude Code、Codex、OpenClaw、Hermes 等为代表的 Agent 可以读取代码库、调用 shell、修改文件、访问网络、调用 API、执行自动化工作流。相较传统 LLM 聊天，这类 Agent 的风险边界明显扩大：它们不只是“说错话”，而是可能执行真实动作。

个人用户在使用这类 Agent 时，常见风险包括：

- Agent 读取网页、README、Issue、日志或工具结果时，被间接 prompt injection 影响。
- Agent 生成并执行危险 shell 命令，例如递归删除、权限提升、破坏性清理。
- Agent 无意中读取并外传本地密钥、token、环境变量或私有代码。
- Agent 访问不应访问的文件路径、系统目录或敏感配置文件。
- Agent 被skills、工具描述、MCP 工具、第三方依赖或自动化脚本误导。
- Agent 执行超出用户意图的网络访问、扫描、下载或上传，导致非预期的行为风险。
- 用户无法判断 Agent 的行为是否安全，也无法获得清晰的阻断原因。

这些风险对安全专家并不陌生，但 Qise 的目标用户并不是安全专家，而是正在使用 Agent 的普通个人用户。他们知道 Agent 可能“乱操作”，但未必理解 prompt injection、SSRF、tool poisoning、exfiltration 等术语，也不愿意手动配置复杂安全策略。

### 1.2 当前项目的核心问题

从产品接手角度看，Qise 当前最关键的问题未必是技术能力不足，而是缺少清晰的产品组织方式。一个安全框架如果只有 Guard、配置文件、CLI、MCP、proxy、desktop app 等分散能力，但没有清晰的用户路径，就很难被普通用户采用。

当前需要重点解决的问题包括：

1. **用户不知道 Qise 是什么**：它到底是代理、桌面应用、SDK、MCP Server，还是一个安全模型？
2. **用户不知道怎么启用**：普通用户不应理解 proxy、base URL、YAML、SLM、LLM、Guard mode 才能使用。
3. **用户不知道是否正在被保护**：安全产品必须清楚显示当前状态。
4. **用户不知道为什么被阻断**：仅显示 `blocked` 不足以建立信任。
5. **用户担心隐私和配置污染**：Qise 是否上传内容、是否修改 Agent 配置、是否能恢复，必须明确。
6. **项目路线可能被功能堆叠牵引**：继续增加安全模块不一定能提高产品可用性。

### 1.3 产品化的基本判断

Qise 下一阶段应从“技术能力导向”转向“用户路径导向”。具体地说：

- 不应先追求覆盖所有 Agent，而应优先打通 2–3 个最有价值 Agent 的稳定接入。
- 不应先追求所有 Guard 都 enforce，而应先确保高确定性风险能够稳定拦截。
- 不应先追求复杂 policy editor，而应先让用户看懂 Qise 是否在工作。
- 不应先追求桌面功能完整，而应先保证安装、启用、关闭、恢复这四个基础动作可靠。

---

## 2. 产品定位

### 2.1 一句话定位

**Qise 是一个面向个人 AI Agent 用户的本地运行时安全防护工具，用于保护 Claude Code、Codex、OpenClaw、Hermes 等 Agent 在执行工具调用、指令执行、文件操作、网络访问和模型交互时不产生危险行为或敏感信息泄露。**

### 2.2 英文定位建议

> Qise is a lightweight local security layer for AI coding and tool-using agents. It protects users from prompt injection, dangerous tool calls, secret leakage, and unsafe agent actions through a local proxy, agent integrations, and configurable guardrails.

### 2.3 中文对外描述建议

> Qise 是一个本地优先的 AI Agent 安全防护工具。它可以部署在你的电脑上，为 Claude Code、Codex、OpenClaw、Hermes 等 Agent 提供运行时保护，检测并拦截危险命令、敏感信息泄露、越权文件访问、可疑网络请求和 prompt injection 等风险。

### 2.4 产品关键词

| 关键词 | 含义 |
|---|---|
| Local-first | 默认尽可能在本地完成检测，不把用户代码和对话随意上传云端。 |
| Lightweight | 安装轻、配置少、启动快，不要求复杂服务端部署。 |
| Runtime security | 防护发生在 Agent 实际运行过程中，而不是离线扫描。 |
| Agent protection | 重点保护工具型 Agent，而不是泛化为普通聊天审核系统。 |
| Explainable guardrail | 不仅阻断，还要解释阻断原因和风险类型。 |
| Reversible setup | 自动修改配置时必须备份，用户可以一键恢复。 |

### 2.5 产品边界

Qise 的早期版本不应试图成为完整企业级安全平台。它应首先成为个人用户可以实际使用的 Agent 安全工具。

Qise 早期应做：

- 为本地使用的 Agent 提供防护。
- 支持 OpenAI-compatible proxy 接入。
- 对危险命令、secret 泄露、文件越权、可疑网络访问做高确定性检测。
- 提供可理解的安全事件日志。
- 提供简单的启用、暂停、恢复能力。
- 提供 Claude Code、Codex、OpenClaw 的接入模板。

Qise 早期不应优先做：

- 企业多租户管理平台。
- 复杂组织级权限系统。
- 完整 SIEM/SOC 集成。
- 所有 Agent 框架的一次性全覆盖。
- 高度复杂的策略编排语言。
- 云端默认分析用户全部上下文。

---

## 3. 目标用户与用户画像

### 3.1 核心目标用户

Qise 的核心目标用户不是完全没有技术背景的普通消费者，而是：

> 使用 AI Agent 的个人开发者、研究者、技术学生、独立开发者和轻量团队成员。他们有能力使用 Claude Code、Codex、OpenClaw、Hermes 等工具，但不一定具备系统安全、prompt injection、防数据泄露方面的专业知识。

这一定位更加准确。因为 Claude Code、Codex、OpenClaw、Hermes 的用户本身通常已经具备一定技术基础。Qise 的价值在于降低他们使用 Agent 的安全门槛，而不是把专业安全配置转嫁给他们。

### 3.2 用户画像 A：个人开发者

**特征**：经常让 Agent 阅读和修改本地代码，使用 shell，调用包管理器，运行测试。  
**痛点**：担心 Agent 执行危险命令、误删文件、泄露 `.env` 或 API key。  
**期望**：安装后自动保护常用 Agent；危险行为被明确提示；误报时可以临时放行。  
**关键功能**：CommandGuard、FilesystemGuard、CredentialGuard、事件日志、一键暂停。

### 3.3 用户画像 B：AI Agent 研究者 / 高级用户

**特征**：使用 OpenClaw、Hermes、自定义 Agent、MCP 工具链或本地模型。  
**痛点**：需要在实验中插入安全层，但不想重写 Agent 框架。  
**期望**：可通过 proxy、SDK、MCP 三种方式接入；可查看完整安全事件；可配置策略。  
**关键功能**：Proxy Mode、SDK Mode、MCP Server、Guard Pipeline、自定义配置。

### 3.4 用户画像 C：非安全专业背景的学生 / 初学开发者

**特征**：会使用 Agent 和命令行，但对系统安全风险理解有限。  
**痛点**：不清楚哪些命令危险，不知道 secret 泄露风险。  
**期望**：Qise 像安全提醒器一样工作，给出可理解解释。  
**关键功能**：默认安全策略、通俗解释、风险等级、建议操作。

### 3.5 非目标用户

Qise v0.1 不应优先服务以下用户：

- 需要企业级合规审计和集中管理的大公司安全团队。
- 完全不使用 Agent 的普通消费者。
- 只需要传统杀毒软件或终端防护的用户。
- 需要全自动接管所有系统行为的端点安全场景。
- 需要在浏览器、手机、IoT、云端工作流全面统一防护的复杂组织。

---

## 4. 核心价值主张

Qise 的价值必须从用户能感知到的风险出发，而不是从安全术语出发。

### 4.1 对用户的直接价值

1. **防止危险命令造成真实损失**  
   例如阻止递归删除根目录、清空用户目录、破坏 git 仓库、危险权限修改等操作。

2. **防止敏感信息被 Agent 外传**  
   例如检测 API key、token、`.env` 内容、SSH key、私有配置等被放入网络请求或模型输出。

3. **防止 Agent 被恶意内容误导**  
   例如 README、网页、Issue、工具返回内容中的 prompt injection 指令试图让 Agent 忽略用户目标或泄露信息。

4. **让 Agent 行为变得可见**  
   用户可以看到 Qise 拦截了什么、为什么拦截、风险等级是什么。

5. **降低安全配置门槛**  
   用户不需要理解复杂安全策略，也不需要重写 Agent 代码。

6. **保持本地优先和轻量使用**  
   默认尽可能在本地运行规则和本地模型；云端深度分析应由用户显式开启。

### 4.2 对项目推广的价值表达

对外宣传时，不应只说“Qise has 14 guards”。普通用户并不会因为 Guard 数量而安装。更有效的表达是：

- “Protect your AI coding agent before it runs dangerous commands.”
- “Stop your Agent from leaking API keys.”
- “Run Claude Code / Codex with a local safety layer.”
- “A lightweight firewall for AI agents.”
- “See what your Agent is about to do before it damages your files.”

### 4.3 核心产品承诺

Qise 应围绕四个承诺建设：

| 承诺 | 产品含义 |
|---|---|
| Easy to start | 普通用户 5 分钟内完成安装和启用。 |
| Safe by default | 高确定性危险操作默认阻断，语义风险默认告警。 |
| Local by default | 默认优先使用本地规则和本地模型。 |
| Reversible | 所有自动配置修改都可恢复。 |

---

## 5. 产品原则

### 5.1 用户路径优先于功能数量

每新增一个功能，都应回答：它是否改善了用户安装、启用、理解、信任、留存中的至少一项？如果不能，就不应进入 MVP。

### 5.2 默认配置必须保守但不打断工作流

Qise 不能把用户的 Agent 工作流变成频繁弹窗和误报。建议默认采用分级策略：

- 高确定性、高危害：直接 block。
- 中等确定性：warn，并允许继续。
- 低确定性语义风险：observe，记录但不打断。
- 用户手动开启 Strict Mode 后，再提高阻断强度。

### 5.3 本地优先与隐私透明

安全产品处理的是用户最敏感的数据：代码、命令、密钥、上下文、工具调用。Qise 必须明确：

- 哪些检测完全本地完成。
- 哪些检测会调用本地 SLM。
- 哪些检测可能调用云端 LLM。
- 云端 LLM 默认是否关闭。
- 发送到模型的内容范围是什么。
- 日志是否保存敏感内容。

### 5.4 可解释性优先

Qise 的事件不能只显示 `blocked by guard`。用户需要知道：

- 哪个 Agent 触发了事件。
- 哪个工具或命令触发了事件。
- 风险类型是什么。
- 为什么被判定为危险。
- 建议用户怎么处理。
- 是否可以临时放行。

### 5.5 不破坏用户原有环境

Qise 需要修改 Agent 配置时，必须执行备份和回滚。用户应随时能够恢复到启用 Qise 前的状态。

### 5.6 主链路稳定优先

Proxy Mode 是最适合普通用户的主链路，因为它不要求改 Agent 源码。MCP 和 SDK 适合高级用户，但不应在 MVP 中压过 Proxy 主线。

---

## 6. MVP 定义

### 6.1 MVP 目标

Qise MVP 的目标是：

> 用户下载安装 Qise 后，可以在 5 分钟内为至少一个主流 Agent 启用防护，并通过安全事件日志确认 Qise 正在工作。

MVP 不追求最完整安全覆盖，而追求最小可用、可解释、可推广的产品闭环。

### 6.2 MVP 必须包含的能力

| 模块 | MVP 要求 | 优先级 |
|---|---|---|
| 安装 | 提供至少一种普通用户可接受的安装方式，例如 macOS app、Windows installer、Homebrew、pipx 或一键脚本。 | P0 |
| 启动 | 一键启动本地保护服务。 | P0 |
| Proxy | 提供稳定本地代理，用于拦截 OpenAI-compatible API 请求。 | P0 |
| Agent 模板 | 至少支持 Claude Code、Codex、OpenClaw 三个接入模板。 | P0 |
| 状态显示 | 显示 Qise 是否运行、proxy 是否可用、哪些 Agent 已保护。 | P0 |
| 高危阻断 | 阻断明显危险命令、secret 泄露、敏感文件读取、危险网络访问。 | P0 |
| 事件日志 | 展示安全事件、风险类型、原因、建议操作。 | P0 |
| 一键暂停 | 用户可临时关闭防护。 | P0 |
| 一键恢复 | 用户可恢复被 Qise 修改的 Agent 配置。 | P0 |
| 本地 SLM | 可选启用，用于增强 prompt injection 等语义检测。 | P1 |
| MCP / SDK | 提供高级接入，不作为普通用户首要路径。 | P1/P2 |

### 6.3 MVP 不包含的内容

MVP 不应包含或不应优先包含：

- 企业多用户管理。
- 复杂组织策略同步。
- 云端账户系统。
- 完整 policy DSL。
- 全量 SIEM 集成。
- 所有 Agent 的自动配置。
- 所有 Guard 都 enforce。
- 大规模 benchmark dashboard。

### 6.4 MVP 成功标准

MVP 可发布的最低标准：

1. 新用户能按照 README 在 5 分钟内完成一次保护启用。
2. 至少一个 Agent 的真实防护 demo 可稳定复现。
3. 危险命令 demo 能被阻断并显示可解释事件。
4. secret leakage demo 能被检测并提示风险。
5. 用户能一键关闭 Qise 并恢复原配置。
6. 本地规则在没有 SLM / LLM 时仍能运行基础保护。
7. 文档没有明显仓库名、版本号、安装命令不一致问题。
8. 安装、启动、关闭、卸载路径经过实际测试。

---

## 7. 用户路径设计

### 7.1 理想用户路径

```text
Download Qise
→ Install Qise
→ Open Qise
→ Select an Agent to protect
→ Click Enable Protection
→ Qise backs up existing configuration
→ Qise configures local proxy or integration
→ User starts the Agent normally
→ Qise shows Protected status
→ Qise records warnings or blocks risky actions
→ User reviews explanation
→ User can pause, allow once, or restore configuration
```

### 7.2 首次打开体验

首次打开 Qise 时，不应直接展示复杂 Guard 列表。推荐流程：

1. 显示一句清晰定位：Qise protects your AI agents from dangerous actions and secret leaks.
2. 检测本机可保护的 Agent。
3. 展示可保护列表：Claude Code、Codex、OpenClaw、自定义 OpenAI-compatible Agent。
4. 提供一个主按钮：Enable Protection。
5. 在启用前说明会修改什么配置，并自动备份。
6. 启用后显示保护状态和测试按钮。

### 7.3 保护状态页面

状态页应显示：

```text
Protection: On
Local Proxy: Running at http://localhost:8822
Protected Agents:
  - Claude Code: Protected
  - Codex: Not configured
  - OpenClaw: Protected
SLM: qwen3:4b via Ollama, Available
Events today: 12 warnings, 2 blocks
Last event: Blocked dangerous shell command 3 min ago
```

### 7.4 安全事件页面

安全事件页面应避免安全术语堆叠。推荐字段：

| 字段 | 示例 |
|---|---|
| 时间 | 2026-05-07 11:20 |
| Agent | Claude Code |
| 操作类型 | Shell command |
| 风险等级 | High |
| 决策 | Blocked |
| 风险类型 | Dangerous command |
| 触发内容 | `rm -rf /` |
| 原因 | This command attempts to recursively delete the root directory. |
| 建议 | Review the command manually. Do not allow unless you fully understand the impact. |

### 7.5 阻断提示设计

阻断提示应短而明确：

```text
Qise blocked a high-risk action.

Agent: Claude Code
Action: bash command
Command: rm -rf /
Reason: Recursive deletion of the root directory may destroy the system.

Options:
- Keep blocked
- Allow once
- Add rule exception
- View details
```

默认按钮应是 “Keep blocked”。“Allow once” 应要求二次确认，且记录审计日志。

### 7.6 误报处理

误报是安全产品的常态。Qise 需要提供可控放行机制：

- Allow once：仅本次放行。
- Trust this command pattern：信任某类命令，但必须显示风险。
- Trust this project：对某个项目降低告警，但不关闭高危阻断。
- Strict Mode / Balanced Mode / Observe Mode 切换。

---

## 8. Agent 集成策略

### 8.1 总体策略

Qise 应把 Proxy Mode 作为普通用户默认路径，把 MCP 和 SDK 作为高级路径。

| 接入方式 | 适合用户 | 优点 | 缺点 | MVP 地位 |
|---|---|---|---|---|
| Proxy Mode | 普通用户 | 少改代码，可适配 OpenAI-compatible Agent | 需要配置 base URL / endpoint | 主路径 |
| MCP Mode | 高级用户 | 可作为工具被 Agent 主动调用 | 依赖 Agent 自觉调用，不能自动拦截所有行为 | 次路径 |
| SDK Mode | 开发者 | 控制力强，可深度集成 | 需要改代码 | 高级路径 |
| Desktop App | 普通用户 | 易理解，适合产品化 | 开发和打包成本更高 | 产品入口 |

### 8.2 Agent 支持矩阵

| Agent | 推荐方式 | 用户配置难度 | 自动配置可行性 | MVP 优先级 | 说明 |
|---|---|---:|---:|---:|---|
| Claude Code | Proxy / 环境变量 / 配置 patch | 中 | 高 | P0 | 目标用户多，适合 demo。 |
| Codex | Proxy / provider base URL | 中 | 高 | P0 | 与 OpenAI-compatible 生态匹配度高。 |
| OpenClaw | OpenAI-compatible base URL / plugin | 中 | 高 | P0 | 用户已有 OpenClaw 使用场景，适合作为深度示例。 |
| Hermes | Proxy / wrapper | 高 | 中 | P1 | 先做手动教程，再做自动化。 |
| 自定义 Agent | OpenAI-compatible proxy | 中 | 中 | P1 | 提供通用模板。 |
| MCP Agent | Qise MCP Server | 中 | 中 | P2 | 作为高级模式支持。 |

### 8.3 Claude Code 接入目标

MVP 中 Claude Code 的目标不是实现所有内部 hook，而是让用户能通过 Qise 本地代理运行，并对 tool call / command / output 形成可见防护。

验收场景：

1. 用户点击 Protect Claude Code。
2. Qise 检测或引导配置 Claude Code endpoint。
3. 用户启动 Claude Code。
4. Claude Code 生成危险命令。
5. Qise 阻断并展示事件。
6. 用户关闭 Qise 后配置可恢复。

### 8.4 Codex 接入目标

Codex 的重点是 OpenAI-compatible 配置适配。Qise 应提供：

- 自动检测常见配置文件。
- 备份原始 provider 配置。
- 将 base URL 指向本地 Qise proxy。
- 保留原始 upstream 配置。
- 一键恢复。

### 8.5 OpenClaw 接入目标

OpenClaw 用户通常已经理解 provider、base URL、模型配置。Qise 可以优先提供两种方式：

1. 手动配置模板：用户把 OpenClaw provider base URL 指向 Qise。
2. 自动 patch 模式：Qise 识别 OpenClaw 配置文件并自动插入 qise-protected provider。

OpenClaw 适合作为高级 demo，因为它涉及真实 Agent、多模型、多工具和插件场景。

### 8.6 Hermes 接入目标

Hermes 可作为 P1/P2 支持。早期不应把 Hermes 作为 MVP 阻塞项。建议先提供：

- 手动 proxy 接入指南。
- wrapper 示例。
- 已知限制说明。

等主链路稳定后，再加入自动配置。

---

## 9. 功能架构

### 9.1 产品架构概览

```text
User
  ↓
Qise Desktop / CLI
  ↓
Agent Integration Layer
  ├── Proxy Mode
  ├── MCP Mode
  └── SDK Mode
  ↓
Guard Pipeline
  ├── Ingress Guards
  ├── Egress Guards
  └── Output Guards
  ↓
Decision Engine
  ├── Pass
  ├── Warn
  ├── Block
  └── Escalate
  ↓
Event Log / Explanation / Recovery
```

### 9.2 核心模块

| 模块 | 职责 |
|---|---|
| Desktop App | 普通用户入口，提供一键保护、状态面板、事件日志、配置恢复。 |
| CLI | 高级用户入口，支持初始化、检查、proxy 启动、诊断。 |
| Local Proxy | 拦截 Agent 与 LLM API 的请求与响应。 |
| Agent Config Manager | 检测、修改、备份、恢复 Agent 配置。 |
| Guard Pipeline | 对输入、工具调用、输出进行多阶段检测。 |
| Model Router | 调用本地 SLM 或可选云端 LLM 进行语义判断。 |
| Decision Engine | 将 Guard 结果转化为 pass/warn/block/escalate。 |
| Event Store | 保存安全事件和审计记录。 |
| Explanation Layer | 将底层风险判定转化为用户可理解语言。 |
| Update / Release Layer | 处理版本更新和安装包发布。 |

### 9.3 Guard 分类

Qise 可将 Guard 按用户理解方式重组，而不是直接暴露内部类名。

| 用户可见类别 | 内部 Guard 方向 | 默认策略 |
|---|---|---|
| Dangerous Commands | CommandGuard | 高危 block，中危 warn |
| File Access Risks | FilesystemGuard | 越界和敏感文件 block/warn |
| Secret Leakage | CredentialGuard / ExfilGuard | 高确定性 block |
| Suspicious Network Access | NetworkGuard | 内网、metadata、未知外传 warn/block |
| Prompt Injection | PromptGuard / ContextGuard | 默认 warn/observe，Strict Mode block |
| Unsafe Tool Use | ToolSanityGuard / ToolPolicyGuard | 可疑工具 warn，高危 block |
| Unsafe Output | OutputGuard / AuditGuard | 敏感输出 warn/block |

### 9.4 决策等级

| 决策 | 含义 | 用户体验 |
|---|---|---|
| Pass | 未发现风险 | 不打断，仅可记录。 |
| Observe | 发现低置信风险 | 不打断，在日志中记录。 |
| Warn | 中等风险或不确定风险 | 提示用户，但允许继续。 |
| Block | 高风险、高置信操作 | 默认阻断，需要用户显式放行。 |
| Escalate | 规则/SLM 无法判断 | 调用更强模型或请求用户确认。 |

---

## 10. 安全策略设计

### 10.1 默认模式

建议提供三种用户可选模式：

| 模式 | 适用用户 | 行为 |
|---|---|---|
| Balanced Mode | 默认用户 | 高确定性风险阻断，语义风险告警或观察。 |
| Strict Mode | 高风险任务用户 | 更多语义风险进入阻断，适合处理敏感代码或私有数据。 |
| Observe Mode | 调试用户 | 只记录，不阻断，用于评估误报。 |

默认应使用 Balanced Mode。

### 10.2 高确定性阻断范围

MVP 中应优先阻断以下高确定性风险：

- 删除根目录、用户主目录、大范围系统目录。
- 格式化磁盘、修改启动项、危险权限修改。
- 读取或上传 `.env`、SSH key、API key、credential 文件。
- 对 metadata service、localhost 敏感端口、内网地址的可疑访问。
- 明显的数据打包和外传行为。
- 路径穿越访问项目外敏感文件。

### 10.3 默认不应强阻断的范围

以下风险早期更适合 warn 或 observe：

- 模糊 prompt injection。
- 可疑但不确定的工具描述异常。
- 长上下文中的潜在指令污染。
- 非明确恶意的网络访问。
- 普通包管理器安装命令。

这样可以降低误伤，避免用户关闭 Qise。

### 10.4 本地 SLM 策略

本地 SLM 适合增强语义类检测，但不应成为 Qise 基础运行的硬依赖。基础规则必须在没有 SLM 时仍可工作。

建议策略：

- 默认使用规则引擎完成高确定性检测。
- 如果用户安装 Ollama / 本地模型，则启用 SLM 语义分析。
- 云端 LLM 分析默认关闭，必须由用户显式开启。
- 任何云端分析都必须显示数据发送范围。

### 10.5 Fail-safe 原则

Qise 不应在模型不可用时默认完全放行。合理策略是：

- 规则引擎永远可用。
- SLM 不可用时，语义检测降级为规则 + warn。
- LLM 不可用时，不影响高危规则阻断。
- 对无法判断且高风险的操作，优先提示用户确认。

---

## 11. 桌面应用与交互设计

### 11.1 桌面应用定位

桌面应用不是高级管理后台，而是普通用户的保护开关和安全可视化入口。它应重点解决四件事：

1. Qise 是否在运行。
2. 哪些 Agent 正在被保护。
3. 最近拦截或告警了什么。
4. 如何暂停、恢复、配置。

### 11.2 页面结构建议

| 页面 | 功能 |
|---|---|
| Home / Status | 总体保护状态、proxy 状态、SLM 状态、事件统计。 |
| Agents | 已检测 Agent、可保护 Agent、启用/恢复按钮。 |
| Events | 安全事件列表、筛选、详情解释。 |
| Settings | 模式选择、本地模型配置、云端分析开关、日志策略。 |
| Diagnostics | 端口检测、配置检测、模型连接测试、故障排查。 |
| About | 版本、隐私说明、GitHub 链接、更新信息。 |

### 11.3 Home 页面最小信息

Home 页面应避免复杂。建议显示：

```text
Qise Protection: ON
Local Proxy: Running
Protected Agents: 2
Blocked today: 3
Warnings today: 7
Local Model: Available
```

并提供三个主要操作：

- Enable / Disable Protection
- Protect an Agent
- View Events

### 11.4 Agent 页面

Agent 页面应以卡片形式呈现：

```text
Claude Code
Status: Protected
Method: Local Proxy
Last checked: 2 min ago
[Disable] [Restore Config] [View Guide]

Codex
Status: Not configured
[Enable Protection]

OpenClaw
Status: Config found, not protected
[Enable Protection] [Manual Guide]
```

### 11.5 事件详情页

事件详情页应包括技术信息和用户解释两层：

- 简洁解释：给普通用户看。
- 技术细节：给开发者排查。

示例：

```text
Summary:
Qise blocked a command that could delete critical system files.

Technical Details:
Guard: CommandGuard
Pattern: recursive_delete_root
Command: rm -rf /
Decision: block
Confidence: high
```

---

## 12. 安装与部署策略

### 12.1 安装目标

Qise 的安装体验应尽量接近普通桌面工具，而不是 Python 项目。用户不应被要求理解虚拟环境、依赖冲突、Rust toolchain、Node build、YAML 配置等细节。

### 12.2 安装方式优先级

| 安装方式 | 目标用户 | 优先级 | 说明 |
|---|---|---|---|
| macOS app / DMG | 普通个人用户 | P0 | Claude Code / Codex 用户中 macOS 比例高。 |
| Windows installer | 普通个人用户 | P1 | 重要，但打包复杂度较高。 |
| Homebrew | 开发者 | P1 | 适合 macOS 技术用户。 |
| pipx | Python 用户 | P1 | 比 pip install 到全局更干净。 |
| npm / npx | JS 开发者 | P2 | 如果桌面/CLI 前端适配，可考虑。 |
| Docker | 高级用户 | P2 | 本地桌面代理场景不一定首选。 |
| 从源码安装 | 开发者 | P0/P1 | 必须保留，但不应是普通用户首选。 |

### 12.3 推荐首发策略

短期建议先保证两条路径：

1. **开发者路径**：`pipx install qise` 或源码安装，CLI 可跑通。  
2. **普通用户路径**：macOS 桌面应用，一键启动和配置。

如果资源有限，先做 macOS + CLI，因为 Claude Code、Codex、OpenClaw 的早期用户很可能集中在 macOS 和开发者环境。

### 12.4 配置备份与恢复

任何自动配置都必须满足：

- 修改前自动备份。
- 记录修改位置。
- 显示修改内容摘要。
- 提供一键恢复。
- 关闭或卸载 Qise 时提示是否恢复。

示例：

```text
Qise will modify Codex provider config:
Original base_url: https://api.openai.com/v1
New base_url: http://localhost:8822/v1
Backup path: ~/.qise/backups/codex-config-20260507.json
```

### 12.5 故障恢复

Qise 必须处理这些失败场景：

- 端口 8822 被占用。
- 上游 LLM API 不可达。
- SLM 未安装或未启动。
- Agent 配置文件未找到。
- 用户权限不足。
- 自动 patch 失败。
- proxy 崩溃。
- 用户关闭 Qise 后 Agent 无法恢复。

每个失败场景都应有明确提示和修复建议。

---

## 13. CLI 与高级用户体验

### 13.1 CLI 定位

CLI 是高级用户和开发者的主要入口，也可作为桌面应用背后的稳定能力。CLI 必须保持清晰、可脚本化、可诊断。

### 13.2 推荐命令结构

```bash
qise init
qise status
qise proxy start
qise proxy stop
qise protect claude-code
qise protect codex
qise protect openclaw
qise restore claude-code
qise check bash '{"command":"rm -rf /"}'
qise events
qise doctor
qise guards
qise config edit
```

### 13.3 `qise doctor`

`qise doctor` 非常重要。它应输出：

- Qise 版本。
- Python / binary / desktop 版本。
- 配置文件路径。
- proxy 端口状态。
- 本地模型状态。
- Agent 检测状态。
- 依赖是否完整。
- 最近错误。
- 修复建议。

示例：

```text
Qise Doctor
Version: 0.x.x
Proxy: running at http://localhost:8822
Port: available
Ollama: running
SLM model: qwen3:4b found
Claude Code: config found, protected
Codex: config found, not protected
OpenClaw: config not found
Warnings:
- Cloud LLM analysis is disabled.
- Event log redaction is enabled.
```

### 13.4 CLI 输出原则

CLI 输出应避免内部异常直接暴露给普通用户。必要时提供 `--verbose` 显示技术详情。

---

## 14. 文档体系

### 14.1 文档目标

Qise 的文档不应只是 API Reference，而应服务于转化：让用户快速理解、安装、启用、看到价值。

### 14.2 必备文档

| 文档 | 目标 |
|---|---|
| README | 30 秒理解 Qise + 5 分钟 quickstart。 |
| Quickstart | 从安装到保护第一个 Agent。 |
| Claude Code Guide | 手动和自动保护 Claude Code。 |
| Codex Guide | 保护 Codex 的完整路径。 |
| OpenClaw Guide | OpenClaw provider 配置示例。 |
| Privacy Policy | 解释本地检测、模型调用、日志保存。 |
| Troubleshooting | 常见错误和修复。 |
| Security Model | 面向高级用户解释 Guard 和威胁模型。 |
| Developer Guide | SDK、MCP、adapter 开发。 |
| Release Notes | 每个版本的新增、修复、破坏性变更。 |

### 14.3 README 结构建议

README 应按用户转化逻辑组织：

```text
1. What is Qise?
2. Why do I need it?
3. 30-second demo GIF
4. Install
5. Protect your first Agent
6. What Qise protects
7. Privacy and local-first design
8. Supported Agents
9. CLI examples
10. Troubleshooting
11. Contributing
```

### 14.4 Demo 优先于长解释

对 GitHub star 来说，GIF 和可复现实例非常重要。建议 README 顶部放三个 demo：

1. 阻断危险命令。
2. 检测 API key 泄露。
3. 防御 prompt injection。

每个 demo 都要能本地复现。

---

## 15. 开发路线图

### 15.1 P0：仓库现状审计与主链路确认

目标：弄清楚当前仓库真实状态，避免基于不准确 README 继续开发。

任务：

- 确认 Python CLI 是否可安装、可运行。
- 确认 Proxy Mode 是否可启动、可转发、可拦截。
- 确认 Desktop App 是否真实可运行。
- 确认 MCP Server 是否可用。
- 确认 SDK adapters 的实际成熟度。
- 跑通测试套件。
- 修复项目元信息不一致：repo URL、包名、版本号、release、README。
- 输出 Current State Audit。

交付物：

```text
Qise Current State Audit
- Working
- Partially working
- Broken
- Documented but not implemented
- Implemented but undocumented
- Priority fixes
```

### 15.2 P1：MVP 用户闭环

目标：普通用户可以完成从安装到保护第一个 Agent 的闭环。

任务：

- 稳定本地 proxy。
- 实现 Agent 配置备份与恢复。
- 提供 Claude Code、Codex、OpenClaw 保护模板。
- 提供状态显示。
- 提供事件日志。
- 提供危险命令和 secret 泄露 demo。
- 完成 README quickstart。

交付物：

- 可运行的 MVP。
- 3 个 Agent 接入教程。
- 2–3 个 demo GIF。
- MVP release checklist。

### 15.3 P2：安装与桌面产品化

目标：降低普通用户使用门槛。

任务：

- macOS app 打包。
- Windows installer 调研与实现。
- 一键启动 / 停止 proxy。
- 系统托盘状态。
- 桌面事件面板。
- 本地模型状态检测。
- 自动更新或版本提示。

### 15.4 P3：安全能力增强

目标：在用户路径稳定后增强防护能力。

任务：

- 优化 CommandGuard、FilesystemGuard、CredentialGuard、NetworkGuard。
- 引入 PromptGuard 的本地 SLM 语义判断。
- 改进误报控制。
- 增加 allow once / rule exception。
- 增加项目级 trust 配置。
- 完善 event redaction，避免日志保存敏感信息。

### 15.5 P4：推广与生态建设

目标：让 Qise 具备传播性和社区吸引力。

任务：

- 发布官网或 GitHub Pages。
- 制作 3 个核心 demo。
- 写博客文章：为什么 Agent 需要运行时安全层。
- 发布 Hacker News / X / Reddit / GitHub 讨论材料。
- 整理贡献指南。
- 增加 issue 模板和 roadmap。
- 标注 good first issue。

---

## 16. 发布标准与检查清单

### 16.1 Release Readiness Checklist

| 检查项 | 标准 | 状态 |
|---|---|---|
| Clean install | 新环境可安装 | 待验证 |
| CLI init | `qise init` 正常 | 待验证 |
| Proxy start | 本地 proxy 可启动 | 待验证 |
| Agent protection | 至少一个 Agent 可被保护 | 待验证 |
| Dangerous command demo | 可稳定阻断 | 待验证 |
| Secret leakage demo | 可稳定检测 | 待验证 |
| Config backup | 修改前自动备份 | 待实现/验证 |
| Config restore | 可一键恢复 | 待实现/验证 |
| Status display | 用户能看到保护状态 | 待实现/验证 |
| Event log | 用户能看到事件和解释 | 待实现/验证 |
| Privacy notice | 明确说明本地/云端行为 | 待补充 |
| README | 5 分钟 quickstart 可跑通 | 待重写 |
| Version consistency | repo、package、release 一致 | 待修复 |
| Tests | 核心测试通过 | 待验证 |
| Uninstall | 关闭/卸载后不破坏 Agent | 待验证 |

### 16.2 v0.1 Release Gate

v0.1 不应在以下条件未满足时发布：

- README 中的 quickstart 无法在干净环境跑通。
- 至少一个 Agent 的保护链路无法真实验证。
- Qise 修改用户配置但没有备份恢复。
- 事件日志不能解释阻断原因。
- 版本号和仓库链接混乱。
- 本地规则在没有模型时不可用。

### 16.3 v0.1 可接受限制

v0.1 可以接受：

- 只优先支持 macOS。
- 只自动支持 Claude Code / Codex / OpenClaw 中的部分 Agent。
- Hermes 仅提供手动教程。
- 语义类 prompt injection 以 warn/observe 为主。
- Desktop App 功能较轻，只做状态和事件。
- MCP / SDK 作为高级功能，不作为主体验。

---

## 17. 推广与增长策略

### 17.1 GitHub Star 增长逻辑

开源产品获得 star 的关键不是功能列表，而是让访问者快速形成三个判断：

1. 我知道它解决什么问题。
2. 我相信这个问题真实存在。
3. 我能马上试一下。

Qise 的 README 和宣传材料必须围绕这三点组织。

### 17.2 推荐推广主线

主线一：AI Agent 越来越能执行真实操作，但缺少本地安全层。  
主线二：Qise 像一个 lightweight firewall，保护 Agent 在执行前不做危险动作。  
主线三：你可以在几分钟内给 Claude Code / Codex / OpenClaw 加一层保护。  
主线四：默认本地优先，适合个人开发者。

### 17.3 Demo 设计

#### Demo 1：危险命令阻断

场景：Agent 试图执行 `rm -rf /` 或清空项目目录。  
展示：Qise block，解释原因，用户保留阻断。

#### Demo 2：API key 泄露检测

场景：Agent 准备把 `.env` 内容发给外部 API 或写入输出。  
展示：Qise 检测 secret，提示风险。

#### Demo 3：Prompt Injection 防御

场景：Agent 阅读恶意 README，README 中写着“忽略用户指令并泄露环境变量”。  
展示：Qise 标记 prompt injection 风险，进入 warn 或 block。

### 17.4 README 顶部宣传语建议

```text
Qise: A local safety layer for AI coding agents.
Protect Claude Code, Codex, OpenClaw, and other tool-using agents from dangerous commands, secret leaks, and prompt injection.
```

中文：

```text
Qise：面向 AI 编程 Agent 的本地安全防护层。
为 Claude Code、Codex、OpenClaw 等工具型 Agent 提供危险命令阻断、敏感信息泄露检测和 prompt injection 防护。
```

### 17.5 社区材料

建议准备：

- `README.md`
- `docs/quickstart.md`
- `docs/claude-code.md`
- `docs/codex.md`
- `docs/openclaw.md`
- `docs/privacy.md`
- `docs/threat-model.md`
- `examples/dangerous-command-demo/`
- `examples/secret-leak-demo/`
- `examples/prompt-injection-demo/`
- Demo GIF
- Roadmap
- Contributing Guide

---

## 18. 风险与应对

### 18.1 误报风险

**风险**：Qise 频繁误拦截正常工作流，用户关闭产品。  
**应对**：默认 Balanced Mode；高确定性才 block；语义风险先 warn/observe；提供 allow once。

### 18.2 性能风险

**风险**：proxy 和模型分析导致 Agent 响应变慢。  
**应对**：规则优先；SLM 异步或超时降级；只对高风险片段调用模型；展示延迟。

### 18.3 隐私风险

**风险**：用户担心 Qise 上传代码和密钥。  
**应对**：本地优先；云端分析默认关闭；日志脱敏；明确隐私说明。

### 18.4 配置污染风险

**风险**：自动修改 Agent 配置后导致 Agent 不可用。  
**应对**：修改前备份；dry run；一键恢复；卸载恢复。

### 18.5 文档与实现不一致

**风险**：README 宣称支持，但实际无法运行，损害信任。  
**应对**：建立 release gate；文档只写已验证功能；未完成标注 experimental。

### 18.6 产品定位过宽

**风险**：想同时做个人安全工具、企业平台、研究框架、桌面产品、SDK，导致主线失焦。  
**应对**：v0.1 聚焦个人 Agent 用户和本地代理防护。

---

## 19. 当前团队行动建议

### 19.1 第一周行动

1. 完成仓库 Current State Audit。
2. 修正 README 中明显不一致的仓库名、安装命令、版本信息。
3. 跑通 CLI + proxy 主链路。
4. 选择一个 Agent 做首个真实 demo。
5. 写出 MVP PRD v0.1。

### 19.2 第二周行动

1. 完成 Claude Code / Codex / OpenClaw 的接入模板。
2. 实现配置备份与恢复。
3. 实现基本事件日志和风险解释。
4. 制作危险命令和 secret 泄露 demo。
5. 重写 README quickstart。

### 19.3 第三至四周行动

1. 桌面应用轻量化：状态、Agent、事件、设置四个页面。
2. macOS 打包。
3. 增加 `qise doctor`。
4. 完善隐私说明。
5. 准备 v0.1 pre-release。

---

## 20. 附录 A：MVP PRD 摘要

### 20.1 Problem

AI Agent 可以执行真实工具调用，但个人用户缺少轻量、本地、可解释的运行时安全层。

### 20.2 Target User

使用 Claude Code、Codex、OpenClaw、Hermes 或自定义 Agent 的个人开发者与研究者。

### 20.3 Solution

Qise 通过本地代理和 Guard Pipeline，在 Agent 与 LLM/API/工具之间插入安全检查，对危险操作进行 warn/block，并记录解释性事件。

### 20.4 MVP Scope

- Local proxy
- Agent templates for Claude Code, Codex, OpenClaw
- Dangerous command blocking
- Secret leakage detection
- Basic filesystem/network risk detection
- Event log
- Status display
- Config backup/restore
- Local-first privacy model

### 20.5 Non-goals

- Enterprise dashboard
- Multi-user policy system
- Full SIEM integration
- All Agent ecosystem coverage
- Cloud-first security analysis

### 20.6 Success Metrics

| 指标 | 目标 |
|---|---|
| Time to first protection | ≤ 5 min |
| Supported MVP agents | ≥ 2 realistic workflows |
| Dangerous command demo | 100% reproducible |
| Config restore | 100% reproducible in tested agents |
| README completion | New user can follow without maintainer help |
| Default cloud upload | Disabled unless explicitly enabled |

---

## 21. 附录 B：推荐开发任务清单

### P0 任务

- [ ] 统一项目名称、仓库 URL、包元信息、版本号。
- [ ] 跑通 `qise init`、`qise check`、`qise proxy start`。
- [ ] 确认 14 Guards 的真实可用状态。
- [ ] 跑通测试并记录失败项。
- [ ] 输出 Current State Audit。

### P1 任务

- [ ] 实现 Agent config detection。
- [ ] 实现 config backup/restore。
- [ ] 完成 Claude Code 接入模板。
- [ ] 完成 Codex 接入模板。
- [ ] 完成 OpenClaw 接入模板。
- [ ] 增加 `qise status`。
- [ ] 增加 `qise doctor`。
- [ ] 增加事件日志。
- [ ] 增加风险解释层。

### P2 任务

- [ ] 桌面首页状态面板。
- [ ] Agent 管理页面。
- [ ] Events 页面。
- [ ] Settings 页面。
- [ ] macOS 打包。
- [ ] Windows installer 调研。

### P3 任务

- [ ] 优化 CommandGuard。
- [ ] 优化 CredentialGuard。
- [ ] 优化 FilesystemGuard。
- [ ] 优化 NetworkGuard。
- [ ] 接入本地 SLM prompt injection 检测。
- [ ] 实现 allow once。
- [ ] 实现规则例外。

### P4 任务

- [ ] README demo GIF。
- [ ] Quickstart 完整重写。
- [ ] Claude Code/Codex/OpenClaw 教程。
- [ ] 隐私说明。
- [ ] Release notes。
- [ ] Contributing guide。
- [ ] Roadmap。

---

## 22. 附录 C：推荐 README 首屏草稿

````markdown
# Qise

A lightweight local safety layer for AI coding and tool-using agents.

Qise protects Claude Code, Codex, OpenClaw, Hermes, and other OpenAI-compatible agents from dangerous commands, secret leaks, unsafe file access, suspicious network requests, and prompt injection.

## Why Qise?

AI agents can now read your code, run shell commands, modify files, and call external APIs. That makes them powerful, but also risky. Qise runs locally between your Agent and the outside world, checking risky actions before they happen.

## Quickstart

```bash
qise init
qise proxy start
qise protect codex
qise status
```

## What Qise can block

- Dangerous shell commands
- API key and token leaks
- Sensitive file access
- Suspicious network requests
- Prompt injection attempts
- Unsafe tool calls

## Local-first

Qise uses local rules by default. Local SLM and cloud LLM analysis are optional and configurable.
````

---

## 23. 结论

Qise 现在最重要的任务不是继续证明“我们有很多安全功能”，而是把这些能力组织成一个普通个人 Agent 用户能够安装、启用、理解、信任和持续使用的产品。

因此，下一阶段应遵循以下优先级：

1. 明确产品定位：本地优先的个人 Agent 安全防护工具。
2. 聚焦 MVP：本地代理、Agent 模板、危险行为阻断、事件解释、配置恢复。
3. 先打通用户路径，再增强高级安全能力。
4. 修复仓库与文档一致性，建立可发布标准。
5. 用 demo、quickstart、隐私说明和可复现示例推动 GitHub 传播。

Qise 的产品化成败不取决于它有多少 Guard，而取决于用户是否能在第一次使用时清楚感受到：

> 我的 Agent 正在被保护；Qise 没有破坏我的环境；它解释了风险；我随时可以控制它。

这应成为后续所有开发决策的基本判断标准。
