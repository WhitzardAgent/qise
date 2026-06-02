# Anthropic /v1/messages Proxy 实施计划

## 1. 当前 OpenAI /v1/chat/completions 的完整支持链路

当前 proxy 对 OpenAI 格式的支持涉及 **3 层**：

### 1.1 路由层 (proxy.rs)

```rust
// 只拦截 /v1/chat/completions
const INTERCEPT_PATHS: &[&str] = &["/v1/chat/completions"];
```

所有非 `/v1/chat/completions` 的请求都直接透传，包括 `/v1/messages`。

### 1.2 解析层 (parser.rs)

**请求解析** (`parse_request_for_ingress`):
- 提取 `body.messages[]` → `BridgeMessage { role, content, trust_boundary }`
- 提取 `body.tools[].function` → `BridgeToolDef { name, description }`
- 提取 `body.model`, `body.stream`

**响应解析** (`parse_response_for_egress`):
- 提取 `choices[0].message.tool_calls[]` → `BridgeToolCall { tool_name, tool_args }`
- 提取 `choices[0].message.content` → 文本内容
- 提取 `choices[0].message.reasoning_content` → 推理内容

### 1.3 安全上下文注入 (proxy.rs `inject_security_context`)

在 `messages` 数组中查找/创建 system role message，在末尾追加安全上下文文本。

### 1.4 流式处理 (streaming.rs)

对 OpenAI SSE 流不做分析，直接透传所有 chunk。仅做简单的 tool_call 检测（检查 `delta.tool_calls`）用于日志记录，不做拦截。

---

## 2. OpenAI 格式 vs Anthropic 格式对比

### 2.1 请求结构

| 对比项 | OpenAI | Anthropic |
|--------|--------|-----------|
| 端点 | `/v1/chat/completions` | `/v1/messages` |
| 系统提示 | 在 `messages[0]` 中 role=system | 顶层 `system` 字段（string 或 ContentBlock数组） |
| 用户消息 | `{role:"user", content:"..."}` | `{role:"user", content:"..."}` 或 `{role:"user", content:[{type:"text","text":"..."}]}` |
| 工具定义 | `tools: [{type:"function", function:{name, description}}]` | `tools: [{name, description, input_schema}]` |
| 工具结果 | `{role:"tool", tool_call_id, content:"..."}` | `{role:"user", content:[{type:"tool_result", tool_use_id, content:"..."}]}` |
| 其他字段 | `model`, `stream`, `temperature` | `model`, `stream`, `max_tokens`, `temperature` |

### 2.2 响应结构（非流式）

| 对比项 | OpenAI | Anthropic |
|--------|--------|-----------|
| 根结构 | `{id, object, choices: [...], usage}` | `{id, type:"message", model, content: [...], stop_reason, usage}` |
| 文本内容 | `choices[0].message.content` (string) | `content` 数组中 `type="text"` 的 block |
| 工具调用 | `choices[0].message.tool_calls[]` | `content` 数组中 `type="tool_use"` 的 blocks |
| 推理内容 | `choices[0].message.reasoning_content` | `content` 数组中 `type="thinking"` 的 blocks |

### 2.3 流式响应结构（SSE）

| 对比项 | OpenAI | Anthropic |
|--------|--------|-----------|
| SSE格式 | `data: {...}\n\n` | 带事件类型: `event: message_start\ndata: {...}\n\n` |
| 文本delta | `data: {"choices":[{"delta":{"content":"..."}}]}` | `event: content_block_delta\ndata: {"type":"text_delta","text":"..."}` |
| 工具调用 | 多个delta逐步累积 | `content_block_start`(type:tool_use) → `content_block_delta`(input_json_delta) → `content_block_stop` |
| 结束标志 | `data: [DONE]` | `event: message_stop\ndata: {...}` |

---

## 3. 施工范围与工作量估算

### 3.1 需要修改的文件

| 文件 | 改动量 | 说明 |
|------|--------|------|
| `proxy.rs` | ~40行 | 添加 `/v1/messages` 到 INTERCEPT_PATHS，新增 `handle_anthropic_messages()` |
| `parser.rs` | ~120行 | 新增 Anthropic 请求解析和响应解析两个函数 |
| `streaming.rs` | ~60行 | 新增 Anthropic SSE 流解析（事件类型分发） |
| `decision.rs` | ~0行 | 无需改动，BridgeMessage/BridgeToolCall 结构已足够通用 |

### 3.2 总工作量：约 220 行新增 Rust 代码

施工难度不高，主要是格式映射工作。核心复杂度在于 Anthropic 的 content 数组结构比 OpenAI 更灵活，以及流式 SSE 的事件名格式不同。但核心 Guard 检查逻辑完全不变，直接复用。

### 3.3 不需要改动的地方

- Python Bridge 和 Guard Pipeline：完全不变
- 前端 UI：Claude Code 的 takeover/restore 标记不需要 UI 改动
- 事件模型 (SecurityEvent)：不变
- 配置 (shield.yaml)：用户只需将 upstream_url 指向 Anthropic API 即可

---

## 4. 逐步实施计划

### Step 1: 新增 Anthropic 请求解析器 (parser.rs)

新增函数 `parse_anthropic_request_for_ingress(body: &Value) -> GuardCheckRequest`:

**提取 messages**：
- 遍历 `body.messages[]`
- 如果有顶层 `system` 字段：构造一条 role="system" 的 message 作为首条
- content 字段如果是 string 直接用；如果是 content blocks 数组，拼接 text 类型的 text
- trust_boundary: role="user" → user_input, 带有 tool_result block 的 user → tool_result hilabihan

**提取 tools**：`body.tools[]` → `{ name, description }`

**输出**：标准的 `GuardCheckRequest { type:"request", messages, tools, model, stream }`

### Step 2: 新增 Anthropic 响应解析器 (parser.rs)

新增函数 `parse_anthropic_response_for_egress(body: &Value, model: &str) -> GuardCheckRequest`:

**提取内容**：
- 遍历 `body.content[]`
- type="text" → 追加到 content 字符串
- type="tool_use" → 构造 `BridgeToolCall { tool_name: block.name, tool_args: block.input }`
- type="thinking" → 追加到 reasoning 字符串

### Step 3: 新增 Anthropic 安全上下文注入 (proxy.rs)

新增函数 `inject_security_context_anthropic(body: &mut Value, security_context: &str)`:

- 修改 `body.system` 字段
- 如果不存在，设置为 security_context
- 如果是 string，在后面追加 `\n\n{security_context}`
- 如果是 content blocks 数组，追加一个 text block

### Step 4: 新增 Anthropic 路由处理 (proxy.rs)

新增函数 `handle_anthropic_messages(state, headers, body) -> Response`:

```
1. 解析请求 → GuardCheckRequest
2. 调用 guard_client.check()
3. 如果 BLOCK → 返回 Anthropic 格式的错误响应
   {"type":"error","error":{"type":"permission_error","message":"..."}}
4. 注入安全上下文
5. 如果是 streaming → 转发到上游（SSE 透传）
6. 如果是非流式 → 转发到上游 → 解析响应 → 再次 check → block/warn/pass
```

### Step 5: 注册路由

```rust
const INTERCEPT_PATHS: &[&str] = &["/v1/chat/completions", "/v1/messages"];
```

在 `handle_request()` 中：
```rust
if path == "/v1/messages" && method == Method::POST {
    return handle_anthropic_messages(state, headers, body).await;
}
```

### Step 6: 增强 SSE 流式处理 (streaming.rs)

新增 `process_anthropic_sse_stream()`：

- 解析 Anthropic 的事件命名格式 (`event: xxx\ndata: {...}`)
- 检测 `content_block_start`(type=tool_use) + `content_block_delta`(input_json_delta) + `content_block_stop` 来累积完整的 tool_use
- 不做实时拦截，仅透传 + 记录

---

## 5. 后续增强（不在本次范围）

1. **流式中对 tool_use 的实时拦截** — 需要对累积的完整 tool_use 做 guard check
2. **Anthropic 扩展 block 类型** — thinking、redacted_thinking、search_result 等
3. **Prompt Caching** — cache_control 标记处理
4. **tool_result 注入** — 在 tool_result block 中注入安全上下文

---

## 6. 验证方法

1. **单元测试**：用 `curl` 发送 Anthropic 格式请求到 proxy，验证解析
2. **集成测试**：upstream 指向真实 Anthropic API，发送触发 block 的请求（如含 `rm -rf /` 的 tool_use），验证拦截
3. **流式测试**：`stream: true`，验证 SSE 流正常转发
4. **安全上下文测试**：验证 system 字段被正确追加
5. **回归测试**：确认 OpenAI `/v1/chat/completions` 不受影响
