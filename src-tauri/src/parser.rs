//! Request/response parser — extracts guard-relevant data from JSON bodies.

use crate::decision::{BridgeMessage, BridgeToolCall, BridgeToolDef, GuardCheckRequest};
use serde_json::Value;

/// Parse a chat completion request body into a GuardCheckRequest for ingress checks.
pub fn parse_request_for_ingress(body: &Value) -> GuardCheckRequest {
    let messages = parse_messages(body);
    let tools = parse_tools(body);
    let model = body.get("model").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let stream = body.get("stream").and_then(|v| v.as_bool()).unwrap_or(false);

    GuardCheckRequest {
        r#type: "request".into(),
        messages,
        tools,
        tool_calls: vec![],
        content: String::new(),
        reasoning: String::new(),
        model,
        stream,
    }
}

/// Parse a chat completion response body into a GuardCheckRequest for egress/output checks.
pub fn parse_response_for_egress(body: &Value, model: &str) -> GuardCheckRequest {
    let tool_calls = parse_response_tool_calls(body);
    let content = parse_response_content(body);
    let reasoning = parse_response_reasoning(body);

    GuardCheckRequest {
        r#type: "response".into(),
        messages: vec![],
        tools: vec![],
        tool_calls,
        content,
        reasoning,
        model: model.to_string(),
        stream: false,
    }
}

/// Extract messages from request body.
fn parse_messages(body: &Value) -> Vec<BridgeMessage> {
    let Some(messages_arr) = body.get("messages").and_then(|v| v.as_array()) else {
        return vec![];
    };

    messages_arr
        .iter()
        .filter_map(|msg| {
            let role = msg.get("role")?.as_str()?.to_string();
            let content = msg
                .get("content")
                .and_then(|v| {
                    if v.is_string() {
                        v.as_str().map(|s| s.to_string())
                    } else if v.is_array() {
                        let texts: Vec<String> = v
                            .as_array()?
                            .iter()
                            .filter_map(|part| {
                                if part.get("type")?.as_str()? == "text" {
                                    part.get("text")?.as_str().map(|s| s.to_string())
                                } else {
                                    None
                                }
                            })
                            .collect();
                        Some(texts.join("\n"))
                    } else {
                        None
                    }
                })
                .unwrap_or_default();

            let trust_boundary = match role.as_str() {
                "user" => Some("user_input".into()),
                "tool" => Some("tool_result".into()),
                _ => None,
            };

            Some(BridgeMessage {
                role,
                content,
                trust_boundary,
            })
        })
        .collect()
}

/// Extract tool definitions from request body.
fn parse_tools(body: &Value) -> Vec<BridgeToolDef> {
    let Some(tools_arr) = body.get("tools").and_then(|v| v.as_array()) else {
        return vec![];
    };

    tools_arr
        .iter()
        .filter_map(|tool| {
            let function = tool.get("function")?;
            let name = function.get("name")?.as_str()?.to_string();
            let description = function
                .get("description")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            Some(BridgeToolDef { name, description })
        })
        .collect()
}

/// Extract tool calls from response body.
fn parse_response_tool_calls(body: &Value) -> Vec<BridgeToolCall> {
    let choices = body.get("choices").and_then(|v| v.as_array());
    let Some(choice) = choices.and_then(|c| c.first()) else {
        return vec![];
    };

    let message = choice.get("message");
    let Some(tool_calls_arr) = message.and_then(|m| m.get("tool_calls")).and_then(|v| v.as_array()) else {
        return vec![];
    };

    tool_calls_arr
        .iter()
        .filter_map(|tc| {
            let function = tc.get("function")?;
            let tool_name = function.get("name")?.as_str()?.to_string();
            let args_str = function.get("arguments").and_then(|v| v.as_str()).unwrap_or("{}");
            let tool_args: serde_json::Value =
                serde_json::from_str(args_str).unwrap_or(serde_json::Value::Object(Default::default()));
            Some(BridgeToolCall { tool_name, tool_args })
        })
        .collect()
}

/// Extract text content from response body.
fn parse_response_content(body: &Value) -> String {
    let choices = body.get("choices").and_then(|v| v.as_array());
    let Some(choice) = choices.and_then(|c| c.first()) else {
        return String::new();
    };

    if let Some(content) = choice
        .get("message")
        .and_then(|m| m.get("content"))
        .and_then(|c| c.as_str())
    {
        return content.to_string();
    }

    String::new()
}

/// Extract reasoning/thinking content from response body.
fn parse_response_reasoning(body: &Value) -> String {
    let choices = body.get("choices").and_then(|v| v.as_array());
    let Some(choice) = choices.and_then(|c| c.first()) else {
        return String::new();
    };

    if let Some(reasoning) = choice
        .get("message")
        .and_then(|m| m.get("reasoning_content"))
        .and_then(|r| r.as_str())
    {
        return reasoning.to_string();
    }

    String::new()
}
