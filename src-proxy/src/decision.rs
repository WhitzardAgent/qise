//! Guard decision types — models the Python Bridge response.

use serde::{Deserialize, Serialize};

/// Guard check request sent to Python Bridge.
#[derive(Debug, Serialize)]
pub struct GuardCheckRequest {
    /// "request" for ingress checks, "response" for egress/output checks.
    pub r#type: String,
    /// Parsed messages from the chat completion request.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub messages: Vec<BridgeMessage>,
    /// Tool definitions from the request.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<BridgeToolDef>,
    /// Tool calls from the response.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tool_calls: Vec<BridgeToolCall>,
    /// Text content from the response.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub content: String,
    /// Agent reasoning from the response.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub reasoning: String,
    /// Model name.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub model: String,
    /// Whether the request is streaming.
    pub stream: bool,
}

/// A parsed message from a chat completion request.
#[derive(Debug, Serialize)]
pub struct BridgeMessage {
    pub role: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_boundary: Option<String>,
}

/// A tool definition from a chat completion request.
#[derive(Debug, Serialize)]
pub struct BridgeToolDef {
    pub name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub description: String,
}

/// A tool call from a chat completion response.
#[derive(Debug, Serialize)]
pub struct BridgeToolCall {
    pub tool_name: String,
    pub tool_args: serde_json::Value,
}

/// Guard check response from Python Bridge.
#[derive(Debug, Deserialize)]
pub struct GuardCheckResponse {
    /// "pass" | "warn" | "block"
    pub action: String,
    #[serde(default)]
    pub guard_results: Vec<GuardResultSummary>,
    #[serde(default)]
    pub security_context: String,
    #[serde(default)]
    pub warnings: Vec<String>,
    #[serde(default)]
    pub block_reason: String,
}

/// Summary of a single guard's result.
#[derive(Debug, Deserialize)]
pub struct GuardResultSummary {
    pub guard: String,
    pub verdict: String,
    #[serde(default)]
    pub message: String,
    #[serde(default)]
    pub latency_ms: u64,
}

/// Guard action type.
#[derive(Debug, Clone, PartialEq)]
pub enum GuardAction {
    Pass,
    Warn,
    Block,
}

impl GuardCheckResponse {
    /// Parse the action string into a typed enum.
    pub fn action_type(&self) -> GuardAction {
        match self.action.as_str() {
            "block" => GuardAction::Block,
            "warn" => GuardAction::Warn,
            _ => GuardAction::Pass,
        }
    }
}
