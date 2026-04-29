//! Proxy handler — main request interception and forwarding logic.

use crate::config::ProxyConfig;
use crate::decision::GuardAction;
use crate::guard_client::GuardClient;
use crate::parser;
use crate::streaming;
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use bytes::Bytes;
use reqwest::Client;
use serde_json::Value;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, warn};

/// Shared application state.
#[derive(Clone)]
pub struct AppState {
    pub config: ProxyConfig,
    pub guard_client: GuardClient,
    pub http_client: Client,
}

impl AppState {
    pub fn new(config: ProxyConfig) -> Self {
        let guard_client = GuardClient::new(&config);
        let http_client = Client::builder()
            .timeout(Duration::from_secs(config.request_timeout_s))
            .build()
            .expect("failed to build HTTP client");

        Self {
            config,
            guard_client,
            http_client,
        }
    }
}

/// Handle all incoming requests — route to intercept or passthrough.
pub async fn handle_request(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(path): axum::extract::Path<String>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let path_owned = format!("/{}", path);
    let path = path_owned.as_str();

    debug!("Request: {} {}", method, path);

    // Check if this path should be intercepted
    let should_intercept = state.config.intercept_paths.iter().any(|ip| {
        path == ip || path.starts_with(&format!("{}/", ip))
    });

    let is_passthrough = state
        .config
        .passthrough_paths
        .iter()
        .any(|pp| path == pp);

    if is_passthrough || !should_intercept {
        return forward_request(&state, &method, &headers, path, &body).await;
    }

    // Intercept chat completion requests
    if path == "/v1/chat/completions" && method == Method::POST {
        return handle_chat_completions(state, headers, body).await;
    }

    // Other intercepted paths: just forward
    forward_request(&state, &method, &headers, path, &body).await
}

/// Handle /v1/chat/completions with full guard pipeline.
async fn handle_chat_completions(
    state: Arc<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // Step 1: Parse request body
    let parsed_body: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            let error_resp = serde_json::json!({"error": format!("Invalid JSON: {}", e)});
            return (StatusCode::BAD_REQUEST, Json(error_resp)).into_response();
        }
    };

    // Step 2: Run ingress guard check via Python Bridge
    let is_stream = parsed_body
        .get("stream")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let guard_request = parser::parse_request_for_ingress(&parsed_body);

    match state.guard_client.check(&guard_request).await {
        Ok(guard_resp) => {
            if guard_resp.action_type() == GuardAction::Block && state.config.block_on_guard_block {
                info!("Request BLOCKED: {}", guard_resp.block_reason);
                return guard_block_response(&guard_resp.block_reason, &guard_resp.warnings);
            }

            // Step 3: Inject security context into system message
            let mut forward_body = parsed_body.clone();
            if state.config.inject_security_context && !guard_resp.security_context.is_empty() {
                inject_security_context(&mut forward_body, &guard_resp.security_context);
            }

            // Step 4: Forward to upstream (streaming or non-streaming)
            if is_stream {
                return handle_streaming(state, &headers, &forward_body).await;
            }

            // Non-streaming path
            let upstream_resp =
                forward_json_request(&state, &Method::POST, &headers, "/v1/chat/completions", &forward_body)
                    .await;

            match upstream_resp {
                Ok(resp) if resp.status().is_success() => {
                    // Step 5: Parse response and run egress check
                    let resp_bytes = match resp.bytes().await {
                        Ok(b) => b,
                        Err(e) => {
                            error!("Failed to read upstream response: {}", e);
                            return StatusCode::BAD_GATEWAY.into_response();
                        }
                    };

                    let resp_body: Value = match serde_json::from_slice(&resp_bytes) {
                        Ok(v) => v,
                        Err(_) => {
                            // Not JSON, return as-is
                            return Response::builder()
                                .status(StatusCode::OK)
                                .body(Body::from(resp_bytes))
                                .unwrap();
                        }
                    };

                    let model = parsed_body
                        .get("model")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let egress_request = parser::parse_response_for_egress(&resp_body, model);

                    // Skip guard check if no tool_calls or content to check
                    let should_check = !egress_request.tool_calls.is_empty() || !egress_request.content.is_empty();

                    if should_check {
                        match state.guard_client.check(&egress_request).await {
                            Ok(egress_resp) => {
                                if egress_resp.action_type() == GuardAction::Block
                                    && state.config.block_on_guard_block
                                {
                                    info!("Response BLOCKED: {}", egress_resp.block_reason);
                                    return guard_block_response(
                                        &egress_resp.block_reason,
                                        &egress_resp.warnings,
                                    );
                                }

                                // Return response with optional warning headers
                                let mut response = Response::builder()
                                    .status(StatusCode::OK)
                                    .header("Content-Type", "application/json");

                                if egress_resp.action_type() == GuardAction::Warn {
                                    let warnings = egress_resp.warnings.join("; ");
                                    let truncated = &warnings[..warnings.len().min(500)];
                                    if let Ok(val) = HeaderValue::from_str(truncated) {
                                        response = response.header("X-Qise-Warnings", val);
                                    }
                                }

                                response.body(Body::from(resp_bytes)).unwrap()
                            }
                            Err(e) => {
                                warn!("Egress guard check failed (degrading to pass): {}", e);
                                Response::builder()
                                    .status(StatusCode::OK)
                                    .header("Content-Type", "application/json")
                                    .body(Body::from(resp_bytes))
                                    .unwrap()
                            }
                        }
                    } else {
                        // No tool calls or content to check
                        Response::builder()
                            .status(StatusCode::OK)
                            .header("Content-Type", "application/json")
                            .body(Body::from(resp_bytes))
                            .unwrap()
                    }
                }
                Ok(resp) => {
                    // Non-200 from upstream
                    let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
                    match resp.bytes().await {
                        Ok(b) => Response::builder().status(status).body(Body::from(b)).unwrap(),
                        Err(_) => status.into_response(),
                    }
                }
                Err(e) => {
                    error!("Upstream request failed: {}", e);
                    StatusCode::BAD_GATEWAY.into_response()
                }
            }
        }
        Err(e) => {
            // Guard check failed — degrade to pass with warning
            warn!("Ingress guard check failed (degrading to pass): {}", e);
            match forward_json_request(&state, &Method::POST, &headers, "/v1/chat/completions", &parsed_body).await {
                Ok(resp) => {
                    let status =
                        StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
                    match resp.bytes().await {
                        Ok(b) => Response::builder()
                            .status(status)
                            .header("X-Qise-Degraded", "true")
                            .body(Body::from(b))
                            .unwrap(),
                        Err(_) => status.into_response(),
                    }
                }
                Err(_) => StatusCode::BAD_GATEWAY.into_response(),
            }
        }
    }
}

/// Handle streaming (SSE) chat completion requests.
async fn handle_streaming(
    state: Arc<AppState>,
    headers: &HeaderMap,
    forward_body: &Value,
) -> Response {
    let url = build_upstream_url(&state.config.upstream_base_url, "/v1/chat/completions");

    let req_headers = build_forward_headers(headers, &state.config);

    let upstream_resp = match state
        .http_client
        .post(&url)
        .headers(req_headers)
        .json(forward_body)
        .timeout(Duration::from_secs(state.config.request_timeout_s))
        .send()
        .await
    {
        Ok(resp) => resp,
        Err(e) => {
            error!("Upstream streaming request failed: {}", e);
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };

    let status = StatusCode::from_u16(upstream_resp.status().as_u16()).unwrap_or(StatusCode::OK);

    let stream = streaming::process_sse_stream(upstream_resp);

    Response::builder()
        .status(status)
        .header("Content-Type", "text/event-stream")
        .header("Cache-Control", "no-cache")
        .body(Body::from_stream(stream))
        .unwrap()
}

/// Build the upstream URL, handling potential /v1 overlap.
/// If upstream_base_url ends with /v1 and path starts with /v1, avoid duplication.
fn build_upstream_url(base_url: &str, path: &str) -> String {
    let base = base_url.trim_end_matches('/');
    // Check if base ends with /v1 and path starts with /v1
    if base.ends_with("/v1") && path.starts_with("/v1/") {
        // Strip /v1 from base to avoid duplication
        format!("{}{}", base.trim_end_matches("/v1"), path)
    } else if base.ends_with("/v1") && path == "/v1" {
        base.to_string()
    } else {
        format!("{}{}", base, path)
    }
}

/// Forward a request to the upstream LLM API without interception.
async fn forward_request(
    state: &AppState,
    method: &Method,
    headers: &HeaderMap,
    path: &str,
    body: &Bytes,
) -> Response {
    let url = build_upstream_url(&state.config.upstream_base_url, path);

    let req_headers = build_forward_headers(headers, &state.config);

    let mut request = state
        .http_client
        .request(method.clone(), &url)
        .headers(req_headers)
        .timeout(Duration::from_secs(state.config.request_timeout_s));

    if method == Method::POST || method == Method::PUT || method == Method::PATCH {
        request = request.body(body.clone());
    }

    match request.send().await {
        Ok(resp) => {
            let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
            match resp.bytes().await {
                Ok(b) => Response::builder()
                    .status(status)
                    .body(Body::from(b))
                    .unwrap(),
                Err(_) => status.into_response(),
            }
        }
        Err(e) => {
            error!("Forward request failed: {}", e);
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

/// Forward a JSON request to the upstream LLM API.
async fn forward_json_request(
    state: &AppState,
    method: &Method,
    headers: &HeaderMap,
    path: &str,
    body: &Value,
) -> Result<reqwest::Response, reqwest::Error> {
    let url = build_upstream_url(&state.config.upstream_base_url, path);
    let req_headers = build_forward_headers(headers, &state.config);

    state
        .http_client
        .request(method.clone(), &url)
        .headers(req_headers)
        .json(body)
        .timeout(Duration::from_secs(state.config.request_timeout_s))
        .send()
        .await
}

/// Build headers for forwarding to upstream.
/// Replaces Authorization with the upstream API key.
fn build_forward_headers(headers: &HeaderMap, config: &ProxyConfig) -> HeaderMap {
    let mut forward_headers = HeaderMap::new();

    for (key, value) in headers.iter() {
        let key_lower = key.as_str().to_lowercase();
        if matches!(
            key_lower.as_str(),
            "host" | "content-length" | "transfer-encoding"
        ) {
            continue;
        }
        if key_lower == "authorization" && !config.upstream_api_key.is_empty() {
            continue; // Will be replaced
        }
        forward_headers.insert(key.clone(), value.clone());
    }

    if !config.upstream_api_key.is_empty() {
        if let Ok(val) = HeaderValue::from_str(&format!("Bearer {}", config.upstream_api_key)) {
            forward_headers.insert("authorization", val);
        }
    }

    forward_headers
}

/// Inject security context into the system message of the request body.
fn inject_security_context(body: &mut Value, security_context: &str) {
    if security_context.is_empty() {
        return;
    }

    let messages = match body.get_mut("messages").and_then(|m| m.as_array_mut()) {
        Some(m) => m,
        None => return,
    };

    // Find or create a system message
    let has_system = messages.first().and_then(|m| m.get("role")).and_then(|r| r.as_str())
        == Some("system");

    if has_system {
        // Append to existing system message
        if let Some(content_val) = messages[0].get_mut("content") {
            if let Some(content_str) = content_val.as_str() {
                let new_content = format!("{}\n\n{}", content_str, security_context);
                *content_val = Value::String(new_content);
            }
        }
    } else {
        // Insert a new system message at the beginning
        let system_msg = serde_json::json!({
            "role": "system",
            "content": security_context,
        });
        messages.insert(0, system_msg);
    }
}

/// Return a 403 block response with guard details.
fn guard_block_response(block_reason: &str, warnings: &[String]) -> Response {
    let body = serde_json::json!({
        "error": {
            "message": block_reason,
            "type": "qise_guard_block",
            "warnings": warnings,
        }
    });

    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header("Content-Type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}
