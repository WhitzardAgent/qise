//! Embedded proxy server — runs inside Tauri's tokio runtime.
//!
//! Ports the core logic from src-proxy but uses AppState from Tauri
//! instead of environment-variable-based ProxyConfig.

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
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tauri::Emitter;
use tracing::{debug, error, info, warn};

/// Handle to a running proxy server task.
pub struct ProxyHandle {
    /// JoinHandle for the spawned axum server task.
    pub server_handle: tokio::task::JoinHandle<()>,
    /// Sender to signal graceful shutdown.
    pub shutdown_tx: tokio::sync::oneshot::Sender<()>,
    /// Address the proxy is listening on.
    pub addr: SocketAddr,
}

/// Shared state for the embedded proxy server.
#[derive(Clone)]
pub struct ProxyState {
    pub guard_client: GuardClient,
    pub http_client: Client,
    pub upstream_url: String,
    pub upstream_api_key: String,
    pub request_timeout_s: u64,
    pub block_on_guard_block: bool,
    pub inject_security_context: bool,
    pub tauri_app: tauri::AppHandle,
}

/// Paths that should be intercepted for guard analysis.
const INTERCEPT_PATHS: &[&str] = &["/v1/chat/completions"];

/// Paths that should pass through without interception.
const PASSTHROUGH_PATHS: &[&str] = &["/v1/models"];

/// Start the embedded proxy server.
///
/// Returns a ProxyHandle that can be used to stop the server later.
pub async fn start_proxy(
    bridge_url: String,
    upstream_url: String,
    upstream_api_key: String,
    port: u16,
    tauri_app: tauri::AppHandle,
) -> Result<ProxyHandle, String> {
    let guard_client = GuardClient::new(&bridge_url, 35);
    let http_client = Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {}", e))?;

    let proxy_state = Arc::new(ProxyState {
        guard_client,
        http_client,
        upstream_url,
        upstream_api_key,
        request_timeout_s: 60,
        block_on_guard_block: true,
        inject_security_context: true,
        tauri_app,
    });

    let app = axum::Router::new()
        .fallback(handle_request)
        .with_state(proxy_state);

    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", port))
        .await
        .map_err(|e| format!("Failed to bind proxy port {}: {}", port, e))?;

    let addr = listener.local_addr()
        .map_err(|e| format!("Failed to get local addr: {}", e))?;

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let server_handle = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap_or_else(|e| {
                error!("Proxy server error: {}", e);
            });
        info!("Proxy server stopped");
    });

    info!("Proxy server started on {}", addr);

    Ok(ProxyHandle {
        server_handle,
        shutdown_tx,
        addr,
    })
}

/// Stop the proxy server.
pub async fn stop_proxy(handle: ProxyHandle) -> Result<(), String> {
    let _ = handle.shutdown_tx.send(());
    handle.server_handle.await.map_err(|e| format!("Proxy shutdown error: {}", e))
}

/// Handle all incoming requests — route to intercept or passthrough.
async fn handle_request(
    State(state): State<Arc<ProxyState>>,
    axum::extract::Path(path): axum::extract::Path<String>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let path_owned = format!("/{}", path);
    let path = path_owned.as_str();

    debug!("Request: {} {}", method, path);

    let should_intercept = INTERCEPT_PATHS.iter().any(|ip| {
        path == *ip || path.starts_with(&format!("{}/", ip))
    });

    let is_passthrough = PASSTHROUGH_PATHS.iter().any(|pp| path == *pp);

    if is_passthrough || !should_intercept {
        return forward_request(&state, &method, &headers, path, &body).await;
    }

    if path == "/v1/chat/completions" && method == Method::POST {
        return handle_chat_completions(state, headers, body).await;
    }

    forward_request(&state, &method, &headers, path, &body).await
}

/// Handle /v1/chat/completions with full guard pipeline.
async fn handle_chat_completions(
    state: Arc<ProxyState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let parsed_body: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            let error_resp = serde_json::json!({"error": format!("Invalid JSON: {}", e)});
            return (StatusCode::BAD_REQUEST, Json(error_resp)).into_response();
        }
    };

    let is_stream = parsed_body
        .get("stream")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let guard_request = parser::parse_request_for_ingress(&parsed_body);

    match state.guard_client.check(&guard_request).await {
        Ok(guard_resp) => {
            // Emit guard event to Tauri frontend
            emit_guard_event(&state, &guard_resp);

            if guard_resp.action_type() == GuardAction::Block && state.block_on_guard_block {
                info!("Request BLOCKED: {}", guard_resp.block_reason);
                return guard_block_response(&guard_resp.block_reason, &guard_resp.warnings);
            }

            let mut forward_body = parsed_body.clone();
            if state.inject_security_context && !guard_resp.security_context.is_empty() {
                inject_security_context(&mut forward_body, &guard_resp.security_context);
            }

            if is_stream {
                return handle_streaming(state, &headers, &forward_body).await;
            }

            // Non-streaming path
            let upstream_resp =
                forward_json_request(&state, &Method::POST, &headers, "/v1/chat/completions", &forward_body)
                    .await;

            match upstream_resp {
                Ok(resp) if resp.status().is_success() => {
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

                    let should_check = !egress_request.tool_calls.is_empty() || !egress_request.content.is_empty();

                    if should_check {
                        match state.guard_client.check(&egress_request).await {
                            Ok(egress_resp) => {
                                emit_guard_event(&state, &egress_resp);

                                if egress_resp.action_type() == GuardAction::Block
                                    && state.block_on_guard_block
                                {
                                    info!("Response BLOCKED: {}", egress_resp.block_reason);
                                    return guard_block_response(
                                        &egress_resp.block_reason,
                                        &egress_resp.warnings,
                                    );
                                }

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
                        Response::builder()
                            .status(StatusCode::OK)
                            .header("Content-Type", "application/json")
                            .body(Body::from(resp_bytes))
                            .unwrap()
                    }
                }
                Ok(resp) => {
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

/// Emit a guard event to the Tauri frontend.
fn emit_guard_event(state: &ProxyState, guard_resp: &crate::decision::GuardCheckResponse) {
    let event = serde_json::json!({
        "action": guard_resp.action,
        "warnings": guard_resp.warnings,
        "block_reason": guard_resp.block_reason,
        "guard_results": guard_resp.guard_results,
    });
    let _ = state.tauri_app.emit("guard-event", event);
}

/// Handle streaming (SSE) chat completion requests.
async fn handle_streaming(
    state: Arc<ProxyState>,
    headers: &HeaderMap,
    forward_body: &Value,
) -> Response {
    let url = build_upstream_url(&state.upstream_url, "/v1/chat/completions");
    let req_headers = build_forward_headers(headers, &state.upstream_api_key);

    let upstream_resp = match state
        .http_client
        .post(&url)
        .headers(req_headers)
        .json(forward_body)
        .timeout(Duration::from_secs(state.request_timeout_s))
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
fn build_upstream_url(base_url: &str, path: &str) -> String {
    let base = base_url.trim_end_matches('/');
    if base.ends_with("/v1") && path.starts_with("/v1/") {
        format!("{}{}", base.trim_end_matches("/v1"), path)
    } else if base.ends_with("/v1") && path == "/v1" {
        base.to_string()
    } else {
        format!("{}{}", base, path)
    }
}

/// Forward a request to the upstream LLM API without interception.
async fn forward_request(
    state: &ProxyState,
    method: &Method,
    headers: &HeaderMap,
    path: &str,
    body: &Bytes,
) -> Response {
    let url = build_upstream_url(&state.upstream_url, path);
    let req_headers = build_forward_headers(headers, &state.upstream_api_key);

    let mut request = state
        .http_client
        .request(method.clone(), &url)
        .headers(req_headers)
        .timeout(Duration::from_secs(state.request_timeout_s));

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
    state: &ProxyState,
    method: &Method,
    headers: &HeaderMap,
    path: &str,
    body: &Value,
) -> Result<reqwest::Response, reqwest::Error> {
    let url = build_upstream_url(&state.upstream_url, path);
    let req_headers = build_forward_headers(headers, &state.upstream_api_key);

    state
        .http_client
        .request(method.clone(), &url)
        .headers(req_headers)
        .json(body)
        .timeout(Duration::from_secs(state.request_timeout_s))
        .send()
        .await
}

/// Build headers for forwarding to upstream.
fn build_forward_headers(headers: &HeaderMap, upstream_api_key: &str) -> HeaderMap {
    let mut forward_headers = HeaderMap::new();

    for (key, value) in headers.iter() {
        let key_lower = key.as_str().to_lowercase();
        if matches!(
            key_lower.as_str(),
            "host" | "content-length" | "transfer-encoding"
        ) {
            continue;
        }
        if key_lower == "authorization" && !upstream_api_key.is_empty() {
            continue;
        }
        forward_headers.insert(key.clone(), value.clone());
    }

    if !upstream_api_key.is_empty() {
        if let Ok(val) = HeaderValue::from_str(&format!("Bearer {}", upstream_api_key)) {
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

    let has_system = messages.first().and_then(|m| m.get("role")).and_then(|r| r.as_str())
        == Some("system");

    if has_system {
        if let Some(content_val) = messages[0].get_mut("content") {
            if let Some(content_str) = content_val.as_str() {
                let new_content = format!("{}\n\n{}", content_str, security_context);
                *content_val = Value::String(new_content);
            }
        }
    } else {
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
