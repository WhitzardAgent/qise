//! SSE streaming handler — processes Server-Sent Events streams from upstream.

use bytes::Bytes;
use futures::StreamExt;
use reqwest::Response;
use std::pin::Pin;
use tokio::sync::mpsc;
use tracing::{debug, warn};

/// Process an SSE stream from upstream, buffering tool_calls for guard checks
/// while passing text chunks through immediately.
pub fn process_sse_stream(
    upstream_resp: Response,
) -> Pin<Box<dyn futures::Stream<Item = Result<Bytes, std::io::Error>> + Send>> {
    let (tx, rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(32);

    tokio::spawn(async move {
        let mut stream = upstream_resp.bytes_stream();
        let mut buffer = String::new();

        while let Some(chunk_result) = stream.next().await {
            match chunk_result {
                Ok(chunk) => {
                    // Forward the chunk immediately
                    if tx.send(Ok(chunk.clone())).await.is_err() {
                        break;
                    }

                    // Also buffer for tool_call detection
                    if let Ok(text) = std::str::from_utf8(&chunk) {
                        buffer.push_str(text);

                        // Check for complete SSE events containing tool_calls
                        let _ = extract_tool_calls_from_buffer(&buffer);

                        // Keep buffer reasonable — trim processed data
                        if buffer.len() > 65536 {
                            let keep = buffer.len().saturating_sub(8192);
                            buffer = buffer[keep..].to_string();
                        }
                    }
                }
                Err(e) => {
                    warn!("SSE stream error: {}", e);
                    let _ = tx.send(Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        e.to_string(),
                    ))).await;
                    break;
                }
            }
        }

        debug!("SSE stream complete");
    });

    Box::pin(tokio_stream::wrappers::ReceiverStream::new(rx))
}

/// Extract tool_call fragments from the SSE buffer.
/// Returns the count of tool_call events found (for logging).
fn extract_tool_calls_from_buffer(buffer: &str) -> usize {
    let mut count = 0;

    for line in buffer.lines() {
        if let Some(data) = line.strip_prefix("data: ") {
            if data == "[DONE]" {
                continue;
            }
            if let Ok(event) = serde_json::from_str::<serde_json::Value>(data) {
                if let Some(choices) = event.get("choices").and_then(|c| c.as_array()) {
                    for choice in choices {
                        if choice.get("delta").and_then(|d| d.get("tool_calls")).is_some() {
                            count += 1;
                        }
                    }
                }
            }
        }
    }

    count
}
