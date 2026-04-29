//! Bridge subprocess management — starts/stops the Python Bridge process.

use reqwest::Client;
use std::process::Child;
use std::time::Duration;
use tracing::{info, warn};

/// Handle to a running Python Bridge subprocess.
pub struct BridgeHandle {
    /// The child process.
    pub process: Child,
    /// Port the bridge is listening on.
    pub port: u16,
}

/// Start the Python Bridge subprocess.
///
/// 1. Locate `qise` CLI (or fall back to `python -m qise`)
/// 2. Spawn the subprocess
/// 3. Wait for health check to pass (up to 30s)
pub async fn start_bridge(port: u16, config_path: &str) -> Result<BridgeHandle, String> {
    let qise_bin = find_qise_binary()?;

    let args = if qise_bin.ends_with("python") || qise_bin.ends_with("python3") {
        vec![
            "-m".to_string(),
            "qise".to_string(),
            "bridge".to_string(),
            "start".to_string(),
            "--port".to_string(),
            port.to_string(),
            "--config".to_string(),
            config_path.to_string(),
        ]
    } else {
        vec![
            "bridge".to_string(),
            "start".to_string(),
            "--port".to_string(),
            port.to_string(),
            "--config".to_string(),
            config_path.to_string(),
        ]
    };

    info!("Starting bridge: {} {}", qise_bin, args.join(" "));

    let child = std::process::Command::new(&qise_bin)
        .args(&args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn bridge process: {}", e))?;

    let mut handle = BridgeHandle {
        process: child,
        port,
    };

    // Wait for bridge to become healthy (up to 30s)
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {}", e))?;

    let health_url = format!("http://127.0.0.1:{}/v1/bridge/health", port);
    let mut attempts = 0;
    let max_attempts = 30;

    loop {
        attempts += 1;
        match client.get(&health_url).send().await {
            Ok(resp) if resp.status().is_success() => {
                info!("Bridge is healthy after {} attempts", attempts);
                return Ok(handle);
            }
            Ok(resp) => {
                warn!("Bridge health check returned {} (attempt {}/{})", resp.status(), attempts, max_attempts);
            }
            Err(e) => {
                if attempts < 5 {
                    // Early attempts — process may still be starting
                    debug_early(attempts, &e.to_string());
                } else {
                    warn!("Bridge health check failed: {} (attempt {}/{})", e, attempts, max_attempts);
                }
            }
        }

        if attempts >= max_attempts {
            // Kill the process since it didn't start
            let _ = handle.process.kill();
            let _ = handle.process.wait();
            return Err(format!("Bridge failed to become healthy after {} attempts", max_attempts));
        }

        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

/// Stop the Python Bridge subprocess gracefully.
pub async fn stop_bridge(mut handle: BridgeHandle) -> Result<(), String> {
    info!("Stopping bridge on port {}", handle.port);

    // Try graceful shutdown first via SIGTERM (Unix)
    #[cfg(unix)]
    {
        if let Err(e) = handle.process.kill() {
            warn!("Failed to send SIGTERM to bridge: {}", e);
        }
    }

    #[cfg(not(unix))]
    {
        if let Err(e) = handle.process.kill() {
            warn!("Failed to kill bridge process: {}", e);
        }
    }

    // Wait for the process to exit (with timeout)
    match tokio::time::timeout(Duration::from_secs(5), async {
        handle.process.wait()
    }).await {
        Ok(Ok(status)) => {
            info!("Bridge exited with status: {}", status);
            Ok(())
        }
        Ok(Err(e)) => {
            Err(format!("Failed to wait for bridge exit: {}", e))
        }
        Err(_) => {
            warn!("Bridge did not exit within 5s, force killing");
            let _ = handle.process.kill();
            let _ = handle.process.wait();
            Ok(())
        }
    }
}

/// Find the qise binary — try `qise` first, then `python -m qise`.
fn find_qise_binary() -> Result<String, String> {
    // Try 1: `which qise`
    if let Ok(output) = std::process::Command::new("which")
        .arg("qise")
        .output()
    {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                info!("Found qise at: {}", path);
                return Ok(path);
            }
        }
    }

    // Try 2: `which python3`
    if let Ok(output) = std::process::Command::new("which")
        .arg("python3")
        .output()
    {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                // Verify `python3 -m qise` works
                if let Ok(check) = std::process::Command::new(&path)
                    .args(["-m", "qise", "--help"])
                    .output()
                {
                    if check.status.success() {
                        info!("Using python3 at: {} (with -m qise)", path);
                        return Ok(path);
                    }
                }
            }
        }
    }

    Err("Could not find qise CLI or python3 with qise module. Install with: pip install -e .".into())
}

fn debug_early(attempt: usize, msg: &str) {
    if attempt <= 3 {
        tracing::debug!("Bridge not ready yet (attempt {}): {}", attempt, msg);
    }
}
