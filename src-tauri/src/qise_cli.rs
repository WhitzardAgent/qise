//! Safe helpers for invoking the Python Qise product CLI.
//!
//! The Desktop app treats the Python product layer as the source of truth.
//! This module centralizes command discovery, argument construction, stdout
//! parsing, and stderr-rich error messages.

use serde_json::Value;
use std::ffi::OsString;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::process::CommandExt;
#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x08000000;

#[derive(Clone, Debug)]
pub struct QiseInvocation {
    program: OsString,
    prefix_args: Vec<OsString>,
    pythonpath: Option<OsString>,
}

#[derive(Debug)]
pub struct QiseOutput {
    pub stdout: String,
    pub stderr: String,
    pub success: bool,
    pub exit_status: String,
    pub display: String,
}

impl QiseInvocation {
    pub fn command(&self) -> Command {
        let mut command = Command::new(&self.program);
        command.args(&self.prefix_args);
        if let Some(ref pythonpath) = self.pythonpath {
            command.env("PYTHONPATH", pythonpath);
        }
        #[cfg(windows)]
        command.creation_flags(CREATE_NO_WINDOW);
        command
    }

    pub fn display(&self, args: &[String]) -> String {
        let mut parts = Vec::new();
        parts.push(self.program.to_string_lossy().to_string());
        parts.extend(
            self.prefix_args
                .iter()
                .map(|arg| arg.to_string_lossy().to_string()),
        );
        parts.extend(args.iter().cloned());
        parts.join(" ")
    }
}

pub fn args(items: &[&str]) -> Vec<String> {
    items.iter().map(|item| (*item).to_string()).collect()
}

pub fn args_with_default_config(items: &[&str]) -> Vec<String> {
    let mut full = Vec::new();
    if let Some(config_path) = default_config_path_if_exists() {
        full.push("--config".to_string());
        full.push(config_path);
    }
    full.extend(args(items));
    full
}

pub async fn run(args: Vec<String>) -> Result<QiseOutput, String> {
    let output = run_permissive(args).await?;
    if !output.success {
        return Err(format!(
            "`{}` failed with exit {}. stdout: {} stderr: {}",
            output.display, output.exit_status, output.stdout, output.stderr
        ));
    }
    Ok(output)
}

pub async fn run_permissive(args: Vec<String>) -> Result<QiseOutput, String> {
    tokio::task::spawn_blocking(move || run_blocking(args))
        .await
        .map_err(|e| format!("Qise command task failed: {}", e))?
}

pub async fn run_json(args: Vec<String>) -> Result<Value, String> {
    let output = run(args).await?;
    serde_json::from_str::<Value>(&output.stdout).map_err(|e| {
        format!(
            "Failed to parse Qise JSON output: {}. stdout: {}",
            e, output.stdout
        )
    })
}

pub async fn run_json_permissive(args: Vec<String>) -> Result<Value, String> {
    let output = run_permissive(args).await?;
    serde_json::from_str::<Value>(&output.stdout).map_err(|e| {
        format!(
            "Failed to parse Qise JSON output: {}. exit: {} stdout: {} stderr: {}",
            e, output.exit_status, output.stdout, output.stderr
        )
    })
}

pub fn resolve() -> Result<QiseInvocation, String> {
    if let Some(raw) = non_empty_env("QISE_BINARY") {
        return Ok(QiseInvocation {
            program: OsString::from(raw),
            prefix_args: Vec::new(),
            pythonpath: None,
        });
    }

    if let Some(path) = bundled_qise_path() {
        return Ok(QiseInvocation {
            program: OsString::from(path),
            prefix_args: Vec::new(),
            pythonpath: None,
        });
    }

    let qise = QiseInvocation {
        program: OsString::from("qise"),
        prefix_args: Vec::new(),
        pythonpath: None,
    };
    if verify_invocation(&qise) {
        return Ok(qise);
    }

    let python = QiseInvocation {
        program: OsString::from("python3"),
        prefix_args: vec![OsString::from("-m"), OsString::from("qise")],
        pythonpath: repo_pythonpath(),
    };
    if verify_invocation(&python) {
        return Ok(python);
    }

    Err(
        "Could not find Qise. The bundled Qise runtime is missing or invalid. Rebuild the Desktop app, set QISE_BINARY to the qise executable, install qise on PATH, or make `python3 -m qise` available."
            .to_string(),
    )
}

pub fn default_config_path_if_exists() -> Option<String> {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .ok()?;
    let path = Path::new(&home).join(".qise").join("shield.yaml");
    if path.exists() {
        Some(path.to_string_lossy().to_string())
    } else {
        None
    }
}

fn run_blocking(args: Vec<String>) -> Result<QiseOutput, String> {
    let invocation = resolve()?;
    let display = invocation.display(&args);
    let timeout = command_timeout();
    let mut command = invocation.command();
    command
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        command.process_group(0);
    }
    let mut child = command
        .spawn()
        .map_err(|e| format!("Failed to run `{}`: {}", display, e))?;

    let mut stdout_pipe = child.stdout.take();
    let mut stderr_pipe = child.stderr.take();
    let stdout_reader = thread::spawn(move || {
        let mut output = Vec::new();
        if let Some(ref mut pipe) = stdout_pipe {
            let _ = pipe.read_to_end(&mut output);
        }
        output
    });
    let stderr_reader = thread::spawn(move || {
        let mut output = Vec::new();
        if let Some(ref mut pipe) = stderr_pipe {
            let _ = pipe.read_to_end(&mut output);
        }
        output
    });

    let started = Instant::now();
    let mut timed_out = false;
    let status = loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|e| format!("Failed to wait for `{}`: {}", display, e))?
        {
            break status;
        }
        if started.elapsed() >= timeout {
            timed_out = true;
            terminate_child(&mut child);
            break child
                .wait()
                .map_err(|e| format!("Failed to kill timed-out `{}`: {}", display, e))?;
        }
        thread::sleep(Duration::from_millis(100));
    };

    let stdout_bytes = stdout_reader.join().unwrap_or_default();
    let stderr_bytes = stderr_reader.join().unwrap_or_default();
    let stdout = String::from_utf8_lossy(&stdout_bytes).trim().to_string();
    let mut stderr = String::from_utf8_lossy(&stderr_bytes).trim().to_string();

    if timed_out {
        let note = format!(
            "Qise command timed out after {} seconds. Command: {}",
            timeout.as_secs(),
            display
        );
        if stderr.is_empty() {
            stderr = note;
        } else {
            stderr = format!("{}\n{}", stderr, note);
        }
    }

    let exit_status = if timed_out {
        "timeout".to_string()
    } else {
        status
            .code()
            .map(|value| value.to_string())
            .unwrap_or_else(|| "signal".to_string())
    };

    Ok(QiseOutput {
        stdout,
        stderr,
        success: status.success() && !timed_out,
        exit_status,
        display,
    })
}

fn command_timeout() -> Duration {
    let seconds = std::env::var("QISE_DESKTOP_COMMAND_TIMEOUT_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value >= 5)
        .unwrap_or(180);
    Duration::from_secs(seconds)
}

#[cfg(unix)]
fn terminate_child(child: &mut Child) {
    let pid = child.id() as i32;
    unsafe {
        libc::kill(-pid, libc::SIGKILL);
    }
    let _ = child.kill();
}

#[cfg(not(unix))]
fn terminate_child(child: &mut Child) {
    let _ = child.kill();
}

fn verify_invocation(invocation: &QiseInvocation) -> bool {
    invocation
        .command()
        .arg("version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn non_empty_env(name: &str) -> Option<String> {
    let value = std::env::var(name).ok()?;
    if value.trim().is_empty() {
        None
    } else {
        Some(value)
    }
}

fn bundled_qise_path() -> Option<PathBuf> {
    let exe_path = std::env::current_exe().ok()?;
    let exe_dir = exe_path.parent()?;
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    let candidates = [
        exe_dir.join("../Resources/bin/qise"),
        exe_dir.join("bin/qise.exe"),
        exe_dir.join("bin/qise"),
        manifest_dir.join("resources/bin/qise.exe"),
        manifest_dir.join("resources/bin/qise"),
    ];

    candidates
        .into_iter()
        .find(|path| path.is_file())
        .and_then(|path| path.canonicalize().ok().or(Some(path)))
}

fn repo_pythonpath() -> Option<OsString> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let src_dir = manifest_dir.parent()?.join("src");
    if !src_dir.join("qise").exists() {
        return None;
    }

    let mut paths: Vec<PathBuf> = std::env::var_os("PYTHONPATH")
        .map(|raw| std::env::split_paths(&raw).collect())
        .unwrap_or_default();
    if !paths.iter().any(|path| path == &src_dir) {
        paths.insert(0, src_dir);
    }
    std::env::join_paths(paths).ok()
}
