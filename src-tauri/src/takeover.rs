//! Proxy Takeover — automatically redirect Agent API configurations to Qise Proxy.
//!
//! When "Take Over" is clicked:
//! 1. Back up the agent's current API config (env vars)
//! 2. Set new values pointing to Qise Proxy (localhost:8822)
//! 3. Persist state to ~/.qise/backups/active_takeovers.json
//!
//! On exit/crash:
//! - Auto-restore all active takeovers
//! - On next startup, recover any unrecovered takeovers

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use tracing::{error, info, warn};

/// Supported agent types for takeover.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AgentType {
    GenericOpenAI,
    ClaudeCode,
}

impl AgentType {
    /// All supported agent types.
    pub fn all() -> Vec<AgentType> {
        vec![AgentType::GenericOpenAI, AgentType::ClaudeCode]
    }

    /// Display name.
    pub fn display_name(&self) -> &str {
        match self {
            AgentType::GenericOpenAI => "Generic OpenAI",
            AgentType::ClaudeCode => "Claude Code",
        }
    }

    /// CLI binary name to detect if agent is installed.
    pub fn cli_name(&self) -> &str {
        match self {
            AgentType::GenericOpenAI => "",  // Generic, no specific CLI
            AgentType::ClaudeCode => "claude",
        }
    }

    /// Environment variable(s) to set for takeover.
    pub fn takeover_env_vars(&self, proxy_port: u16) -> Vec<(String, String)> {
        let proxy_url = format!("http://localhost:{}/v1", proxy_port);
        match self {
            AgentType::GenericOpenAI => vec![
                ("OPENAI_API_BASE".to_string(), proxy_url),
            ],
            AgentType::ClaudeCode => vec![
                ("ANTHROPIC_BASE_URL".to_string(), proxy_url),
            ],
        }
    }
}

/// State of a single takeover.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TakeoverState {
    /// Which agent was taken over.
    pub agent_name: String,
    /// Original env var values (None = didn't exist before).
    pub original_env_vars: HashMap<String, Option<String>>,
    /// When the takeover happened.
    pub taken_at: String,
    /// Whether it has been restored.
    pub restored: bool,
}

/// Manages proxy takeovers for agents.
pub struct TakeoverManager {
    /// Directory for backup files.
    backup_dir: PathBuf,
    /// Active takeovers (agent_name → state).
    active_takeovers: HashMap<String, TakeoverState>,
    /// Path to the state file.
    state_file: PathBuf,
    /// Proxy port for generating redirect URLs.
    proxy_port: u16,
}

impl TakeoverManager {
    /// Create a new TakeoverManager.
    pub fn new(proxy_port: u16) -> Self {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_else(|_| ".".into());
        let backup_dir = PathBuf::from(format!("{}/.qise/backups", home));
        let state_file = backup_dir.join("active_takeovers.json");

        let mut manager = Self {
            backup_dir,
            active_takeovers: HashMap::new(),
            state_file,
            proxy_port,
        };

        // Load existing state (for crash recovery)
        manager.load_state();

        manager
    }

    /// Detect which agents are installed on this system.
    pub fn detect_agents(&self) -> Vec<AgentInfo> {
        AgentType::all()
            .into_iter()
            .map(|agent| {
                let installed = if agent.cli_name().is_empty() {
                    true // Generic is always "available"
                } else {
                    self.is_cli_installed(agent.cli_name())
                };

                let taken_over = self.active_takeovers.contains_key(&format!("{:?}", agent));

                AgentInfo {
                    agent_type: format!("{:?}", agent),
                    display_name: agent.display_name().to_string(),
                    installed,
                    taken_over,
                }
            })
            .collect()
    }

    /// Take over an agent's API configuration.
    pub fn takeover(&mut self, agent: &AgentType) -> Result<TakeoverState, String> {
        let key = format!("{:?}", agent);

        if self.active_takeovers.contains_key(&key) {
            return Err(format!("{} is already taken over", agent.display_name()));
        }

        // Backup original env vars
        let env_vars = agent.takeover_env_vars(self.proxy_port);
        let mut original_env_vars = HashMap::new();

        for (var_name, new_value) in &env_vars {
            let original = std::env::var(var_name).ok();
            original_env_vars.insert(var_name.clone(), original);

            // Set the new value
            std::env::set_var(var_name, new_value);
            info!("Set {} = {} (was {:?})", var_name, new_value, original_env_vars[var_name]);
        }

        let state = TakeoverState {
            agent_name: key.clone(),
            original_env_vars,
            taken_at: chrono_now(),
            restored: false,
        };

        self.active_takeovers.insert(key, state.clone());
        self.save_state()?;

        info!("Takeover complete for {}", agent.display_name());
        Ok(state)
    }

    /// Restore an agent's original API configuration.
    pub fn restore(&mut self, agent: &AgentType) -> Result<(), String> {
        let key = format!("{:?}", agent);

        let state = self.active_takeovers.remove(&key)
            .ok_or_else(|| format!("{} is not taken over", agent.display_name()))?;

        // Restore original env vars
        for (var_name, original_value) in &state.original_env_vars {
            match original_value {
                Some(val) => {
                    std::env::set_var(var_name, val);
                    info!("Restored {} = {}", var_name, val);
                }
                None => {
                    std::env::remove_var(var_name);
                    info!("Removed {} (was not set before)", var_name);
                }
            }
        }

        self.save_state()?;

        info!("Restored {}", agent.display_name());
        Ok(())
    }

    /// Restore all active takeovers (for shutdown/cleanup).
    pub fn restore_all(&mut self) -> Vec<Result<(), String>> {
        let keys: Vec<String> = self.active_takeovers.keys().cloned().collect();
        let mut results = Vec::new();

        for key in keys {
            if let Some(agent) = parse_agent_type(&key) {
                results.push(self.restore(&agent));
            }
        }

        results
    }

    /// Recover any unrecovered takeovers from a previous crash.
    pub fn recover_on_startup(&mut self) {
        if self.active_takeovers.is_empty() {
            return;
        }

        info!("Found {} unrecovered takeover(s), restoring...", self.active_takeovers.len());

        let keys: Vec<String> = self.active_takeovers.keys().cloned().collect();
        for key in keys {
            if let Some(agent) = parse_agent_type(&key) {
                match self.restore(&agent) {
                    Ok(()) => info!("Recovered takeover for {}", agent.display_name()),
                    Err(e) => error!("Failed to recover takeover for {}: {}", agent.display_name(), e),
                }
            }
        }
    }

    /// Get the status of all takeovers.
    pub fn get_takeover_status(&self) -> Vec<TakeoverState> {
        self.active_takeovers.values().cloned().collect()
    }

    /// Check if a CLI is installed.
    fn is_cli_installed(&self, cli_name: &str) -> bool {
        std::process::Command::new("which")
            .arg(cli_name)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Save takeover state to disk.
    fn save_state(&self) -> Result<(), String> {
        if let Err(e) = std::fs::create_dir_all(&self.backup_dir) {
            warn!("Failed to create backup dir: {}", e);
        }

        let states: Vec<TakeoverState> = self.active_takeovers.values().cloned().collect();
        let json = serde_json::to_string_pretty(&states)
            .map_err(|e| format!("Failed to serialize takeover state: {}", e))?;

        std::fs::write(&self.state_file, json)
            .map_err(|e| format!("Failed to write state file: {}", e))?;

        Ok(())
    }

    /// Load takeover state from disk.
    fn load_state(&mut self) {
        if !self.state_file.exists() {
            return;
        }

        match std::fs::read_to_string(&self.state_file) {
            Ok(json) => {
                match serde_json::from_str::<Vec<TakeoverState>>(&json) {
                    Ok(states) => {
                        for state in states {
                            if !state.restored {
                                self.active_takeovers.insert(state.agent_name.clone(), state);
                            }
                        }
                        if !self.active_takeovers.is_empty() {
                            info!("Loaded {} active takeover(s) from state file", self.active_takeovers.len());
                        }
                    }
                    Err(e) => {
                        warn!("Failed to parse takeover state file: {}", e);
                    }
                }
            }
            Err(e) => {
                warn!("Failed to read takeover state file: {}", e);
            }
        }
    }
}

/// Information about a detectable agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentInfo {
    pub agent_type: String,
    pub display_name: String,
    pub installed: bool,
    pub taken_over: bool,
}

/// Parse an agent type from its string key.
fn parse_agent_type(key: &str) -> Option<AgentType> {
    match key {
        "GenericOpenAI" => Some(AgentType::GenericOpenAI),
        "ClaudeCode" => Some(AgentType::ClaudeCode),
        _ => None,
    }
}

/// Simple timestamp without external dependency.
fn chrono_now() -> String {
    let output = std::process::Command::new("date")
        .arg("+%Y-%m-%dT%H:%M:%S")
        .output()
        .ok();
    output
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}
