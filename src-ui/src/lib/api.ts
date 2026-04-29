/** Tauri IPC API types and wrappers. */

export interface AppStatus {
  protection_enabled: boolean;
  proxy_port: number;
  bridge_port: number;
  blocked_count: number;
  warning_count: number;
}

export interface GuardInfo {
  name: string;
  mode: string;
  pipeline: string;
  primary_strategy: string;
}

export interface SecurityEvent {
  timestamp: string;
  guard_name: string;
  verdict: string;
  message: string;
}

export interface AgentInfo {
  agent_type: string;
  display_name: string;
  installed: boolean;
  taken_over: boolean;
}

export interface TakeoverState {
  agent_name: string;
  original_env_vars: Record<string, string | null>;
  taken_at: string;
  restored: boolean;
}
