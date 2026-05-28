import { useState } from "react";
import type { AgentInfo } from "../lib/api";

interface AgentTaskState {
  status: "idle" | "running" | "succeeded" | "failed";
  action?: string;
  error?: string;
}

interface AgentPanelProps {
  agents: AgentInfo[];
  task: AgentTaskState;
  onProtect: (agent: AgentInfo) => void;
  onRestore: (agent: AgentInfo) => void;
}

function statusColor(agent: AgentInfo): string {
  if (agent.protected) return "var(--qise-green)";
  if (agent.installed) return "var(--qise-yellow)";
  return "var(--indicator-muted)";
}

function statusLabel(agent: AgentInfo): string {
  if (agent.protected) return "Protected";
  if (agent.installed) return "Available";
  return "Not Found";
}

function backupPreview(agent: AgentInfo): string {
  return `~/.qise/backups/${agent.key}/<timestamp>/`;
}

export default function AgentPanel({ agents, task, onProtect, onRestore }: AgentPanelProps) {
  const [confirmAgent, setConfirmAgent] = useState<AgentInfo | null>(null);
  const anyBusy = task.status === "running";
  const busyAgent = task.status === "running" && task.action?.includes(":")
    ? task.action.split(":")[1]
    : null;

  return (
    <div className="qise-card p-4">
      {task.status === "failed" && task.error && (
        <div className="mb-3 rounded-lg border border-[rgba(255,95,111,0.35)] bg-[rgba(255,95,111,0.08)] px-3 py-2">
          <p className="text-xs text-qise-red">{task.error}</p>
        </div>
      )}

      {agents.map((agent) => (
        <div
          key={agent.key}
          className="flex items-center justify-between gap-3 py-3 px-3 rounded-lg hover:bg-[var(--bg-card)]"
        >
          <div className="flex items-center gap-3 min-w-0">
            <div
              className="w-2 h-2 rounded-full shrink-0"
              style={{
                backgroundColor: statusColor(agent),
                boxShadow: agent.protected ? `0 0 8px ${statusColor(agent)}` : undefined,
              }}
            />
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <span className="text-sm text-[var(--text-primary)]">{agent.name}</span>
                {agent.experimental && (
                  <span className="text-[10px] uppercase tracking-wide text-[var(--text-dim)]">
                    experimental
                  </span>
                )}
              </div>
              <p className="text-xs text-[var(--text-dim)] truncate">
                {agent.config_path || agent.cli_path || agent.note || "No local config detected"}
              </p>
            </div>
            <span
              className="text-xs px-2 py-0.5 rounded-full shrink-0"
              style={{
                color: statusColor(agent),
                backgroundColor: `${statusColor(agent)}20`,
              }}
            >
              {statusLabel(agent)}
            </span>
          </div>

          {agent.installed && (
            agent.protected ? (
              <button
                className="text-xs px-3 py-1.5 rounded-[86px] bg-[var(--button-primary-bg)] text-[var(--button-primary-text)] hover:opacity-60 transition-opacity disabled:opacity-40"
                disabled={anyBusy}
                onClick={() => onRestore(agent)}
              >
                {busyAgent === agent.key ? (
                  <span className="inline-flex items-center gap-2"><span className="qise-spinner" />Restoring...</span>
                ) : "Restore"}
              </button>
            ) : (
              <button
                className="text-xs px-3 py-1.5 rounded-[86px] bg-transparent border border-[var(--border-strong)] text-[var(--text-primary)] hover:opacity-60 transition-opacity disabled:opacity-40"
                disabled={anyBusy}
                onClick={() => setConfirmAgent(agent)}
              >
                {busyAgent === agent.key ? (
                  <span className="inline-flex items-center gap-2"><span className="qise-spinner qise-spinner-blue" />Protecting...</span>
                ) : "Protect"}
              </button>
            )
          )}
        </div>
      ))}

      {agents.length === 0 && (
        <p className="text-sm text-[var(--text-dim)] text-center py-4">
          No agents detected.
        </p>
      )}

      {confirmAgent && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-[rgba(35,68,96,0.28)] px-4">
          <div className="w-full max-w-lg rounded-lg border border-[var(--border-subtle)] bg-qise-surface p-5 shadow-double-ring">
            <h3 className="text-sm font-medium text-[var(--text-primary)] mb-3">
              Protect {confirmAgent.name}
            </h3>
            <div className="space-y-2 text-xs text-[var(--text-tertiary)]">
              <p>
                Command: <span className="font-mono text-[var(--text-secondary)]">qise protect {confirmAgent.key}</span>
              </p>
              <p>
                Config: <span className="font-mono text-[var(--text-secondary)]">{confirmAgent.config_path || "not detected"}</span>
              </p>
              <p>
                Backup: <span className="font-mono text-[var(--text-secondary)]">{backupPreview(confirmAgent)}</span>
              </p>
              <p className="text-qise-yellow">
                Qise will patch the Agent config only after the product CLI confirms an upstream.
              </p>
            </div>
            <div className="mt-5 flex justify-end gap-2">
              <button
                className="px-4 py-2 rounded-[43px] text-sm font-medium bg-[var(--bg-card)] text-[var(--text-tertiary)] hover:opacity-60 transition-all"
                onClick={() => setConfirmAgent(null)}
              >
                Cancel
              </button>
              <button
                className="px-4 py-2 rounded-[43px] text-sm font-medium bg-[var(--button-primary-bg)] text-[var(--button-primary-text)] hover:opacity-60 transition-all disabled:opacity-40"
                disabled={anyBusy}
                onClick={() => {
                  onProtect(confirmAgent);
                  setConfirmAgent(null);
                }}
              >
                {busyAgent === confirmAgent.key ? (
                  <span className="inline-flex items-center gap-2"><span className="qise-spinner" />Protecting...</span>
                ) : "Confirm"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
