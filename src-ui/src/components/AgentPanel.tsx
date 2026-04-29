import { invoke } from "@tauri-apps/api/core";
import type { AgentInfo } from "../lib/api";

interface AgentPanelProps {
  agents: AgentInfo[];
  onRefresh: () => void;
}

function statusColor(agent: AgentInfo): string {
  if (agent.taken_over) return "#5fc992";
  if (agent.installed) return "#ffbc33";
  return "#6a6b6c";
}

function statusLabel(agent: AgentInfo): string {
  if (agent.taken_over) return "Connected";
  if (agent.installed) return "Available";
  return "Not Found";
}

export default function AgentPanel({ agents, onRefresh }: AgentPanelProps) {
  async function handleTakeover(agentType: string) {
    try {
      await invoke("takeover_agent", { agent: agentType });
      onRefresh();
    } catch (e) {
      console.error("Failed to takeover agent:", e);
    }
  }

  async function handleRestore(agentType: string) {
    try {
      await invoke("restore_agent", { agent: agentType });
      onRefresh();
    } catch (e) {
      console.error("Failed to restore agent:", e);
    }
  }

  return (
    <div className="qise-card p-4">
      {agents.map((agent) => (
        <div
          key={agent.agent_type}
          className="flex items-center justify-between py-3 px-3 rounded-lg hover:bg-[#1b1c1e]"
        >
          <div className="flex items-center gap-3">
            {/* Status dot */}
            <div
              className="w-2 h-2 rounded-full"
              style={{
                backgroundColor: statusColor(agent),
                boxShadow: agent.taken_over ? `0 0 8px ${statusColor(agent)}` : undefined,
              }}
            />
            <span className="text-sm text-[#f9f9f9]">
              {agent.display_name}
            </span>
            <span
              className="text-xs px-2 py-0.5 rounded-full"
              style={{
                color: statusColor(agent),
                backgroundColor: `${statusColor(agent)}20`,
              }}
            >
              {statusLabel(agent)}
            </span>
          </div>

          {/* Action button */}
          {agent.installed && (
            agent.taken_over ? (
              <button
                className="text-xs px-3 py-1.5 rounded-[86px] bg-[hsla(0,0%,100%,0.815)] text-[#07080a] hover:opacity-60 transition-opacity"
                onClick={() => handleRestore(agent.agent_type)}
              >
                Restore
              </button>
            ) : (
              <button
                className="text-xs px-3 py-1.5 rounded-[86px] bg-transparent border border-[rgba(255,255,255,0.1)] text-[#f9f9f9] hover:opacity-60 transition-opacity"
                onClick={() => handleTakeover(agent.agent_type)}
              >
                Take Over
              </button>
            )
          )}
        </div>
      ))}

      {agents.length === 0 && (
        <p className="text-sm text-[#6a6b6c] text-center py-4">
          No agents detected.
        </p>
      )}
    </div>
  );
}
