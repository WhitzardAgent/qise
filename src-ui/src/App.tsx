import { useState, useEffect, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import StatusIndicator from "./components/StatusIndicator";
import ProxyToggle from "./components/ProxyToggle";
import GuardList from "./components/GuardList";
import EventLog from "./components/EventLog";
import AgentPanel from "./components/AgentPanel";
import { AppStatus, GuardInfo, SecurityEvent, AgentInfo } from "./lib/api";

function App() {
  const [status, setStatus] = useState<AppStatus | null>(null);
  const [guards, setGuards] = useState<GuardInfo[]>([]);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [agents, setAgents] = useState<AgentInfo[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadStatus();
    loadGuards();
    loadEvents();
    loadAgents();

    const interval = setInterval(loadStatus, 5000);
    return () => clearInterval(interval);
  }, []);

  async function loadStatus() {
    try {
      const s = await invoke<AppStatus>("get_status");
      setStatus(s);
    } catch (e) {
      console.error("Failed to load status:", e);
    } finally {
      setLoading(false);
    }
  }

  async function loadGuards() {
    try {
      const g = await invoke<GuardInfo[]>("get_guards");
      setGuards(g);
    } catch (e) {
      console.error("Failed to load guards:", e);
    }
  }

  async function loadEvents() {
    try {
      const ev = await invoke<SecurityEvent[]>("get_events", { limit: 50 });
      setEvents(ev);
    } catch (e) {
      console.error("Failed to load events:", e);
    }
  }

  async function loadAgents() {
    try {
      const a = await invoke<AgentInfo[]>("detect_agents");
      setAgents(a);
    } catch (e) {
      console.error("Failed to detect agents:", e);
    }
  }

  const handleEvent = useCallback((event: SecurityEvent) => {
    setEvents((prev) => [event, ...prev].slice(0, 50));
  }, []);

  async function handleToggle(enable: boolean) {
    try {
      await invoke("toggle_protection", { enable });
      await loadStatus();
      if (enable) {
        await loadGuards();
      }
    } catch (e) {
      console.error("Failed to toggle protection:", e);
    }
  }

  async function handleSetGuardMode(guardName: string, mode: string) {
    try {
      await invoke("set_guard_mode", { guardName, mode });
      await loadGuards();
    } catch (e) {
      console.error("Failed to set guard mode:", e);
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-screen bg-qise-deep">
        <p className="text-qise-yellow text-lg">Loading Qise...</p>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-qise-deep p-6">
      {/* Header */}
      <header className="flex items-center justify-between mb-8">
        <div className="flex items-center gap-4">
          <h1 className="text-2xl font-medium tracking-wide text-[#f9f9f9]">
            Qise
          </h1>
          <span className="text-sm text-[#6a6b6c] font-mono">v0.1.0</span>
        </div>
        <div className="flex items-center gap-4">
          <StatusIndicator
            enabled={status?.protection_enabled ?? false}
          />
          <ProxyToggle
            enabled={status?.protection_enabled ?? false}
            onToggle={handleToggle}
          />
        </div>
      </header>

      {/* Stats bar */}
      <div className="flex gap-4 mb-8">
        <div className="qise-card px-4 py-3 flex items-center gap-3">
          <div className="w-2 h-2 rounded-full bg-qise-red" />
          <span className="text-sm text-[#cecece]">
            Blocked: <span className="text-qise-red font-mono">{status?.blocked_count ?? 0}</span>
          </span>
        </div>
        <div className="qise-card px-4 py-3 flex items-center gap-3">
          <div className="w-2 h-2 rounded-full bg-qise-yellow" />
          <span className="text-sm text-[#cecece]">
            Warnings: <span className="text-qise-yellow font-mono">{status?.warning_count ?? 0}</span>
          </span>
        </div>
        <div className="qise-card px-4 py-3 flex items-center gap-3">
          <span className="text-sm text-[#9c9c9d]">
            Proxy: <span className="text-[#f9f9f9] font-mono">{status?.proxy_port ?? 8822}</span>
          </span>
        </div>
        <div className="qise-card px-4 py-3 flex items-center gap-3">
          <span className="text-sm text-[#9c9c9d]">
            Bridge: <span className="text-[#f9f9f9] font-mono">{status?.bridge_port ?? 8823}</span>
          </span>
        </div>
      </div>

      {/* Agents */}
      <section className="mb-8">
        <h2 className="text-lg font-medium text-[#f9f9f9] mb-4">Agents</h2>
        <AgentPanel agents={agents} onRefresh={loadAgents} />
      </section>

      {/* Guard List */}
      <section className="mb-8">
        <h2 className="text-lg font-medium text-[#f9f9f9] mb-4">Guards</h2>
        <GuardList guards={guards} onSetMode={handleSetGuardMode} />
      </section>

      {/* Event Log */}
      <section>
        <h2 className="text-lg font-medium text-[#f9f9f9] mb-4">Recent Events</h2>
        <EventLog events={events} onEvent={handleEvent} />
      </section>
    </div>
  );
}

export default App;
