import { useState, useEffect, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import StatusIndicator from "./components/StatusIndicator";
import ProxyToggle from "./components/ProxyToggle";
import GuardList from "./components/GuardList";
import EventLog from "./components/EventLog";
import AgentPanel from "./components/AgentPanel";
import ConfigPanel from "./components/ConfigPanel";
import { AppStatus, GuardInfo, SecurityEvent, AgentInfo } from "./lib/api";

type TabId = "dashboard" | "configuration";

function App() {
  const [activeTab, setActiveTab] = useState<TabId>("dashboard");
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

  // Listen for tray toggle events
  useEffect(() => {
    let unlisten: (() => void) | null = null;
    import("@tauri-apps/api/event").then(({ listen }) => {
      listen<boolean>("toggle-protection", (event) => {
        handleToggle(event.payload);
      }).then((fn) => { unlisten = fn; });
    });
    return () => { unlisten?.(); };
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
    <div className="min-h-screen bg-qise-deep p-6 pb-20">
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
        <div className="qise-card px-4 py-3 flex items-center gap-3">
          <div className={`w-2 h-2 rounded-full ${
            status?.slm_status === "local" ? "bg-qise-green" :
            status?.slm_status === "cloud" ? "bg-qise-yellow" :
            "bg-[#6a6b6c]"
          }`} />
          <span className="text-sm text-[#9c9c9d]">
            SLM: <span className="text-[#f9f9f9] font-mono">{status?.slm_status ?? "unavailable"}</span>
            {status?.slm_latency_ms ? (
              <span className="text-[#6a6b6c] ml-1">{status.slm_latency_ms}ms</span>
            ) : null}
          </span>
        </div>
      </div>

      {/* Tab content */}
      {activeTab === "dashboard" ? (
        <>
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
        </>
      ) : (
        <ConfigPanel />
      )}

      {/* Tab bar — fixed bottom */}
      <div className="fixed bottom-0 left-0 right-0 bg-qise-deep border-t border-[rgba(255,255,255,0.06)]">
        <div className="flex justify-center gap-2 p-3">
          {(["dashboard", "configuration"] as TabId[]).map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`px-5 py-2 rounded-[43px] text-sm font-medium transition-all ${
                activeTab === tab
                  ? "bg-[hsla(0,0%,100%,0.815)] text-[#07080a]"
                  : "text-[#9c9c9d] hover:text-[#cecece]"
              }`}
            >
              {tab === "dashboard" ? "Dashboard" : "Configuration"}
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}

export default App;
