import { useEffect } from "react";
import { listen } from "@tauri-apps/api/event";
import type { SecurityEvent } from "../lib/api";

interface EventLogProps {
  events: SecurityEvent[];
  onEvent: (event: SecurityEvent) => void;
}

function verdictBadgeClass(verdict: string): string {
  switch (verdict.toLowerCase()) {
    case "block":
      return "badge-block";
    case "warn":
      return "badge-warn";
    case "pass":
      return "badge-pass";
    default:
      return "badge-pass";
  }
}

export default function EventLog({ events, onEvent }: EventLogProps) {
  // Listen for real-time guard events from Tauri backend
  useEffect(() => {
    const unlisten = listen<Record<string, unknown>>("guard-event", (event) => {
      const payload = event.payload;
      // Extract guard results from the payload
      const guardResults = (payload.guard_results || []) as Array<{
        guard: string;
        verdict: string;
        message: string;
      }>;

      for (const gr of guardResults) {
        onEvent({
          timestamp: new Date().toISOString().replace("T", " ").slice(0, 19),
          guard_name: gr.guard,
          verdict: gr.verdict,
          message: gr.message,
        });
      }

      // If the overall action is block/warn with no individual results
      if (guardResults.length === 0 && (payload.action === "block" || payload.action === "warn")) {
        onEvent({
          timestamp: new Date().toISOString().replace("T", " ").slice(0, 19),
          guard_name: "proxy",
          verdict: String(payload.action),
          message: String(payload.block_reason || (Array.isArray(payload.warnings) ? payload.warnings.join("; ") : "") || ""),
        });
      }
    });

    return () => {
      unlisten.then((fn) => fn());
    };
  }, [onEvent]);

  if (events.length === 0) {
    return (
      <div className="qise-card p-6 shadow-double-ring text-center">
        <p className="text-sm text-[#6a6b6c]">
          No security events yet. Enable protection to start monitoring.
        </p>
      </div>
    );
  }

  return (
    <div className="qise-card p-4 shadow-double-ring space-y-2">
      {events.map((event, i) => (
        <div
          key={i}
          className={`flex items-center gap-3 py-2 px-3 rounded-lg ${
            event.verdict.toLowerCase() === "block"
              ? "border-l-2 border-[#FF6363]"
              : ""
          }`}
        >
          <span className="text-xs font-mono text-[#6a6b6c]">
            {event.timestamp}
          </span>
          <span className="text-xs font-mono text-[#9c9c9d]">
            {event.guard_name}
          </span>
          <span className={verdictBadgeClass(event.verdict)}>
            {event.verdict}
          </span>
          <span className="text-sm text-[#cecece] truncate">
            {event.message}
          </span>
        </div>
      ))}
    </div>
  );
}
