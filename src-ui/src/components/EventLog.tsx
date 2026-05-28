import { useEffect, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { makeRealtimeEvent } from "../lib/api";
import type { EventEvidence, SecurityEvent } from "../lib/api";

interface EventLogProps {
  events: SecurityEvent[];
  onEvent: (event: SecurityEvent) => void;
}

type EventFilter = "all" | "blocked" | "warnings";

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

function eventVerdict(event: SecurityEvent): string {
  return event.decision.verdict || "pass";
}

function evidenceText(evidence: EventEvidence): string {
  return evidence.message || evidence.snippet || evidence.rule_id || evidence.type;
}

function eventMessage(event: SecurityEvent): string {
  const firstEvidence = event.evidence.find((item) => item.message || item.snippet);
  return (
    firstEvidence?.message ||
    firstEvidence?.snippet ||
    event.recommendation ||
    event.action.resource ||
    event.risk.category
  );
}

function eventGuardName(event: SecurityEvent): string {
  return event.evidence.find((item) => item.guard)?.guard || event.action.name || event.risk.category || event.source;
}

export default function EventLog({ events, onEvent }: EventLogProps) {
  const [filter, setFilter] = useState<EventFilter>("all");

  // Listen for real-time guard events from Tauri backend
  useEffect(() => {
    const unlisten = listen<Record<string, unknown>>("guard-event", (event) => {
      makeRealtimeEvent(event.payload).forEach(onEvent);
    });

    return () => {
      unlisten.then((fn) => fn());
    };
  }, [onEvent]);

  const filteredEvents = events.filter((e) => {
    const verdict = eventVerdict(e).toLowerCase();
    if (filter === "blocked") return verdict === "block";
    if (filter === "warnings") return verdict === "warn";
    return true;
  });

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
    <div>
      {/* Filter buttons */}
      <div className="flex gap-2 mb-3">
        {(["all", "blocked", "warnings"] as EventFilter[]).map((f) => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            className={`px-4 py-1 rounded-[43px] text-xs font-medium transition-all ${
              filter === f
                ? "bg-[hsla(0,0%,100%,0.815)] text-[#07080a]"
                : "bg-[#1b1c1e] text-[#9c9c9d] hover:text-[#cecece]"
            }`}
          >
            {f.charAt(0).toUpperCase() + f.slice(1)}
            {f === "all" && ` (${events.length})`}
            {f === "blocked" && ` (${events.filter((e) => eventVerdict(e).toLowerCase() === "block").length})`}
            {f === "warnings" && ` (${events.filter((e) => eventVerdict(e).toLowerCase() === "warn").length})`}
          </button>
        ))}
      </div>

      <div className="qise-card p-4 shadow-double-ring space-y-2">
        {filteredEvents.length === 0 ? (
          <p className="text-sm text-[#6a6b6c] text-center py-4">
            No {filter} events
          </p>
        ) : (
          filteredEvents.map((event, i) => (
            <div
              key={i}
              className={`flex items-center gap-3 py-2 px-3 rounded-lg animate-fade-in ${
                eventVerdict(event).toLowerCase() === "block"
                  ? "border-l-2 border-[#FF6363]"
                  : ""
              }`}
            >
              <span className="text-xs font-mono text-[#6a6b6c]">
                {event.timestamp.replace("T", " ").slice(0, 19)}
              </span>
              <span className="text-xs font-mono text-[#9c9c9d]">
                {eventGuardName(event)}
              </span>
              <span className={verdictBadgeClass(eventVerdict(event))}>
                {eventVerdict(event)}
              </span>
              <span className="text-sm text-[#cecece] truncate">
                {event.evidence.length > 0 ? evidenceText(event.evidence[0]) : eventMessage(event)}
              </span>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
