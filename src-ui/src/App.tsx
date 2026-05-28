import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { ReactNode } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import AgentPanel from "./components/AgentPanel";
import ConfigPanel from "./components/ConfigPanel";
import DiagnosticsPanel from "./components/DiagnosticsPanel";
import EventLog from "./components/EventLog";
import GuardList from "./components/GuardList";
import {
  AgentInfo,
  AppStatus,
  GuardInfo,
  ProtectedAgentRecord,
  SecurityEvent,
  normalizeSecurityEvent,
  normalizeStatus,
  portLabel,
  slmLabel,
  slmTone,
  statusEventCounts,
  statusProtectionEnabled,
} from "./lib/api";

type PageId =
  | "home"
  | "shield"
  | "preflight"
  | "events"
  | "rules"
  | "slm"
  | "doctor"
  | "observer"
  | "backup"
  | "integrations"
  | "advanced"
  | "settings";

type ScanMode = "all" | "agent" | "skill" | "mcp" | "agent-config";
type GuardPreset = "balanced" | "strict" | "observe";
type Pipeline = "ingress" | "egress" | "output";

interface CommandText {
  stdout: string;
  stderr: string;
  success: boolean;
  exit_status: string;
}

interface ScanFinding {
  verdict?: string;
  category?: string;
  severity?: string;
  confidence?: number;
  message?: string;
  path?: string;
  snippet?: string;
  rule_id?: string;
}

interface ScanReport {
  target?: string;
  target_type?: string;
  verdict?: string;
  risk?: {
    category?: string;
    severity?: string;
  };
  findings?: ScanFinding[];
  recommendation?: string;
}

interface ScanSkip {
  agent?: string;
  target_type?: string;
  reason?: string;
}

interface ScanCollection {
  target?: string;
  target_type?: string;
  verdict?: string;
  reports?: ScanReport[];
  skipped?: ScanSkip[];
  recommendation?: string;
  summary?: {
    reports?: number;
    block?: number;
    warn?: number;
    pass?: number;
    skipped?: number;
  };
}

type ScanResult = ScanReport | ScanCollection;

type TaskStatus = "idle" | "running" | "succeeded" | "failed";

interface TaskState<T> {
  status: TaskStatus;
  title: string;
  detail?: string;
  action?: string;
  startedAt?: string;
  finishedAt?: string;
  result?: T;
  error?: string;
}

interface PreflightRequest {
  mode: ScanMode;
  path: string;
  agent: string;
  selectedAgents: string[];
  includeSkills: boolean;
  includeMcp: boolean;
  includeAgentConfig: boolean;
}

interface SlmStartRequest {
  model: string;
  baseUrl: string;
  apiKey: string;
  timeoutMs: number;
  noInstall: boolean;
  noPull: boolean;
  noVerify: boolean;
}

interface FeatureItem {
  id: PageId;
  glyph: string;
  title: string;
  subtitle: string;
  summary: string;
  accent: string;
}

const FEATURES: FeatureItem[] = [
  {
    id: "preflight",
    glyph: "PF",
    title: "Preflight Scan",
    subtitle: "Scan before you trust it",
    summary: "Skill, MCP and Agent config checks",
    accent: "var(--qise-blue)",
  },
  {
    id: "shield",
    glyph: "AS",
    title: "Agent Shield",
    subtitle: "Protect your Agent",
    summary: "Codex, OpenClaw, Claude Code, custom",
    accent: "var(--qise-green)",
  },
  {
    id: "events",
    glyph: "EV",
    title: "Security Events",
    subtitle: "See what Qise blocked",
    summary: "Runtime and preflight evidence",
    accent: "var(--qise-red)",
  },
  {
    id: "rules",
    glyph: "GR",
    title: "Protection Rules",
    subtitle: "Tune guard behavior",
    summary: "Ingress, egress and output guards",
    accent: "var(--qise-yellow)",
  },
  {
    id: "slm",
    glyph: "AI",
    title: "Local SLM",
    subtitle: "Optional second layer",
    summary: "Ollama or OpenAI-compatible model",
    accent: "var(--qise-blue)",
  },
  {
    id: "doctor",
    glyph: "DR",
    title: "System Doctor",
    subtitle: "Check readiness",
    summary: "Runtime, services and config checks",
    accent: "var(--qise-green)",
  },
  {
    id: "observer",
    glyph: "RT",
    title: "Runtime Observer",
    subtitle: "Record real behavior",
    summary: "Generate qise run commands",
    accent: "var(--qise-yellow)",
  },
  {
    id: "backup",
    glyph: "BR",
    title: "Backup & Restore",
    subtitle: "Recover Agent configs",
    summary: "View backups and restore safely",
    accent: "var(--qise-green)",
  },
  {
    id: "integrations",
    glyph: "IN",
    title: "Integrations",
    subtitle: "SDK, MCP and adapters",
    summary: "Nanobot, Hermes, NexAU, LangGraph",
    accent: "var(--qise-blue)",
  },
  {
    id: "settings",
    glyph: "CF",
    title: "Settings",
    subtitle: "App and model config",
    summary: "Proxy, upstream, SLM and guards",
    accent: "var(--text-tertiary)",
  },
  {
    id: "advanced",
    glyph: "LB",
    title: "Advanced Lab",
    subtitle: "Test guards manually",
    summary: "check and context tools",
    accent: "var(--qise-red)",
  },
];

const GUARD_PRESETS: Record<GuardPreset, Partial<Record<string, string>>> = {
  balanced: {
    command: "enforce",
    credential: "enforce",
    filesystem: "enforce",
    network: "enforce",
    tool_policy: "enforce",
    prompt: "observe",
    reasoning: "observe",
    output: "observe",
    exfil: "observe",
    resource: "observe",
    audit: "observe",
    context: "observe",
    tool_sanity: "observe",
    supply_chain: "observe",
  },
  strict: {
    command: "enforce",
    credential: "enforce",
    filesystem: "enforce",
    network: "enforce",
    tool_policy: "enforce",
    prompt: "enforce",
    reasoning: "enforce",
    output: "enforce",
    exfil: "enforce",
    resource: "enforce",
    audit: "observe",
    context: "enforce",
    tool_sanity: "enforce",
    supply_chain: "enforce",
  },
  observe: {
    command: "observe",
    credential: "observe",
    filesystem: "observe",
    network: "observe",
    tool_policy: "observe",
    prompt: "observe",
    reasoning: "observe",
    output: "observe",
    exfil: "observe",
    resource: "observe",
    audit: "observe",
    context: "observe",
    tool_sanity: "observe",
    supply_chain: "observe",
  },
};

const ADAPTERS = ["nanobot", "hermes", "nexau", "langgraph", "openai-agents"] as const;

function eventVerdict(event: SecurityEvent): string {
  return event.decision.verdict || "pass";
}

function eventSummary(event: SecurityEvent): string {
  const evidence = event.evidence.find((item) => item.message || item.snippet);
  return evidence?.message || evidence?.snippet || event.recommendation || event.action.resource || event.risk.category;
}

function badgeClass(verdict?: string): string {
  switch ((verdict || "pass").toLowerCase()) {
    case "block":
      return "badge-block";
    case "warn":
      return "badge-warn";
    default:
      return "badge-pass";
  }
}

function resultText(value: unknown): string {
  if (typeof value === "string") return value;
  return JSON.stringify(value, null, 2);
}

function commandText(result: CommandText): string {
  return result.stdout || result.stderr || `Qise command exited with ${result.exit_status}.`;
}

function requireCommandSuccess(result: CommandText): string {
  const output = commandText(result);
  if (!result.success) {
    throw new Error(output);
  }
  return output;
}

async function copyText(text: string): Promise<void> {
  await navigator.clipboard.writeText(text);
}

function Spinner({ tone = "light" }: { tone?: "light" | "blue" }) {
  return (
    <span
      className={`qise-spinner ${tone === "blue" ? "qise-spinner-blue" : ""}`}
      aria-hidden="true"
    />
  );
}

function BusyButton({
  children,
  busy,
  busyLabel,
  variant = "primary",
  className = "",
  disabled,
  onClick,
}: {
  children: ReactNode;
  busy?: boolean;
  busyLabel?: string;
  variant?: "primary" | "secondary" | "danger";
  className?: string;
  disabled?: boolean;
  onClick?: () => void;
}) {
  const variantClass = {
    primary: "qise-action-primary",
    secondary: "qise-action-secondary",
    danger: "qise-action-danger",
  }[variant];

  return (
    <button
      className={`qise-action ${variantClass} ${className}`}
      disabled={disabled || busy}
      onClick={onClick}
    >
      {busy && <Spinner tone={variant === "primary" ? "light" : "blue"} />}
      <span>{busy ? busyLabel || "Working..." : children}</span>
    </button>
  );
}

function StatusPill({
  children,
  tone = "neutral",
}: {
  children: ReactNode;
  tone?: "green" | "yellow" | "red" | "blue" | "neutral";
}) {
  return <span className={`qise-pill qise-pill-${tone}`}>{children}</span>;
}

function OperationPanel({
  title,
  detail,
  tone = "blue",
}: {
  title: string;
  detail?: string;
  tone?: "green" | "yellow" | "red" | "blue";
}) {
  return (
    <div className={`qise-operation qise-operation-${tone}`}>
      <div className="flex items-center gap-2">
        {tone === "blue" && <Spinner tone="blue" />}
        <p className="text-sm font-semibold text-[var(--text-primary)]">{title}</p>
      </div>
      {detail && <p className="mt-1 text-xs text-[var(--text-tertiary)]">{detail}</p>}
    </div>
  );
}

function createTask<T>(title = "No operation yet."): TaskState<T> {
  return { status: "idle", title };
}

function runningTask<T>(title: string, detail?: string, action?: string): TaskState<T> {
  return {
    status: "running",
    title,
    detail,
    action,
    startedAt: new Date().toISOString(),
  };
}

function succeededTask<T>(previous: TaskState<T>, result: T, detail?: string): TaskState<T> {
  return {
    ...previous,
    status: "succeeded",
    detail: detail ?? previous.detail,
    result,
    error: undefined,
    finishedAt: new Date().toISOString(),
  };
}

function failedTask<T>(previous: TaskState<T>, error: unknown): TaskState<T> {
  return {
    ...previous,
    status: "failed",
    error: String(error),
    finishedAt: new Date().toISOString(),
  };
}

function taskTone(task: TaskState<unknown>): "green" | "yellow" | "red" | "blue" {
  if (task.status === "running") return "blue";
  if (task.status === "succeeded") return "green";
  if (task.status === "failed") return "red";
  return "yellow";
}

function taskStatusText(task: TaskState<unknown>): string {
  if (task.status === "running") return "Running";
  if (task.status === "succeeded") return "Done";
  if (task.status === "failed") return "Failed";
  return "Idle";
}

function TaskStrip({ tasks }: { tasks: TaskState<unknown>[] }) {
  const visible = tasks.filter((task) => task.status !== "idle");
  if (visible.length === 0) return null;
  return (
    <div className="qise-card mb-5 grid gap-2 p-3 md:grid-cols-3">
      {visible.map((task, index) => (
        <div key={`${task.title}-${index}`} className="rounded-lg bg-[var(--bg-card)] p-3">
          <div className="flex items-center justify-between gap-2">
            <p className="truncate text-sm font-semibold text-[var(--text-primary)]">{task.title}</p>
            <StatusPill tone={taskTone(task)}>{taskStatusText(task)}</StatusPill>
          </div>
          <p className="mt-1 truncate text-xs text-[var(--text-tertiary)]">
            {task.status === "failed" ? task.error : task.detail || task.startedAt || ""}
          </p>
        </div>
      ))}
    </div>
  );
}

function isScanCollection(result: ScanResult | null): result is ScanCollection {
  return Boolean(result && Array.isArray((result as ScanCollection).reports));
}

function scanReports(result: ScanResult | null): ScanReport[] {
  if (!result) return [];
  return isScanCollection(result) ? result.reports ?? [] : [result as ScanReport];
}

function scanFindingCount(result: ScanResult | null): number {
  return scanReports(result).reduce((total, report) => total + (report.findings?.length ?? 0), 0);
}

function scanSummary(result: ScanResult | null) {
  const reports = scanReports(result);
  if (!result) {
    return { reports: 0, block: 0, warn: 0, pass: 0, skipped: 0 };
  }
  if (isScanCollection(result) && result.summary) {
    return {
      reports: result.summary.reports ?? reports.length,
      block: result.summary.block ?? 0,
      warn: result.summary.warn ?? 0,
      pass: result.summary.pass ?? 0,
      skipped: result.summary.skipped ?? result.skipped?.length ?? 0,
    };
  }
  return {
    reports: reports.length,
    block: reports.filter((report) => report.verdict === "block").length,
    warn: reports.filter((report) => report.verdict === "warn").length,
    pass: reports.filter((report) => report.verdict === "pass").length,
    skipped: 0,
  };
}

function BootScreen({ hint }: { hint: string }) {
  return (
    <div className="min-h-screen bg-qise-deep px-5 pb-16 pt-4">
      <div className="mx-auto max-w-6xl">
        <div className="mb-5 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-[var(--qise-blue)] text-sm font-bold text-white">
              Q
            </div>
            <div>
              <h1 className="text-xl font-semibold text-[var(--text-primary)]">Qise</h1>
              <p className="text-sm text-[var(--text-tertiary)]">AI Agent Security</p>
            </div>
          </div>
          <div className="flex gap-2">
            <div className="h-9 w-20 animate-pulse rounded-lg bg-[var(--bg-surface)]" />
            <div className="h-9 w-16 animate-pulse rounded-lg bg-[var(--bg-surface)]" />
          </div>
        </div>
        <div className="qise-hero mb-4 p-6">
          <div className="h-7 w-72 max-w-full animate-pulse rounded-xl bg-[var(--bg-card)]" />
          <div className="mt-4 h-4 w-[520px] max-w-full animate-pulse rounded bg-[var(--bg-card)]" />
          <p className="mt-5 text-sm text-[var(--text-tertiary)]">{hint}</p>
          <div className="mt-6 flex gap-3">
            <div className="h-10 w-36 animate-pulse rounded-[43px] bg-[var(--bg-card)]" />
            <div className="h-10 w-28 animate-pulse rounded-[43px] bg-[var(--bg-card)]" />
          </div>
        </div>
        <div className="mb-4 grid gap-4 md:grid-cols-3">
          {Array.from({ length: 3 }).map((_, index) => (
            <div key={index} className="qise-card h-24 animate-pulse" />
          ))}
        </div>
        <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
          {Array.from({ length: 8 }).map((_, index) => (
            <div key={index} className="qise-card h-24 animate-pulse" />
          ))}
        </div>
      </div>
    </div>
  );
}

function ErrorBanner({ error, onDismiss }: { error: string | null; onDismiss: () => void }) {
  if (!error) return null;
  return (
    <div className="qise-card mb-5 flex items-start justify-between gap-3 border-l-2 border-qise-red p-3">
      <p className="text-sm text-qise-red">{error}</p>
      <button
        className="shrink-0 rounded-[43px] bg-[var(--bg-card)] px-3 py-1 text-xs text-[var(--text-tertiary)]"
        onClick={onDismiss}
      >
        Dismiss
      </button>
    </div>
  );
}

function PageHeader({
  page,
  onHome,
  right,
}: {
  page: PageId;
  onHome: () => void;
  right?: ReactNode;
}) {
  const feature = FEATURES.find((item) => item.id === page);
  if (page === "home") return null;
  return (
    <div className="qise-page-heading mb-5 flex flex-wrap items-center justify-between gap-3">
      <div className="flex min-w-0 items-center gap-3">
        <button className="qise-back-button" onClick={onHome} title="Back to Home">
          <span aria-hidden="true">{"<-"}</span>
          <span>Back to Home</span>
        </button>
        <div className="h-7 w-px bg-[var(--border-subtle)]" />
        <div className="min-w-0">
          <h2 className="truncate text-xl font-semibold text-[var(--text-primary)]">{feature?.title}</h2>
          <p className="text-sm text-[var(--text-tertiary)]">Qise Desktop</p>
        </div>
      </div>
      {right}
    </div>
  );
}

function MetricTile({
  label,
  value,
  tone = "neutral",
}: {
  label: string;
  value: string | number;
  tone?: "neutral" | "green" | "yellow" | "red" | "blue";
}) {
  const color = {
    neutral: "var(--text-tertiary)",
    green: "var(--qise-green)",
    yellow: "var(--qise-yellow)",
    red: "var(--qise-red)",
    blue: "var(--qise-blue)",
  }[tone];

  return (
    <div className="rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-card)] px-3 py-2">
      <p className="text-xs text-[var(--text-tertiary)]">{label}</p>
      <p className="mt-1 font-mono text-lg font-semibold" style={{ color }}>
        {value}
      </p>
    </div>
  );
}

function StatusFooter({ status }: { status: AppStatus | null }) {
  return (
    <footer className="fixed bottom-0 left-0 right-0 z-40 border-t border-[var(--border-subtle)] bg-[rgba(243,248,252,0.94)] backdrop-blur">
      <div className="mx-auto grid max-w-6xl grid-cols-1 gap-2 px-5 py-2 text-xs text-[var(--text-tertiary)] sm:grid-cols-3">
        <span className="flex items-center gap-2">
          <span className="h-2 w-2 rounded-full bg-qise-green" />
          Proxy: <span className="font-mono text-[var(--text-primary)]">{portLabel(status?.proxy, status?.proxy_port ?? 8822)}</span>
        </span>
        <span className="flex items-center justify-start gap-2 sm:justify-center">
          <span className="h-2 w-2 rounded-full bg-qise-yellow" />
          SLM: <span className="font-mono text-[var(--text-primary)]">{slmLabel(status)}</span>
        </span>
        <span className="text-left sm:text-right">
          <span className="font-mono text-[var(--text-primary)]">v0.2.0</span>
        </span>
      </div>
    </footer>
  );
}

function TopBar({
  activePage,
  status,
  onOpen,
}: {
  activePage: PageId;
  status: AppStatus | null;
  onOpen: (page: PageId) => void;
}) {
  const protectedEnabled = statusProtectionEnabled(status);
  return (
    <header className="qise-topbar mb-5 flex flex-wrap items-center justify-between gap-4">
      <button className="text-left" onClick={() => onOpen("home")}>
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-[var(--qise-blue)] text-lg font-bold text-white shadow-[0_8px_20px_rgba(40,120,216,0.25)]">
            Q
          </div>
          <div>
            <h1 className="text-xl font-semibold leading-tight text-[var(--text-primary)]">Qise</h1>
            <p className="text-sm text-[var(--text-tertiary)]">AI Agent Security</p>
          </div>
        </div>
      </button>
      <div className="flex flex-wrap items-center gap-3">
        <StatusPill tone={protectedEnabled ? "green" : "yellow"}>
          {protectedEnabled ? "Protection ON" : "Setup needed"}
        </StatusPill>
        <button
          className={`qise-nav-button ${
            activePage === "doctor"
              ? "qise-nav-button-active"
              : ""
          }`}
          onClick={() => onOpen("doctor")}
        >
          Doctor
        </button>
        <button
          className={`qise-nav-button ${
            activePage === "settings"
              ? "qise-nav-button-active"
              : ""
          }`}
          onClick={() => onOpen("settings")}
        >
          Settings
        </button>
      </div>
    </header>
  );
}

function HomePage({
  status,
  guards,
  agents,
  onOpen,
  onDetectAgents,
  detectingAgents,
}: {
  status: AppStatus | null;
  guards: GuardInfo[];
  agents: AgentInfo[];
  onOpen: (page: PageId) => void;
  onDetectAgents: () => void;
  detectingAgents: boolean;
}) {
  const protectedEnabled = statusProtectionEnabled(status);
  const counts = statusEventCounts(status);
  const slmState = slmLabel(status);
  const slmStateTone = slmTone(status);
  const installedAgents = agents.filter((agent) => agent.installed);
  const protectedAgents = agents.filter((agent) => agent.protected);

  const featureBadges: Partial<Record<PageId, string>> = {
    events: `${counts.blocked}/${counts.warnings}`,
    rules: `${guards.length || 14}`,
    slm: slmState,
    shield: `${protectedAgents.length}/${installedAgents.length || agents.length || 0}`,
    backup: `${Object.keys(status?.protected_agents ?? {}).length}`,
  };

  const STATUS_GLYPH = protectedEnabled ? "\u{1F6E1}" : "⚠";
  const mainStatus = protectedEnabled ? "Protection is ON" : "Protection needs setup";
  const statusDetail = protectedEnabled
    ? `${protectedAgents.length} agents protected · Blocked ${counts.blocked} threats today · ${counts.warnings} warnings`
    : `${installedAgents.length || agents.length || 0} agents detected · Run Preflight or protect an Agent to start`;

  const coreFeatures = FEATURES.filter((f) =>
    ["preflight", "shield", "events", "slm"].includes(f.id)
  );
  const moreFeatures = FEATURES.filter((f) =>
    ["rules", "doctor", "observer", "backup", "integrations", "advanced", "settings"].includes(f.id)
  );

  // Helper: feature card with icon + text
  function FeatureCardLarge({ item, badge }: { item: FeatureItem; badge?: string }) {
    const iconBg = `color-mix(in srgb, ${item.accent} 12%, white)`;
    return (
      <button
        className="qise-feature-card group"
        onClick={() => onOpen(item.id)}
      >
        <div
          className="qise-feature-icon shrink-0"
          style={{
            color: item.accent,
            backgroundColor: iconBg,
            border: `1px solid color-mix(in srgb, ${item.accent} 22%, white)`,
          }}
        >
          {item.glyph}
        </div>
        <div className="qise-feature-card-body">
          <div className="qise-feature-card-title">{item.title}</div>
          <div className="qise-feature-card-subtitle">{item.subtitle}</div>
        </div>
        {badge && (
          <span className="rounded-full bg-[var(--bg-card)] px-2 py-1 text-[11px] font-mono font-bold text-[var(--text-tertiary)] ring-1 ring-[var(--border-subtle)] shrink-0">
            {badge}
          </span>
        )}
      </button>
    );
  }

  return (
    <div className="space-y-5">
      {/* === STATUS BANNER === */}
      <section className={`qise-hero ${protectedEnabled ? "qise-hero-on" : "qise-hero-warn"}`}>
        <div className="flex flex-col gap-5 p-6 md:flex-row md:items-center md:justify-between">
          <div className="flex min-w-0 items-start gap-5">
            <div className={`qise-hero-icon ${protectedEnabled ? "qise-hero-icon-on" : "qise-hero-icon-warn"}`}>
              {STATUS_GLYPH}
            </div>
            <div className="min-w-0">
              <h2 className="text-3xl font-bold text-[var(--text-primary)]">{mainStatus}</h2>
              <p className="mt-2 text-base text-[var(--text-secondary)]">{statusDetail}</p>
              <p className="mt-2 text-sm text-[var(--text-dim)]">
                Local-first guard pipeline is {slmStateTone === "ready" ? "running with SLM review." : "active in rule-only mode."}
              </p>
            </div>
          </div>
          <div className="flex shrink-0 flex-wrap gap-3 md:justify-end">
            <BusyButton variant="primary" busy={detectingAgents} busyLabel="Detecting..." onClick={onDetectAgents}>
              一键检测智能体
            </BusyButton>
            <BusyButton variant="secondary" onClick={() => onOpen("preflight")}>
              Preflight Scan
            </BusyButton>
          </div>
        </div>
      </section>

      {/* === AGENT CARDS === */}
      <section>
        <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
          <div>
            <div className="qise-section-label mb-0">Detected Agents</div>
            <p className="mt-1 text-sm text-[var(--text-tertiary)]">
              这里只显示当前电脑实际检测到的 Agent。
            </p>
          </div>
          <BusyButton variant="secondary" busy={detectingAgents} busyLabel="Detecting..." onClick={onDetectAgents}>
            一键检测智能体
          </BusyButton>
        </div>
        {installedAgents.length > 0 ? (
          <div className="grid gap-4 md:grid-cols-3">
            {installedAgents.map((agent) => {
            const dotClass = agent.protected ? "qise-agent-dot-green" : agent.installed ? "qise-agent-dot-yellow" : "qise-agent-dot-muted";
            const statusLabel = agent.protected ? "Protected" : agent.installed ? "Available" : "Not found";

            return (
              <button key={agent.key} className="qise-agent-card group" onClick={() => onOpen("shield")}>
                <div className="flex items-center gap-4">
                  <span className={`qise-agent-dot ${dotClass}`} />
                  <div>
                    <p className="text-base font-semibold text-[var(--text-primary)]">{agent.name}</p>
                    <p className="text-sm text-[var(--text-secondary)]">{statusLabel}</p>
                  </div>
                </div>
                <StatusPill tone={agent.protected ? "green" : "yellow"}>
                  {agent.protected ? "Protected" : "Detected"}
                </StatusPill>
              </button>
            );
            })}
          </div>
        ) : (
          <div className="qise-card p-6 text-center">
            <p className="text-sm font-semibold text-[var(--text-primary)]">No supported Agent detected yet.</p>
            <p className="mt-2 text-sm text-[var(--text-tertiary)]">
              安装或删除 Agent 后，点击“一键检测智能体”即可刷新这里的列表。
            </p>
          </div>
        )}
      </section>

      {/* === CORE FUNCTIONS === */}
      <section>
        <div className="qise-section-label">Core Protection</div>
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {coreFeatures.map((item) => (
            <FeatureCardLarge key={item.id} item={item} badge={featureBadges[item.id]} />
          ))}
        </div>
      </section>

      {/* === SUMMARY + MORE === */}
      <section className="grid gap-5 lg:grid-cols-[0.95fr_1.05fr]">
        <div>
          <div className="qise-section-label">Today&apos;s Summary</div>
          <div className="qise-card grid gap-3 p-4 sm:grid-cols-4">
            <MetricTile label="Protected" value={protectedAgents.length} tone={protectedEnabled ? "green" : "neutral"} />
            <MetricTile label="Blocked" value={counts.blocked} tone={counts.blocked > 0 ? "red" : "neutral"} />
            <MetricTile label="Warnings" value={counts.warnings} tone={counts.warnings > 0 ? "yellow" : "neutral"} />
            <MetricTile label="SLM" value={slmStateTone === "ready" ? "ON" : slmState} tone={slmStateTone === "ready" ? "green" : "yellow"} />
          </div>
        </div>

        <div>
          <div className="qise-section-label">More Tools</div>
          <div className="grid gap-3 sm:grid-cols-4">
            {moreFeatures.map((item) => (
              <button
                key={item.id}
                className="qise-card px-3 py-3 text-center text-xs font-semibold text-[var(--text-secondary)] hover:border-[var(--border-strong)]"
                onClick={() => onOpen(item.id)}
              >
                {item.title}
              </button>
            ))}
          </div>
        </div>
      </section>
    </div>
  );
}

function AgentShieldPage({
  agents,
  task,
  onProtectAgent,
  onRestoreAgent,
  onRestoreAll,
  onStopServices,
  onProtectCustom,
}: {
  agents: AgentInfo[];
  task: TaskState<string>;
  onProtectAgent: (agent: AgentInfo) => void;
  onRestoreAgent: (agent: AgentInfo) => void;
  onRestoreAll: () => void;
  onStopServices: () => void;
  onProtectCustom: (baseUrl: string) => void;
}) {
  const [customBaseUrl, setCustomBaseUrl] = useState("");
  const busy = task.status === "running";
  const output = task.status === "failed" ? task.error : task.result;

  return (
    <div className="grid gap-5 xl:grid-cols-[1.35fr_0.65fr]">
      <section>
        <AgentPanel agents={agents} task={task} onProtect={onProtectAgent} onRestore={onRestoreAgent} />
      </section>
      <aside className="space-y-4">
        <div className="qise-card p-5">
          <h3 className="text-sm font-semibold uppercase text-[var(--text-primary)]">Shield Operations</h3>
          <p className="mt-2 text-sm leading-6 text-[var(--text-secondary)]">
            Protect patches the selected Agent config to route through Qise proxy and records a restorable backup.
          </p>
          <div className="mt-4 space-y-2">
            <BusyButton className="w-full" variant="secondary" busy={busy && task.action === "restore-all"} busyLabel="Restoring..." disabled={busy} onClick={onRestoreAll}>
              Restore All Agents
            </BusyButton>
            <BusyButton className="w-full" variant="secondary" busy={busy && task.action === "stop"} busyLabel="Stopping..." disabled={busy} onClick={onStopServices}>
              Stop Qise Services
            </BusyButton>
          </div>
        </div>
        <div className="qise-card p-5">
          <h3 className="text-sm font-semibold uppercase text-[var(--text-primary)]">Custom Agent</h3>
          <p className="mt-2 text-sm leading-6 text-[var(--text-secondary)]">
            Route an OpenAI-compatible custom Agent through Qise by providing its upstream base URL.
          </p>
          <label className="mt-3 block">
            <span className="text-xs text-[var(--text-tertiary)]">Upstream base URL</span>
            <input
              className="qise-input"
              value={customBaseUrl}
              onChange={(event) => setCustomBaseUrl(event.target.value)}
              placeholder="https://api.example.com/v1"
            />
          </label>
          <BusyButton
            className="mt-4 w-full"
            busy={busy && task.action === "protect:custom"}
            busyLabel="Protecting..."
            disabled={busy || !customBaseUrl.trim()}
            onClick={() => onProtectCustom(customBaseUrl)}
          >
            Protect Custom Agent
          </BusyButton>
        </div>
        {busy && (
          <OperationPanel title={task.title} detail={task.detail || "Qise is applying this operation in the background."} />
        )}
        {!busy && output && (
          <pre className={`qise-card max-h-64 overflow-auto p-4 text-xs ${task.status === "failed" ? "text-qise-red" : "text-[var(--text-secondary)]"}`}>{output}</pre>
        )}
      </aside>
    </div>
  );
}

function BackupRestorePage({
  status,
  onRefresh,
  setError,
}: {
  status: AppStatus | null;
  onRefresh: () => Promise<void>;
  setError: (error: string | null) => void;
}) {
  const [busy, setBusy] = useState<string | null>(null);
  const [output, setOutput] = useState("");
  const records = Object.entries(status?.protected_agents ?? {}) as [string, ProtectedAgentRecord][];

  async function restoreAgent(agent: string) {
    setBusy(agent);
    setError(null);
    try {
      await invoke("restore_agent", { agent });
      setOutput(`Restored ${agent}.`);
      await onRefresh();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(null);
    }
  }

  async function restoreAll() {
    if (!window.confirm("Restore all Agent configs modified by Qise?")) return;
    setBusy("all");
      setError(null);
    try {
      const result = await invoke<CommandText>("restore_all_agents");
      setOutput(requireCommandSuccess(result));
      await onRefresh();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="grid gap-5 xl:grid-cols-[1.2fr_0.8fr]">
      <section className="qise-card p-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h3 className="text-xl font-semibold text-[var(--text-primary)]">Agent Config Backups</h3>
            <p className="mt-1 text-sm text-[var(--text-tertiary)]">Qise keeps the original Agent config before applying protection.</p>
          </div>
          <BusyButton busy={busy === "all"} busyLabel="Restoring..." disabled={busy !== null || records.length === 0} onClick={restoreAll}>
            Restore All
          </BusyButton>
        </div>
        <div className="mt-5 space-y-3">
          {records.length === 0 ? (
            <p className="rounded-lg bg-[var(--bg-card)] p-4 text-sm text-[var(--text-dim)]">
              No protected Agent backups found yet. Protect an Agent first, then its backup will appear here.
            </p>
          ) : (
            records.map(([key, record]) => (
              <div key={key} className="rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-card)] p-4">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <StatusPill tone="green">backup ready</StatusPill>
                      <p className="font-semibold text-[var(--text-primary)]">{record.display_name || record.agent || key}</p>
                    </div>
                    <p className="mt-2 truncate font-mono text-xs text-[var(--text-tertiary)]">{record.config_path || "config path unavailable"}</p>
                    <p className="mt-1 truncate font-mono text-xs text-[var(--text-dim)]">{record.backup_path || "backup path unavailable"}</p>
                  </div>
                  <BusyButton
                    busy={busy === key}
                    busyLabel="Restoring..."
                    variant="secondary"
                    disabled={busy !== null}
                    onClick={() => restoreAgent(key)}
                  >
                    Restore
                  </BusyButton>
                </div>
              </div>
            ))
          )}
        </div>
      </section>

      <aside className="space-y-4">
        <div className="qise-card p-5">
          <h3 className="text-sm font-semibold uppercase text-[var(--text-primary)]">Backup Directory</h3>
          <p className="mt-3 font-mono text-xs leading-5 text-[var(--text-secondary)]">~/.qise/backups/&lt;agent&gt;/&lt;timestamp&gt;/</p>
          <p className="mt-3 text-sm leading-6 text-[var(--text-tertiary)]">
            Restoring only touches Agent config files previously changed by Qise. It does not remove your security events.
          </p>
        </div>
        <div className="qise-card p-5">
          <h3 className="text-sm font-semibold uppercase text-[var(--text-primary)]">Last Operation</h3>
          {busy ? (
            <OperationPanel title="Restore command running..." detail="Qise is applying the selected backup through the product CLI." />
          ) : (
            <pre className="max-h-64 overflow-auto rounded-lg bg-[var(--bg-card)] p-4 text-xs text-[var(--text-secondary)]">
              {output || "No restore operation has run in this session."}
            </pre>
          )}
        </div>
      </aside>
    </div>
  );
}

function PreflightPage({
  agents,
  setError,
  task,
  onRunScan,
}: {
  agents: AgentInfo[];
  setError: (error: string | null) => void;
  task: TaskState<ScanResult>;
  onRunScan: (request: PreflightRequest) => void;
}) {
  const [mode, setMode] = useState<ScanMode>("all");
  const [path, setPath] = useState("");
  const [agent, setAgent] = useState(agents[0]?.key ?? "codex");
  const [selectedAgents, setSelectedAgents] = useState<string[]>([]);
  const [includeSkills, setIncludeSkills] = useState(true);
  const [includeMcp, setIncludeMcp] = useState(true);
  const [includeAgentConfig, setIncludeAgentConfig] = useState(true);

  useEffect(() => {
    if (!agent && agents[0]?.key) setAgent(agents[0].key);
  }, [agent, agents]);

  useEffect(() => {
    setSelectedAgents((current) => {
      if (current.length > 0) {
        return current.filter((key) => agents.some((item) => item.key === key));
      }
      return agents.filter((item) => item.installed).map((item) => item.key);
    });
  }, [agents]);

  function runScan() {
    setError(null);
    onRunScan({
      mode,
      path,
      agent,
      selectedAgents,
      includeSkills,
      includeMcp,
      includeAgentConfig,
    });
  }

  const busy = task.status === "running";
  const report = task.result ?? null;
  const needsPath = mode === "skill" || mode === "mcp";
  const needsAgent = mode === "agent" || mode === "agent-config";
  const hasCategory = includeSkills || includeMcp || includeAgentConfig;
  const canRun = busy
    || (needsPath && !path.trim())
    || (needsAgent && !agent.trim())
    || ((mode === "all" || mode === "agent") && !hasCategory);
  const summary = scanSummary(report);
  const reports = scanReports(report);

  return (
    <div className="space-y-4">
      <section className="qise-card p-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h3 className="text-xl font-semibold text-[var(--text-primary)]">What do you want to scan?</h3>
            <p className="mt-1 text-sm text-[var(--text-tertiary)]">Validate installed Agents and integrations before enabling them.</p>
          </div>
          <StatusPill tone="green">Pre-install check</StatusPill>
        </div>
        <div className="mt-5 grid gap-4 md:grid-cols-3">
          {[
            { id: "all", title: "All Agents", subtitle: "One-click full scan", glyph: "ALL" },
            { id: "agent", title: "Single Agent", subtitle: "Choose Agent and categories", glyph: "AG" },
            { id: "agent-config", title: "Agent Config", subtitle: "Check installed config", glyph: "CFG" },
            { id: "skill", title: "Skill Path", subtitle: "Advanced manual scan", glyph: "SK" },
            { id: "mcp", title: "MCP Path", subtitle: "Advanced manual scan", glyph: "MCP" },
          ].map((item) => (
            <button
              key={item.id}
              className={`qise-choice-card ${mode === item.id ? "qise-choice-card-active" : ""}`}
              onClick={() => setMode(item.id as ScanMode)}
            >
              <span className="qise-choice-icon">{item.glyph}</span>
              <span>
                <span className="block text-base font-semibold text-[var(--text-primary)]">{item.title}</span>
                <span className="block text-sm text-[var(--text-tertiary)]">{item.subtitle}</span>
              </span>
            </button>
          ))}
        </div>

        {(mode === "all" || mode === "agent") && (
          <div className="mt-5 grid gap-4 lg:grid-cols-[1fr_1fr]">
            <div className="rounded-lg bg-[var(--bg-card)] p-4">
              <p className="mb-3 text-sm font-semibold text-[var(--text-primary)]">Agents</p>
              <div className="grid gap-2 sm:grid-cols-2">
                {(agents.length ? agents : [{ key: "codex", name: "Codex" } as AgentInfo]).map((item) => (
                  <label key={item.key} className="qise-check rounded-lg bg-white px-3 py-2">
                    <input
                      type="checkbox"
                      checked={mode === "agent" ? agent === item.key : selectedAgents.includes(item.key)}
                      onChange={(event) => {
                        if (mode === "agent") {
                          setAgent(item.key);
                          return;
                        }
                        setSelectedAgents((current) =>
                          event.target.checked
                            ? Array.from(new Set([...current, item.key]))
                            : current.filter((key) => key !== item.key),
                        );
                      }}
                    />
                    <span>{item.name}</span>
                  </label>
                ))}
              </div>
            </div>
            <div className="rounded-lg bg-[var(--bg-card)] p-4">
              <p className="mb-3 text-sm font-semibold text-[var(--text-primary)]">Categories</p>
              <div className="grid gap-2 sm:grid-cols-3">
                <label className="qise-check rounded-lg bg-white px-3 py-2">
                  <input type="checkbox" checked={includeSkills} onChange={(event) => setIncludeSkills(event.target.checked)} />
                  <span>Skills</span>
                </label>
                <label className="qise-check rounded-lg bg-white px-3 py-2">
                  <input type="checkbox" checked={includeMcp} onChange={(event) => setIncludeMcp(event.target.checked)} />
                  <span>MCP</span>
                </label>
                <label className="qise-check rounded-lg bg-white px-3 py-2">
                  <input type="checkbox" checked={includeAgentConfig} onChange={(event) => setIncludeAgentConfig(event.target.checked)} />
                  <span>Agent config</span>
                </label>
              </div>
            </div>
          </div>
        )}

        {mode === "agent-config" && (
          <label className="mt-5 block">
            <span className="text-xs text-[var(--text-tertiary)]">Agent config</span>
            <select
              className="qise-input"
              value={agent}
              onChange={(event) => setAgent(event.target.value)}
            >
              {(agents.length ? agents : [{ key: "codex", name: "Codex" } as AgentInfo]).map((item) => (
                <option key={item.key} value={item.key}>{item.name}</option>
              ))}
            </select>
          </label>
        )}

        {needsPath && (
          <label className="mt-4 block">
            <span className="text-xs text-[var(--text-tertiary)]">
              {mode === "skill" ? "Skill directory or file path" : "MCP JSON/YAML config path"}
            </span>
            <input
              className="qise-input font-mono"
              value={path}
              onChange={(event) => setPath(event.target.value)}
              placeholder={mode === "skill" ? "/path/to/skill" : "/path/to/mcp.json"}
            />
          </label>
        )}
        <div className="mt-5 flex flex-wrap items-center gap-3">
          <BusyButton busy={busy} busyLabel="Scanning..." disabled={canRun} onClick={runScan}>
            {mode === "all" ? "Scan Selected Agents" : "Run Scan"}
          </BusyButton>
          {busy && <p className="text-sm text-[var(--text-tertiary)]">Qise is running the preflight CLI in the background. You can return Home and come back here.</p>}
        </div>
      </section>

      <section className="qise-card p-5">
        <div className="mb-4 flex items-center justify-between gap-3">
          <div>
            <h3 className="text-sm font-semibold uppercase text-[var(--text-primary)]">Result</h3>
            <p className="text-xs text-[var(--text-tertiary)]">Findings are also recorded as preflight security events.</p>
          </div>
          {report?.verdict && <span className={badgeClass(report.verdict)}>{report.verdict}</span>}
        </div>
        {busy ? (
          <OperationPanel title={task.title || "Scanning Agent assets..."} detail={task.detail || "Checking selected Agent files, MCP candidates and config state."} />
        ) : task.status === "failed" ? (
          <OperationPanel title="Scan failed" detail={task.error} tone="red" />
        ) : !report ? (
          <p className="rounded-lg bg-[var(--bg-card)] p-4 text-sm text-[var(--text-dim)]">Choose a target and run a scan.</p>
        ) : (
          <div className="space-y-4">
            <div className="grid gap-3 md:grid-cols-4">
              <MetricTile label="Reports" value={summary.reports} tone="blue" />
              <MetricTile label="Blocks" value={summary.block} tone={summary.block > 0 ? "red" : "neutral"} />
              <MetricTile label="Warnings" value={summary.warn} tone={summary.warn > 0 ? "yellow" : "neutral"} />
              <MetricTile label="Findings" value={scanFindingCount(report)} tone={scanFindingCount(report) > 0 ? "yellow" : "green"} />
            </div>
            <p className="text-sm text-[var(--text-secondary)]">{report.recommendation}</p>
            <div className="grid gap-3 xl:grid-cols-2">
              {reports.length === 0 ? (
                <p className="rounded-lg bg-[var(--bg-card)] p-3 text-sm text-[var(--text-dim)]">No findings.</p>
              ) : (
                reports.map((item, reportIndex) => (
                  <div key={`${item.target}-${reportIndex}`} className="rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-card)] p-3">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className={badgeClass(item.verdict)}>{item.verdict || "report"}</span>
                      <span className="text-xs font-mono text-[var(--text-secondary)]">{item.target_type}</span>
                      <span className="text-xs text-[var(--text-dim)]">{item.risk?.severity || "low"}</span>
                    </div>
                    <p className="mt-2 truncate text-sm font-mono text-[var(--text-secondary)]">{item.target}</p>
                    {(item.findings ?? []).slice(0, 3).map((finding, index) => (
                      <div key={`${finding.rule_id}-${index}`} className="mt-2 rounded bg-white p-2">
                        <p className="text-xs font-semibold text-[var(--text-secondary)]">{finding.message}</p>
                        {finding.path && <p className="mt-1 text-[11px] font-mono text-[var(--text-dim)]">{finding.path}</p>}
                      </div>
                    ))}
                    {(item.findings ?? []).length === 0 && (
                      <p className="mt-2 text-xs text-[var(--text-dim)]">No findings in this asset.</p>
                    )}
                  </div>
                ))
              )}
            </div>
            {isScanCollection(report) && (report.skipped?.length ?? 0) > 0 && (
              <div className="rounded-lg bg-[var(--bg-card)] p-3">
                <p className="text-xs font-semibold uppercase text-[var(--text-primary)]">Skipped</p>
                {report.skipped?.map((item, index) => (
                  <p key={`${item.agent}-${item.target_type}-${index}`} className="mt-1 text-xs text-[var(--text-tertiary)]">
                    {item.agent} · {item.target_type}: {item.reason}
                  </p>
                ))}
              </div>
            )}
          </div>
        )}
      </section>
    </div>
  );
}

function EventsPage({ events, onEvent }: { events: SecurityEvent[]; onEvent: (event: SecurityEvent) => void }) {
  const [copied, setCopied] = useState(false);
  async function exportJson() {
    await copyText(JSON.stringify(events, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 1600);
  }

  return (
    <section className="space-y-4">
      <div className="flex items-center justify-end">
        <button className="rounded-[43px] bg-[var(--bg-card)] px-4 py-2 text-sm text-[var(--text-secondary)]" onClick={exportJson}>
          {copied ? "Copied JSON" : "Export JSON"}
        </button>
      </div>
      <EventLog events={events} onEvent={onEvent} />
    </section>
  );
}

function RulesPage({
  guards,
  onSetGuardMode,
  setError,
}: {
  guards: GuardInfo[];
  onSetGuardMode: (guardName: string, mode: string) => Promise<void>;
  setError: (error: string | null) => void;
}) {
  const [busyPreset, setBusyPreset] = useState<GuardPreset | null>(null);

  async function applyPreset(preset: GuardPreset) {
    setBusyPreset(preset);
    setError(null);
    try {
      const modes = GUARD_PRESETS[preset];
      for (const guard of guards) {
        const mode = modes[guard.name];
        if (mode && mode !== guard.mode) {
          await onSetGuardMode(guard.name, mode);
        }
      }
    } catch (e) {
      setError(String(e));
    } finally {
      setBusyPreset(null);
    }
  }

  return (
    <div className="space-y-5">
      <div className="qise-card flex flex-wrap items-center justify-between gap-4 p-4">
        <div>
          <h3 className="text-sm font-semibold uppercase text-[var(--text-primary)]">Global Presets</h3>
          <p className="text-xs text-[var(--text-tertiary)]">Changing runtime modes requires the Qise bridge to be available.</p>
        </div>
        <div className="flex flex-wrap gap-2">
          {(["balanced", "strict", "observe"] as GuardPreset[]).map((preset) => (
            <BusyButton
              key={preset}
              variant="secondary"
              busy={busyPreset === preset}
              busyLabel="Applying..."
              disabled={busyPreset !== null || guards.length === 0}
              onClick={() => applyPreset(preset)}
            >
              {preset}
            </BusyButton>
          ))}
        </div>
      </div>
      <GuardList guards={guards} onSetMode={onSetGuardMode} />
    </div>
  );
}

function SlmPage({
  status,
  task,
  onStartSlm,
  onStopSlm,
  onCheckSlm,
}: {
  status: AppStatus | null;
  task: TaskState<string>;
  onStartSlm: (request: SlmStartRequest) => void;
  onStopSlm: (keepServer: boolean) => void;
  onCheckSlm: () => void;
}) {
  const [model, setModel] = useState(status?.slm?.model || "qwen3:4b");
  const [baseUrl, setBaseUrl] = useState(status?.slm?.base_url || "http://localhost:11434/v1");
  const [apiKey, setApiKey] = useState("");
  const [timeoutMs, setTimeoutMs] = useState(10000);
  const [noInstall, setNoInstall] = useState(false);
  const [noPull, setNoPull] = useState(false);
  const [noVerify, setNoVerify] = useState(false);
  const [keepServer, setKeepServer] = useState(true);
  const busy = task.status === "running";
  const output = task.status === "failed" ? task.error : task.result;

  return (
    <div className="grid gap-5 xl:grid-cols-[0.85fr_1.15fr]">
      <section className="qise-card p-5">
        <h3 className="text-sm font-semibold uppercase text-[var(--text-primary)]">Quick Setup</h3>
        <p className="mt-2 text-sm leading-6 text-[var(--text-secondary)]">
          SLM is optional. By default Qise will prepare local Ollama and pull the model if they are missing.
        </p>
        <div className="mt-4 space-y-3">
          <label className="block">
            <span className="text-xs text-[var(--text-tertiary)]">Base URL</span>
            <input className="qise-input" value={baseUrl} onChange={(event) => setBaseUrl(event.target.value)} />
          </label>
          <label className="block">
            <span className="text-xs text-[var(--text-tertiary)]">Model</span>
            <input className="qise-input" value={model} onChange={(event) => setModel(event.target.value)} />
          </label>
          <label className="block">
            <span className="text-xs text-[var(--text-tertiary)]">API key</span>
            <input className="qise-input" value={apiKey} onChange={(event) => setApiKey(event.target.value)} placeholder="Optional" />
          </label>
          <label className="block">
            <span className="text-xs text-[var(--text-tertiary)]">Timeout ms</span>
            <input className="qise-input" type="number" value={timeoutMs} onChange={(event) => setTimeoutMs(Number(event.target.value) || 10000)} />
          </label>
          <label className="qise-check">
            <input type="checkbox" checked={noInstall} onChange={(event) => setNoInstall(event.target.checked)} />
            <span>Skip automatic Ollama install</span>
          </label>
          <label className="qise-check">
            <input type="checkbox" checked={noPull} onChange={(event) => setNoPull(event.target.checked)} />
            <span>Skip automatic model pull</span>
          </label>
          <label className="qise-check">
            <input type="checkbox" checked={noVerify} onChange={(event) => setNoVerify(event.target.checked)} />
            <span>Write config without verification</span>
          </label>
        </div>
        <div className="mt-5 flex flex-wrap gap-2">
          <BusyButton
            busy={busy && task.action === "start"}
            busyLabel="Starting..."
            disabled={busy}
            onClick={() => onStartSlm({ model, baseUrl, apiKey, timeoutMs, noInstall, noPull, noVerify })}
          >
            Start SLM
          </BusyButton>
          <BusyButton variant="secondary" busy={busy && task.action === "stop"} busyLabel="Stopping..." disabled={busy} onClick={() => onStopSlm(keepServer)}>
            Stop SLM
          </BusyButton>
          <BusyButton variant="secondary" busy={busy && task.action === "status"} busyLabel="Checking..." disabled={busy} onClick={onCheckSlm}>
            Check Status
          </BusyButton>
        </div>
        <label className="qise-check mt-4">
          <input type="checkbox" checked={keepServer} onChange={(event) => setKeepServer(event.target.checked)} />
          <span>Keep model server running when disabling Qise SLM</span>
        </label>
      </section>
      <section className="qise-card p-5">
        <h3 className="text-sm font-semibold uppercase text-[var(--text-primary)]">Current State</h3>
        <div className="mt-4 grid gap-3 md:grid-cols-2">
          <MetricTile label="Verification" value={status?.slm?.verification || slmLabel(status)} tone={slmTone(status) === "ready" ? "green" : "yellow"} />
          <MetricTile label="Provider" value={status?.slm?.provider || "none"} tone="blue" />
          <MetricTile label="Model" value={status?.slm?.model || "not configured"} />
          <MetricTile label="Server" value={status?.slm?.server_running ? "running" : "not running"} tone={status?.slm?.server_running ? "green" : "neutral"} />
        </div>
        {busy && <OperationPanel title={task.title} detail={task.detail || "This runs in the background; you can leave this page and return."} />}
        {!busy && output && (
          <pre className={`mt-4 max-h-80 overflow-auto rounded-lg bg-[var(--bg-card)] p-4 text-xs ${task.status === "failed" ? "text-qise-red" : "text-[var(--text-secondary)]"}`}>
            {output}
          </pre>
        )}
      </section>
    </div>
  );
}

function ObserverPage({ events }: { events: SecurityEvent[] }) {
  const [agent, setAgent] = useState("codex");
  const [command, setCommand] = useState("codex");
  const [cwd, setCwd] = useState("");
  const [copied, setCopied] = useState(false);
  const runtimeEvents = events.filter((event) => event.stage === "runtime").slice(0, 8);
  const generated = `qise run --agent ${agent}${cwd ? ` --cwd ${cwd}` : ""} -- ${command}`;

  async function copyCommand() {
    await copyText(generated);
    setCopied(true);
    setTimeout(() => setCopied(false), 1600);
  }

  return (
    <div className="grid gap-5 xl:grid-cols-[0.8fr_1.2fr]">
      <section className="qise-card p-5">
        <h3 className="text-sm font-semibold uppercase text-[var(--text-primary)]">Command Builder</h3>
        <div className="mt-4 space-y-3">
          <label className="block">
            <span className="text-xs text-[var(--text-tertiary)]">Agent</span>
            <input className="qise-input" value={agent} onChange={(event) => setAgent(event.target.value)} />
          </label>
          <label className="block">
            <span className="text-xs text-[var(--text-tertiary)]">Command</span>
            <input className="qise-input" value={command} onChange={(event) => setCommand(event.target.value)} />
          </label>
          <label className="block">
            <span className="text-xs text-[var(--text-tertiary)]">Working directory</span>
            <input className="qise-input" value={cwd} onChange={(event) => setCwd(event.target.value)} placeholder="Optional" />
          </label>
        </div>
        <pre className="mt-4 rounded-lg bg-[var(--bg-card)] p-3 text-xs text-[var(--text-secondary)]">{generated}</pre>
        <button className="mt-4 rounded-[43px] bg-[var(--button-primary-bg)] px-4 py-2 text-sm text-white" onClick={copyCommand}>
          {copied ? "Copied" : "Copy Command"}
        </button>
      </section>
      <section className="qise-card p-5">
        <h3 className="text-sm font-semibold uppercase text-[var(--text-primary)]">Runtime Events</h3>
        <div className="mt-4 space-y-2">
          {runtimeEvents.length === 0 ? (
            <p className="rounded-lg bg-[var(--bg-card)] p-4 text-sm text-[var(--text-dim)]">No runtime events yet.</p>
          ) : (
            runtimeEvents.map((event) => (
              <div key={event.id} className="rounded-lg bg-[var(--bg-card)] p-3">
                <div className="flex items-center justify-between gap-3">
                  <span className="text-xs font-mono text-[var(--text-dim)]">{event.timestamp.slice(0, 19).replace("T", " ")}</span>
                  <span className={badgeClass(eventVerdict(event))}>{eventVerdict(event)}</span>
                </div>
                <p className="mt-2 text-sm text-[var(--text-secondary)]">{eventSummary(event)}</p>
              </div>
            ))
          )}
        </div>
      </section>
    </div>
  );
}

function IntegrationsPage({ setError }: { setError: (error: string | null) => void }) {
  const [adapter, setAdapter] = useState<(typeof ADAPTERS)[number]>("nanobot");
  const [snippet, setSnippet] = useState("");
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState(false);

  async function loadSnippet(nextAdapter = adapter) {
    setBusy(true);
    setError(null);
    try {
      const text = await invoke<string>("get_adapter_snippet", { adapter: nextAdapter });
      setSnippet(text);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function copySnippet() {
    await copyText(snippet);
    setCopied(true);
    setTimeout(() => setCopied(false), 1600);
  }

  return (
    <div className="grid gap-5 xl:grid-cols-[0.72fr_1.28fr]">
      <section className="space-y-4">
        <div className="qise-card p-5">
          <h3 className="text-sm font-semibold uppercase text-[var(--text-primary)]">Adapters</h3>
          <div className="mt-4 space-y-2">
            {ADAPTERS.map((item) => (
              <button
                key={item}
                className={`w-full rounded-lg px-3 py-2 text-left text-sm ${adapter === item ? "bg-[var(--button-primary-bg)] text-white" : "bg-[var(--bg-card)] text-[var(--text-secondary)]"}`}
                onClick={() => {
                  setAdapter(item);
                  loadSnippet(item);
                }}
              >
                {item}
              </button>
            ))}
          </div>
        </div>
        <div className="qise-card p-5">
          <h3 className="text-sm font-semibold uppercase text-[var(--text-primary)]">Runtime Modes</h3>
          <div className="mt-3 space-y-2 text-xs text-[var(--text-secondary)]">
            <code className="block rounded bg-[var(--bg-card)] p-2">qise proxy start --upstream https://api.openai.com/v1</code>
            <code className="block rounded bg-[var(--bg-card)] p-2">qise bridge start</code>
            <code className="block rounded bg-[var(--bg-card)] p-2">qise serve --transport stdio</code>
          </div>
        </div>
      </section>
      <section className="qise-card p-5">
        <div className="mb-4 flex items-center justify-between gap-3">
          <div>
            <h3 className="text-sm font-semibold uppercase text-[var(--text-primary)]">Integration Snippet</h3>
            <p className="text-xs text-[var(--text-tertiary)]">Generated from the product CLI.</p>
          </div>
          <div className="flex gap-2">
            <BusyButton variant="secondary" busy={busy} busyLabel="Loading..." onClick={() => loadSnippet()}>
              Load
            </BusyButton>
            <button className="rounded-[43px] bg-[var(--bg-card)] px-3 py-1 text-xs text-[var(--text-secondary)] disabled:opacity-50" disabled={!snippet} onClick={copySnippet}>
              {copied ? "Copied" : "Copy"}
            </button>
          </div>
        </div>
        <pre className="max-h-[560px] overflow-auto rounded-lg bg-[var(--bg-card)] p-4 text-xs text-[var(--text-secondary)]">
          {snippet || "Choose an adapter and load its snippet."}
        </pre>
      </section>
    </div>
  );
}

function AdvancedLabPage({ setError }: { setError: (error: string | null) => void }) {
  const [toolName, setToolName] = useState("bash");
  const [toolArgs, setToolArgs] = useState('{"command":"echo hello"}');
  const [pipeline, setPipeline] = useState<Pipeline>("egress");
  const [sessionId, setSessionId] = useState("");
  const [result, setResult] = useState<unknown>(null);
  const [context, setContext] = useState("");
  const [busy, setBusy] = useState<string | null>(null);

  async function runCheck() {
    setBusy("check");
    setError(null);
    try {
      JSON.parse(toolArgs);
      const value = await invoke<unknown>("run_check", {
        toolName,
        toolArgs,
        pipeline,
        sessionId,
      });
      setResult(value);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(null);
    }
  }

  async function loadContext() {
    setBusy("context");
    setError(null);
    try {
      if (toolArgs.trim()) JSON.parse(toolArgs);
      const value = await invoke<string>("get_context", { toolName, toolArgs });
      setContext(value || "No context generated.");
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="grid gap-5 xl:grid-cols-[0.8fr_1.2fr]">
      <section className="qise-card p-5">
        <h3 className="text-sm font-semibold uppercase text-[var(--text-primary)]">Guard Input</h3>
        <div className="mt-4 space-y-3">
          <label className="block">
            <span className="text-xs text-[var(--text-tertiary)]">Tool name</span>
            <input className="qise-input" value={toolName} onChange={(event) => setToolName(event.target.value)} />
          </label>
          <label className="block">
            <span className="text-xs text-[var(--text-tertiary)]">Tool args JSON</span>
            <textarea className="qise-input min-h-32" value={toolArgs} onChange={(event) => setToolArgs(event.target.value)} />
          </label>
          <label className="block">
            <span className="text-xs text-[var(--text-tertiary)]">Pipeline</span>
            <select className="qise-input" value={pipeline} onChange={(event) => setPipeline(event.target.value as Pipeline)}>
              <option value="ingress">ingress</option>
              <option value="egress">egress</option>
              <option value="output">output</option>
            </select>
          </label>
          <label className="block">
            <span className="text-xs text-[var(--text-tertiary)]">Session ID</span>
            <input className="qise-input" value={sessionId} onChange={(event) => setSessionId(event.target.value)} placeholder="Optional" />
          </label>
        </div>
        <div className="mt-5 flex flex-wrap gap-2">
          <BusyButton busy={busy === "check"} busyLabel="Checking..." disabled={busy !== null} onClick={runCheck}>
            Run Check
          </BusyButton>
          <BusyButton variant="secondary" busy={busy === "context"} busyLabel="Loading..." disabled={busy !== null} onClick={loadContext}>
            Get Context
          </BusyButton>
        </div>
      </section>
      <section className="space-y-4">
        <div className="qise-card p-5">
          <h3 className="text-sm font-semibold uppercase text-[var(--text-primary)]">Check Result</h3>
          <pre className="mt-3 max-h-64 overflow-auto rounded-lg bg-[var(--bg-card)] p-4 text-xs text-[var(--text-secondary)]">
            {result ? resultText(result) : "Run a check to see guard verdicts."}
          </pre>
        </div>
        <div className="qise-card p-5">
          <h3 className="text-sm font-semibold uppercase text-[var(--text-primary)]">Security Context</h3>
          <pre className="mt-3 max-h-64 overflow-auto whitespace-pre-wrap rounded-lg bg-[var(--bg-card)] p-4 text-xs text-[var(--text-secondary)]">
            {context || "Get context to preview injected guidance."}
          </pre>
        </div>
      </section>
    </div>
  );
}

function App() {
  const [activePage, setActivePage] = useState<PageId>("home");
  const [status, setStatus] = useState<AppStatus | null>(null);
  const [guards, setGuards] = useState<GuardInfo[]>([]);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [agents, setAgents] = useState<AgentInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [bootHint, setBootHint] = useState("Starting Qise runtime...");
  const [lastError, setLastError] = useState<string | null>(null);
  const [detectingAgents, setDetectingAgents] = useState(false);
  const [stoppingProtection, setStoppingProtection] = useState(false);
  const [preflightTask, setPreflightTask] = useState<TaskState<ScanResult>>(() => createTask("Preflight Scan"));
  const [shieldTask, setShieldTask] = useState<TaskState<string>>(() => createTask("Agent Shield"));
  const [slmTask, setSlmTask] = useState<TaskState<string>>(() => createTask("Local SLM"));
  const statusInFlight = useRef(false);

  const loadStatus = useCallback(async () => {
    if (statusInFlight.current) return;
    statusInFlight.current = true;
    try {
      const nextStatus = normalizeStatus(await invoke<unknown>("get_status"));
      setStatus(nextStatus);
      if (nextStatus.detected_agents) {
        setAgents(nextStatus.detected_agents);
      }
      setLastError(null);
    } catch (e) {
      setLastError(String(e));
    } finally {
      statusInFlight.current = false;
      setBootHint("Qise is ready.");
      setLoading(false);
    }
  }, []);

  const loadGuards = useCallback(async () => {
    try {
      const nextGuards = await invoke<GuardInfo[]>("get_guards");
      setGuards(nextGuards);
    } catch (e) {
      setLastError(String(e));
    }
  }, []);

  const loadEvents = useCallback(async () => {
    try {
      const nextEvents = await invoke<unknown[]>("get_events", { limit: 100 });
      setEvents(nextEvents.map(normalizeSecurityEvent));
    } catch (e) {
      setLastError(String(e));
    }
  }, []);

  useEffect(() => {
    const bootTimer = setTimeout(() => {
      setBootHint("Still checking Qise. You can use the app while diagnostics finish.");
      setLoading(false);
    }, 3500);

    loadStatus();
    loadEvents();
    const detailTimer = setTimeout(loadGuards, 1200);
    const interval = setInterval(loadStatus, 15000);

    return () => {
      clearTimeout(bootTimer);
      clearTimeout(detailTimer);
      clearInterval(interval);
    };
  }, [loadEvents, loadGuards, loadStatus]);

  useEffect(() => {
    let unlisten: (() => void) | null = null;
    listen<boolean>("toggle-protection", async (event) => {
      if (event.payload) {
        setActivePage("shield");
      } else {
        await stopProtection();
      }
    }).then((fn) => {
      unlisten = fn;
    });
    return () => {
      unlisten?.();
    };
  }, []);

  const handleEvent = useCallback((event: SecurityEvent) => {
    setEvents((prev) => [event, ...prev].slice(0, 100));
  }, []);

  async function refreshAll() {
    await Promise.all([loadStatus(), loadEvents(), loadGuards()]);
  }

  async function detectAgentsNow() {
    setDetectingAgents(true);
    setLastError(null);
    try {
      const detected = await invoke<AgentInfo[]>("detect_agents");
      setAgents(detected);
      await loadStatus();
    } catch (e) {
      setLastError(String(e));
    } finally {
      setDetectingAgents(false);
    }
  }

  async function stopProtection() {
    setStoppingProtection(true);
    try {
      await invoke("toggle_protection", { enable: false });
      await refreshAll();
    } catch (e) {
      setLastError(String(e));
    } finally {
      setStoppingProtection(false);
    }
  }

  async function handleSetGuardMode(guardName: string, mode: string) {
    try {
      await invoke("set_guard_mode", { guardName, mode });
      await loadGuards();
    } catch (e) {
      setLastError(String(e));
    }
  }

  function runPreflightScan(request: PreflightRequest) {
    const title = request.mode === "all"
      ? "Scanning selected Agents"
      : request.mode === "agent"
        ? `Scanning ${request.agent}`
        : `Scanning ${request.mode}`;
    const task = runningTask<ScanResult>(
      title,
      "Collecting Agent config, Skills and MCP evidence through the Qise CLI.",
      "scan",
    );
    setPreflightTask(task);
    setLastError(null);

    void (async () => {
      try {
        const result = request.mode === "all"
          ? await invoke<ScanCollection>("scan_all_agents", {
              agents: request.selectedAgents,
              includeMissing: false,
              includeSkills: request.includeSkills,
              includeMcp: request.includeMcp,
              includeAgentConfig: request.includeAgentConfig,
            })
          : request.mode === "agent"
            ? await invoke<ScanCollection>("scan_agent_assets", {
                agent: request.agent,
                includeSkills: request.includeSkills,
                includeMcp: request.includeMcp,
                includeAgentConfig: request.includeAgentConfig,
              })
            : request.mode === "skill"
              ? await invoke<ScanReport>("scan_skill", { path: request.path })
              : request.mode === "mcp"
                ? await invoke<ScanReport>("scan_mcp", { path: request.path })
                : await invoke<ScanReport>("scan_agent_config", { agent: request.agent });
        setPreflightTask(succeededTask(task, result, "Scan finished. Results are preserved here until the next scan."));
        await loadEvents();
      } catch (e) {
        const failed = failedTask(task, e);
        setPreflightTask(failed);
        setLastError(failed.error ?? String(e));
      }
    })();
  }

  function runShieldAction(action: string, title: string, detail: string, operation: () => Promise<string>) {
    const task = runningTask<string>(title, detail, action);
    setShieldTask(task);
    setLastError(null);
    void (async () => {
      try {
        const output = await operation();
        setShieldTask(succeededTask(task, output, "Operation finished. You can review the output below."));
        await refreshAll();
      } catch (e) {
        const failed = failedTask(task, e);
        setShieldTask(failed);
        setLastError(failed.error ?? String(e));
      }
    })();
  }

  function protectAgent(agent: AgentInfo) {
    runShieldAction(
      `protect:${agent.key}`,
      `Protecting ${agent.name}`,
      "Patching Agent config and starting Qise managed services.",
      async () => {
        const result = await invoke<CommandText>("protect_agent_with_options", {
          agent: agent.key,
          baseUrl: "",
          experimental: agent.experimental,
        });
        return requireCommandSuccess(result);
      },
    );
  }

  function restoreAgentTask(agent: AgentInfo) {
    runShieldAction(
      `restore:${agent.key}`,
      `Restoring ${agent.name}`,
      "Restoring the Agent config from the latest Qise backup.",
      async () => {
        await invoke("restore_agent", { agent: agent.key });
        return `${agent.name} config restored.`;
      },
    );
  }

  function restoreAllAgentsTask() {
    if (!window.confirm("Restore all Agent configs modified by Qise?")) return;
    runShieldAction("restore-all", "Restoring all Agents", "Restoring all configs modified by Qise.", async () => {
      const result = await invoke<CommandText>("restore_all_agents");
      return requireCommandSuccess(result);
    });
  }

  function stopServicesTask() {
    runShieldAction("stop", "Stopping Qise services", "Stopping Qise managed proxy/bridge services.", async () => {
      const result = await invoke<CommandText>("stop_qise_services");
      return requireCommandSuccess(result);
    });
  }

  function protectCustomAgentTask(baseUrl: string) {
    if (!baseUrl.trim()) {
      setLastError("Custom Agent requires an upstream base URL.");
      return;
    }
    runShieldAction("protect:custom", "Protecting custom Agent", "Starting Qise proxy for the custom upstream.", async () => {
      const result = await invoke<CommandText>("protect_agent_with_options", {
        agent: "custom",
        baseUrl,
        experimental: false,
      });
      return requireCommandSuccess(result);
    });
  }

  function runSlmAction(action: string, title: string, detail: string, operation: () => Promise<string>) {
    const task = runningTask<string>(title, detail, action);
    setSlmTask(task);
    setLastError(null);
    void (async () => {
      try {
        const output = await operation();
        setSlmTask(succeededTask(task, output, "SLM operation finished. Output is preserved here."));
        await refreshAll();
      } catch (e) {
        const failed = failedTask(task, e);
        setSlmTask(failed);
        setLastError(failed.error ?? String(e));
      }
    })();
  }

  function startSlmTask(request: SlmStartRequest) {
    runSlmAction("start", "Starting Local SLM", "Configuring the SLM layer through the Qise CLI.", async () => {
      const result = await invoke<CommandText>("slm_start", { ...request });
      return requireCommandSuccess(result);
    });
  }

  function stopSlmTask(keepServer: boolean) {
    runSlmAction("stop", "Stopping Local SLM", "Disabling Qise SLM config.", async () => {
      const result = await invoke<CommandText>("slm_stop", { keepServer });
      return requireCommandSuccess(result);
    });
  }

  function checkSlmTask() {
    runSlmAction("status", "Checking Local SLM", "Reading SLM status from the Qise CLI.", async () => {
      const result = await invoke<unknown>("get_slm_status");
      return resultText(result);
    });
  }

  const pageTitleRight = useMemo(() => {
    if (activePage === "shield" && statusProtectionEnabled(status)) {
      return (
        <BusyButton variant="secondary" busy={stoppingProtection} busyLabel="Stopping..." onClick={stopProtection}>
          Stop Protection
        </BusyButton>
      );
    }
    return null;
  }, [activePage, status, stoppingProtection]);

  if (loading) {
    return <BootScreen hint={bootHint} />;
  }

  return (
    <div className="min-h-screen bg-qise-deep px-5 pb-16 pt-5">
      <div className="mx-auto max-w-7xl">
        <TopBar activePage={activePage} status={status} onOpen={setActivePage} />
        <ErrorBanner error={lastError} onDismiss={() => setLastError(null)} />
        <TaskStrip tasks={[preflightTask, shieldTask, slmTask]} />
        <PageHeader page={activePage} onHome={() => setActivePage("home")} right={pageTitleRight} />

        {activePage === "home" && (
          <HomePage
            status={status}
            guards={guards}
            agents={agents}
            onOpen={setActivePage}
            onDetectAgents={detectAgentsNow}
            detectingAgents={detectingAgents}
          />
        )}
        {activePage === "shield" && (
          <AgentShieldPage
            agents={agents}
            task={shieldTask}
            onProtectAgent={protectAgent}
            onRestoreAgent={restoreAgentTask}
            onRestoreAll={restoreAllAgentsTask}
            onStopServices={stopServicesTask}
            onProtectCustom={protectCustomAgentTask}
          />
        )}
        {activePage === "preflight" && (
          <PreflightPage agents={agents} setError={setLastError} task={preflightTask} onRunScan={runPreflightScan} />
        )}
        {activePage === "events" && <EventsPage events={events} onEvent={handleEvent} />}
        {activePage === "rules" && (
          <RulesPage guards={guards} onSetGuardMode={handleSetGuardMode} setError={setLastError} />
        )}
        {activePage === "slm" && (
          <SlmPage status={status} task={slmTask} onStartSlm={startSlmTask} onStopSlm={stopSlmTask} onCheckSlm={checkSlmTask} />
        )}
        {activePage === "doctor" && <DiagnosticsPanel />}
        {activePage === "observer" && <ObserverPage events={events} />}
        {activePage === "backup" && <BackupRestorePage status={status} onRefresh={refreshAll} setError={setLastError} />}
        {activePage === "integrations" && <IntegrationsPage setError={setLastError} />}
        {activePage === "advanced" && <AdvancedLabPage setError={setLastError} />}
        {activePage === "settings" && <ConfigPanel />}
      </div>
      <StatusFooter status={status} />
    </div>
  );
}

export default App;
