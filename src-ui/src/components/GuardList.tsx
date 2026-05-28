import type { GuardInfo } from "../lib/api";

interface GuardListProps {
  guards: GuardInfo[];
  onSetMode: (guardName: string, mode: string) => void;
}

const PIPELINE_LABELS: Record<string, string> = {
  ingress: "Ingress",
  egress: "Egress",
  output: "Output",
};

const MODES = ["observe", "enforce", "off"] as const;

function modeBadgeClass(mode: string): string {
  switch (mode) {
    case "enforce":
      return "badge-block";
    case "observe":
      return "badge-warn";
    case "off":
      return "badge-pass";
    default:
      return "badge-pass";
  }
}

function guardModeBtnClass(mode: string, active: boolean): string {
  if (!active) return "qise-guard-mode-btn qise-guard-mode-btn-inactive";
  switch (mode) {
    case "observe":
      return "qise-guard-mode-btn qise-guard-mode-btn-active-observe";
    case "enforce":
      return "qise-guard-mode-btn qise-guard-mode-btn-active-enforce";
    case "off":
      return "qise-guard-mode-btn qise-guard-mode-btn-active-off";
    default:
      return "qise-guard-mode-btn qise-guard-mode-btn-inactive";
  }
}

const PIPELINE_ICONS: Record<string, string> = {
  ingress: "↓",
  egress: "↑",
  output: "⊙",
};

const PIPELINE_ICON_CLASSES: Record<string, string> = {
  ingress: "qise-pipeline-ingress",
  egress: "qise-pipeline-egress",
  output: "qise-pipeline-output",
};

export default function GuardList({ guards, onSetMode }: GuardListProps) {
  // Group by pipeline
  const grouped = guards.reduce(
    (acc, g) => {
      const key = g.pipeline;
      if (!acc[key]) acc[key] = [];
      acc[key].push(g);
      return acc;
    },
    {} as Record<string, GuardInfo[]>,
  );

  return (
    <div className="space-y-6">
      {["ingress", "egress", "output"].map((pipeline) => {
        const pipelineGuards = grouped[pipeline];
        if (!pipelineGuards) return null;
        const icon = PIPELINE_ICONS[pipeline] || "";
        const iconClass = PIPELINE_ICON_CLASSES[pipeline] || "";

        return (
          <div key={pipeline}>
            <div className="qise-pipeline-header">
              <span className={`qise-pipeline-icon ${iconClass}`}>{icon}</span>
              <h3 className="text-sm font-semibold text-[var(--text-primary)]">
                {PIPELINE_LABELS[pipeline] || pipeline}
              </h3>
              <span className="text-xs text-[var(--text-dim)]">{pipelineGuards.length} guards</span>
            </div>
            <div className="space-y-1">
              {pipelineGuards.map((guard) => (
                <div key={guard.name} className="qise-guard-row">
                  <div className="flex items-center gap-3">
                    <span className="text-sm font-mono font-semibold text-[var(--text-primary)]">
                      {guard.name}
                    </span>
                    <span className={modeBadgeClass(guard.mode)}>
                      <span className="badge-dot" />
                      {guard.mode.toUpperCase()}
                    </span>
                    <span className="rounded-full bg-white px-2 py-1 text-[11px] font-mono text-[var(--text-dim)] ring-1 ring-[var(--border-subtle)]">
                      {guard.primary_strategy === "ai" ? "AI-first" : "Rules"}
                    </span>
                  </div>
                  <div className="flex gap-1">
                    {MODES.map((mode) => (
                      <button
                        key={mode}
                        className={guardModeBtnClass(mode, guard.mode === mode)}
                        onClick={() => onSetMode(guard.name, mode)}
                      >
                        {mode}
                      </button>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );
}
