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

        return (
          <div key={pipeline}>
            <h3 className="text-sm text-[#9c9c9d] mb-3 uppercase tracking-wider">
              {PIPELINE_LABELS[pipeline] || pipeline}
            </h3>
            <div className="qise-card p-4 space-y-2">
              {pipelineGuards.map((guard) => (
                <div
                  key={guard.name}
                  className="flex items-center justify-between py-2 px-3 rounded-lg hover:bg-[#1b1c1e]"
                >
                  <div className="flex items-center gap-3">
                    <span className="text-sm font-mono text-[#f9f9f9]">
                      {guard.name}
                    </span>
                    <span className={modeBadgeClass(guard.mode)}>
                      {guard.mode}
                    </span>
                    <span className="text-xs text-[#6a6b6c]">
                      {guard.primary_strategy === "ai" ? "AI-first" : "Rules"}
                    </span>
                  </div>
                  <div className="flex gap-1">
                    {MODES.map((mode) => (
                      <button
                        key={mode}
                        className={`text-xs px-2 py-1 rounded transition-opacity ${
                          guard.mode === mode
                            ? "bg-[#1b1c1e] text-[#f9f9f9]"
                            : "text-[#6a6b6c] hover:opacity-60"
                        }`}
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
