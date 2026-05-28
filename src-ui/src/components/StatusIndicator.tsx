interface StatusIndicatorProps {
  enabled: boolean;
}

export default function StatusIndicator({ enabled }: StatusIndicatorProps) {
  return (
    <div className="flex items-center gap-3">
      <div
        className={`w-6 h-6 rounded-full ${
          enabled
            ? "bg-qise-green glow-green"
            : "bg-[var(--indicator-muted)]"
        }`}
      />
      <span className="text-sm text-[var(--text-primary)] tracking-wide">
        {enabled ? "Protected" : "Unprotected"}
      </span>
    </div>
  );
}
