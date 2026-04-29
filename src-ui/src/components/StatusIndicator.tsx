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
            : "bg-[#3a3b3c]"
        }`}
      />
      <span className="text-sm text-[#f9f9f9] tracking-wide">
        {enabled ? "Protected" : "Unprotected"}
      </span>
    </div>
  );
}
