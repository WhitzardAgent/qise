import { tr, type Locale } from "../lib/locale";

interface StatusIndicatorProps {
  enabled: boolean;
  locale?: Locale;
}

export default function StatusIndicator({ enabled, locale = "en" }: StatusIndicatorProps) {
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
        {enabled ? tr(locale, "Protected", "已保护") : tr(locale, "Unprotected", "未保护")}
      </span>
    </div>
  );
}
