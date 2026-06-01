import { tr, type Locale } from "../lib/locale";

interface ProxyToggleProps {
  enabled: boolean;
  onToggle: (enable: boolean) => void;
  locale?: Locale;
}

export default function ProxyToggle({ enabled, onToggle, locale = "en" }: ProxyToggleProps) {
  return (
    <button
      className={`qise-btn-primary ${
        enabled ? "qise-btn-primary-active" : "qise-btn-primary-inactive"
      } disabled:opacity-50 disabled:cursor-not-allowed`}
      disabled={!enabled}
      onClick={() => onToggle(false)}
    >
      {enabled ? tr(locale, "Stop Protection", "停止保护") : tr(locale, "Protect Agent First", "请先保护智能体")}
    </button>
  );
}
