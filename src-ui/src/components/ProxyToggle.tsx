interface ProxyToggleProps {
  enabled: boolean;
  onToggle: (enable: boolean) => void;
}

export default function ProxyToggle({ enabled, onToggle }: ProxyToggleProps) {
  return (
    <button
      className={`qise-btn-primary ${
        enabled ? "qise-btn-primary-active" : "qise-btn-primary-inactive"
      } disabled:opacity-50 disabled:cursor-not-allowed`}
      disabled={!enabled}
      onClick={() => onToggle(false)}
    >
      {enabled ? "Stop Protection" : "Protect Agent First"}
    </button>
  );
}
