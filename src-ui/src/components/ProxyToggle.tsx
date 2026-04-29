interface ProxyToggleProps {
  enabled: boolean;
  onToggle: (enable: boolean) => void;
}

export default function ProxyToggle({ enabled, onToggle }: ProxyToggleProps) {
  return (
    <button
      className={`qise-btn-primary ${
        enabled ? "qise-btn-primary-active" : "qise-btn-primary-inactive"
      }`}
      onClick={() => onToggle(!enabled)}
    >
      {enabled ? "Protection On" : "Enable Protection"}
    </button>
  );
}
