import { useCallback, useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { AppStatus, normalizeStatus, portLabel, slmLabel } from "../lib/api";

interface DoctorCheck {
  name: string;
  status: string;
  detail: string;
}

interface DoctorReport {
  result: string;
  checks: DoctorCheck[];
  warnings: string[];
  errors: string[];
}

interface SlmReport {
  configured: boolean;
  provider: string;
  model: string;
  base_url: string;
  verification: string;
  server_running: boolean;
  timeout_ms: number;
  config_path?: string;
}

function statusTone(status: string): string {
  const normalized = status.toLowerCase();
  if (["ok", "ready", "available"].includes(normalized)) return "badge-pass";
  if (["warning", "warn", "ready_with_warnings", "not_configured", "busy"].includes(normalized)) return "badge-warn";
  return "badge-block";
}

function DetailRow({
  label,
  value,
  tone,
}: {
  label: string;
  value: string;
  tone?: string;
}) {
  return (
    <div className="flex min-w-0 items-center justify-between gap-3 rounded-lg bg-[var(--bg-card)] px-3 py-2">
      <span className="text-xs text-[var(--text-tertiary)]">{label}</span>
      <span className="min-w-0 flex-1 truncate text-right text-xs font-mono text-[var(--text-secondary)]">
        {value || "unknown"}
      </span>
      {tone && <span className={statusTone(tone)}>{tone}</span>}
    </div>
  );
}

export default function DiagnosticsPanel() {
  const [doctor, setDoctor] = useState<DoctorReport | null>(null);
  const [slm, setSlm] = useState<SlmReport | null>(null);
  const [status, setStatus] = useState<AppStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadDiagnostics = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [doctorReport, slmReport, statusReport] = await Promise.all([
        invoke<DoctorReport>("get_doctor"),
        invoke<SlmReport>("get_slm_status"),
        invoke<unknown>("get_status"),
      ]);
      setDoctor(doctorReport);
      setSlm(slmReport);
      setStatus(normalizeStatus(statusReport));
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadDiagnostics();
  }, [loadDiagnostics]);

  const checks = useMemo(() => {
    const byName = new Map<string, DoctorCheck>();
    doctor?.checks.forEach((check) => byName.set(check.name, check));
    return byName;
  }, [doctor]);

  const qiseVersion = checks.get("Qise")?.detail ?? "unknown";
  const pythonVersion = checks.get("Python")?.detail ?? "unknown";
  const config = checks.get("Config");
  const eventLog = checks.get("Event log");
  const upstream = checks.get("Upstream");
  const proxy = checks.get("Proxy port");
  const bridge = checks.get("Bridge port");

  return (
    <div className="qise-card p-5">
      <div className="mb-4 flex items-center justify-between gap-3">
        <div>
          <h3 className="text-sm font-medium uppercase tracking-wide text-[var(--text-primary)]">
            Diagnostics
          </h3>
          <p className="mt-1 text-xs font-mono text-[var(--text-dim)]">
            Qise {qiseVersion} · Python {pythonVersion}
          </p>
        </div>
        <div className="flex items-center gap-2">
          {doctor && <span className={statusTone(doctor.result)}>{doctor.result}</span>}
          <button
            className="rounded-[43px] bg-[var(--bg-card)] px-3 py-1 text-xs font-medium text-[var(--text-tertiary)] transition-opacity hover:opacity-60 disabled:opacity-40"
            disabled={loading}
            onClick={loadDiagnostics}
          >
            {loading ? "Checking..." : "Refresh"}
          </button>
        </div>
      </div>

      {error ? (
        <div className="rounded-lg border border-[rgba(255,95,111,0.35)] bg-[rgba(255,95,111,0.08)] px-3 py-2">
          <p className="text-xs text-qise-red">{error}</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-2 xl:grid-cols-2">
          <DetailRow label="Protection" value={Object.keys(status?.protected_agents ?? {}).length > 0 ? "protected" : "unprotected"} />
          <DetailRow label="Proxy" value={status ? portLabel(status.proxy, status.proxy_port ?? 8822) : proxy?.detail ?? ""} tone={proxy?.status} />
          <DetailRow label="Bridge" value={status ? portLabel(status.bridge, status.bridge_port ?? 8823) : bridge?.detail ?? ""} tone={bridge?.status} />
          <DetailRow label="Config" value={status?.config ?? config?.detail ?? ""} tone={config?.status} />
          <DetailRow label="Events" value={status?.events_path ?? eventLog?.detail ?? ""} tone={eventLog?.status} />
          <DetailRow label="Upstream" value={upstream?.detail ?? "unknown"} tone={upstream?.status} />
          <DetailRow label="SLM" value={slm ? `${slm.verification} · ${slm.model || slm.provider || "none"}` : slmLabel(status)} tone={slm?.verification} />
          <DetailRow label="SLM Config" value={slm?.config_path ?? "unknown"} />
        </div>
      )}

      {!error && doctor && (doctor.errors.length > 0 || doctor.warnings.length > 0) && (
        <div className="mt-3 space-y-1">
          {doctor.errors.map((item) => (
            <p key={`error-${item}`} className="text-xs text-qise-red">{item}</p>
          ))}
          {doctor.warnings.map((item) => (
            <p key={`warning-${item}`} className="text-xs text-qise-yellow">{item}</p>
          ))}
        </div>
      )}
    </div>
  );
}
