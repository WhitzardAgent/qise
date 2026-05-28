import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { ReactNode } from "react";
import DiagnosticsPanel from "./DiagnosticsPanel";

interface SLMConfig {
  base_url: string;
  model: string;
  timeout_ms: number;
  api_key: string | null;
  [key: string]: unknown;
}

interface LLMConfig {
  base_url: string;
  model: string;
  timeout_ms: number;
  api_key: string | null;
  [key: string]: unknown;
}

interface GuardConfigEntry {
  mode: string;
  slm_confidence_threshold: number | null;
  skip_slm_on_rule_pass: boolean | null;
  slm_override_rule_warn_threshold: number | null;
  [key: string]: unknown;
}

interface ShieldConfig {
  models: {
    slm: SLMConfig;
    llm: LLMConfig;
  };
  guards: {
    enabled: string[];
    config: Record<string, GuardConfigEntry>;
  };
  integration: {
    mode: string;
    proxy: {
      port: number;
      target_agents?: string[];
      auto_takeover: boolean;
      crash_recovery: boolean;
      upstream_url?: string;
      upstream_api_key?: string;
      [key: string]: unknown;
    };
    [key: string]: unknown;
  };
  [key: string]: unknown;
}

function ConfigCard({
  title,
  children,
  unsaved = false,
}: {
  title: string;
  children: ReactNode;
  unsaved?: boolean;
}) {
  return (
    <div className="qise-card p-5">
      <div className="flex items-center gap-2 mb-4">
        <h3 className="text-sm font-medium text-[var(--text-primary)] tracking-wide uppercase">
          {title}
        </h3>
        {unsaved && (
          <div className="w-2 h-2 rounded-full bg-qise-yellow" />
        )}
      </div>
      <div className="space-y-3">{children}</div>
    </div>
  );
}

function ConfigInput({
  label,
  value,
  onChange,
  type = "text",
  placeholder = "",
}: {
  label: string;
  value: string | number;
  onChange: (val: string) => void;
  type?: string;
  placeholder?: string;
}) {
  return (
    <div className="flex items-center gap-3">
      <label className="text-sm text-[var(--text-tertiary)] w-36 shrink-0">{label}</label>
      <input
        type={type}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className="flex-1 bg-[var(--bg-card)] border border-[var(--border-subtle)] rounded-lg px-3 py-2 text-sm text-[var(--text-secondary)] font-mono focus:outline-none focus:border-[var(--qise-blue)] transition-colors"
      />
    </div>
  );
}

function ConfigSelect({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: string;
  options: { value: string; label: string }[];
  onChange: (val: string) => void;
}) {
  return (
    <div className="flex items-center gap-3">
      <label className="text-sm text-[var(--text-tertiary)] w-36 shrink-0">{label}</label>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="flex-1 bg-[var(--bg-card)] border border-[var(--border-subtle)] rounded-lg px-3 py-2 text-sm text-[var(--text-secondary)] font-mono focus:outline-none focus:border-[var(--qise-blue)] transition-colors appearance-none"
      >
        {options.map((opt) => (
          <option key={opt.value} value={opt.value}>
            {opt.label}
          </option>
        ))}
      </select>
    </div>
  );
}

function ConfigToggle({
  label,
  checked,
  onChange,
}: {
  label: string;
  checked: boolean;
  onChange: (val: boolean) => void;
}) {
  return (
    <div className="flex items-center gap-3">
      <label className="text-sm text-[var(--text-tertiary)] w-36 shrink-0">{label}</label>
      <button
        onClick={() => onChange(!checked)}
        className={`w-10 h-5 rounded-full transition-colors ${
          checked ? "bg-qise-green" : "bg-[var(--indicator-muted)]"
        }`}
      >
        <div
          className={`w-4 h-4 rounded-full bg-white transition-transform ${
            checked ? "translate-x-5" : "translate-x-0.5"
          }`}
        />
      </button>
    </div>
  );
}

const GUARD_MODES = [
  { value: "observe", label: "Observe (log only)" },
  { value: "enforce", label: "Enforce (block)" },
  { value: "off", label: "Off (disabled)" },
];

export default function ConfigPanel() {
  const [config, setConfig] = useState<ShieldConfig | null>(null);
  const [originalConfig, setOriginalConfig] = useState<ShieldConfig | null>(null);
  const [configPath, setConfigPath] = useState<string>("");
  const [saving, setSaving] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadConfig();
  }, []);

  async function loadConfig() {
    try {
      const [c, path] = await Promise.all([
        invoke<ShieldConfig>("get_config"),
        invoke<string>("get_config_path"),
      ]);
      setConfig(c);
      setOriginalConfig(JSON.parse(JSON.stringify(c)));
      setConfigPath(path);
      setError(null);
    } catch (e) {
      console.error("Failed to load config:", e);
      setError(String(e));
    }
  }

  const hasChanges = config && originalConfig && JSON.stringify(config) !== JSON.stringify(originalConfig);

  async function handleSave() {
    if (!config) return;
    const target = configPath || "~/.qise/shield.yaml";
    if (!window.confirm(`Save configuration to ${target}?`)) return;
    setSaving(true);
    setError(null);
    try {
      await invoke("save_config", { config });
      setOriginalConfig(JSON.parse(JSON.stringify(config)));
      setSaveSuccess(true);
      setTimeout(() => setSaveSuccess(false), 2000);
    } catch (e) {
      setError(String(e));
    } finally {
      setSaving(false);
    }
  }

  async function handleReset() {
    try {
      const c = await invoke<ShieldConfig>("get_default_config");
      setConfig(c);
      setError(null);
    } catch (e) {
      setError(String(e));
    }
  }

  if (!config) {
    return (
      <div className="qise-card p-6 text-center">
        <p className="inline-flex items-center justify-center gap-2 text-sm text-[var(--text-dim)]">
          {!error && <span className="qise-spinner qise-spinner-blue" />}
          {error ? `Error: ${error}` : "Loading configuration..."}
        </p>
      </div>
    );
  }

  const updateSlm = (field: keyof SLMConfig, value: string | number | null) => {
    setConfig((prev) => {
      if (!prev) return prev;
      return {
        ...prev,
        models: {
          ...prev.models,
          slm: { ...prev.models.slm, [field]: value },
        },
      };
    });
  };

  const updateLlm = (field: keyof LLMConfig, value: string | number | null) => {
    setConfig((prev) => {
      if (!prev) return prev;
      return {
        ...prev,
        models: {
          ...prev.models,
          llm: { ...prev.models.llm, [field]: value },
        },
      };
    });
  };

  const updateProxy = (
    field: keyof ShieldConfig["integration"]["proxy"],
    value: string | number | boolean | string[],
  ) => {
    setConfig((prev) =>
      prev
        ? {
            ...prev,
            integration: {
              ...prev.integration,
              proxy: { ...prev.integration.proxy, [field]: value },
            },
          }
        : prev,
    );
  };

  const updateGuardConfig = (guardName: string, field: string, value: string | number | boolean | null) => {
    setConfig((prev) => {
      if (!prev) return prev;
      const existing = prev.guards.config[guardName] || {};
      return {
        ...prev,
        guards: {
          ...prev.guards,
          config: {
            ...prev.guards.config,
            [guardName]: { ...existing, [field]: value },
          },
        },
      };
    });
  };

  const toggleGuardEnabled = (guardName: string) => {
    setConfig((prev) => {
      if (!prev) return prev;
      const enabled = prev.guards.enabled.includes(guardName);
      return {
        ...prev,
        guards: {
          ...prev.guards,
          enabled: enabled
            ? prev.guards.enabled.filter((g) => g !== guardName)
            : [...prev.guards.enabled, guardName],
        },
      };
    });
  };

  // Guard categories
  const ingressGuards = ["prompt", "tool_sanity", "context", "supply_chain"];
  const egressGuards = ["command", "filesystem", "network", "exfil", "resource", "tool_policy", "reasoning"];
  const outputGuards = ["credential", "audit", "output"];

  return (
    <div className="space-y-6">
      <DiagnosticsPanel />

      {/* Action bar */}
      <div className="flex flex-wrap items-center gap-3">
        <button
          onClick={handleSave}
          disabled={!hasChanges || saving}
          className={`px-5 py-2 rounded-[43px] text-sm font-medium transition-all ${
            hasChanges && !saving
              ? "bg-[var(--button-primary-bg)] text-[var(--button-primary-text)] hover:opacity-60"
              : "bg-[var(--bg-card)] text-[var(--text-dim)] cursor-not-allowed"
          }`}
        >
          {saving ? (
            <span className="inline-flex items-center gap-2"><span className="qise-spinner" />Saving...</span>
          ) : saveSuccess ? "Saved" : "Save"}
        </button>
        <button
          onClick={handleReset}
          className="px-5 py-2 rounded-[43px] text-sm font-medium bg-[var(--bg-card)] text-[var(--text-tertiary)] hover:opacity-60 transition-all"
        >
          Reset to Default
        </button>
        {hasChanges && (
          <span className="text-xs text-qise-yellow">Unsaved changes</span>
        )}
        <span className="text-xs text-[var(--text-dim)] font-mono truncate max-w-full">
          Target: {configPath || "~/.qise/shield.yaml"}
        </span>
      </div>

      {error && (
        <div className="qise-card p-3 border-l-2 border-qise-red">
          <p className="text-sm text-qise-red">{error}</p>
        </div>
      )}

      {/* Models Section */}
      <ConfigCard title="SLM Model" unsaved={JSON.stringify(config.models.slm) !== JSON.stringify(originalConfig?.models.slm)}>
        <ConfigInput
          label="Base URL"
          value={config.models.slm.base_url}
          onChange={(v) => updateSlm("base_url", v)}
          placeholder="http://localhost:11434/v1"
        />
        <ConfigInput
          label="Model"
          value={config.models.slm.model}
          onChange={(v) => updateSlm("model", v)}
          placeholder="qwen3:4b"
        />
        <ConfigInput
          label="Timeout (ms)"
          value={config.models.slm.timeout_ms}
          onChange={(v) => updateSlm("timeout_ms", parseInt(v) || 0)}
          type="number"
        />
      </ConfigCard>

      <ConfigCard title="LLM Model" unsaved={JSON.stringify(config.models.llm) !== JSON.stringify(originalConfig?.models.llm)}>
        <ConfigInput
          label="Base URL"
          value={config.models.llm.base_url}
          onChange={(v) => updateLlm("base_url", v)}
          placeholder="https://api.anthropic.com"
        />
        <ConfigInput
          label="Model"
          value={config.models.llm.model}
          onChange={(v) => updateLlm("model", v)}
          placeholder="claude-sonnet-4-5"
        />
        <ConfigInput
          label="Timeout (ms)"
          value={config.models.llm.timeout_ms}
          onChange={(v) => updateLlm("timeout_ms", parseInt(v) || 0)}
          type="number"
        />
      </ConfigCard>

      {/* Integration Section */}
      <ConfigCard title="Integration">
        <ConfigSelect
          label="Mode"
          value={config.integration.mode}
          options={[
            { value: "proxy", label: "Proxy (zero-code)" },
            { value: "sdk", label: "SDK (code)" },
            { value: "mcp", label: "MCP (limited)" },
          ]}
          onChange={(v) =>
            setConfig((prev) =>
              prev ? { ...prev, integration: { ...prev.integration, mode: v } } : prev
            )
          }
        />
        <ConfigInput
          label="Proxy Port"
          value={config.integration.proxy.port}
          onChange={(v) => updateProxy("port", parseInt(v) || 8822)}
          type="number"
        />
        <ConfigInput
          label="Upstream URL"
          value={config.integration.proxy.upstream_url ?? ""}
          onChange={(v) => updateProxy("upstream_url", v)}
          placeholder="https://api.openai.com/v1"
        />
        <ConfigInput
          label="Upstream API Key"
          value={config.integration.proxy.upstream_api_key ?? ""}
          onChange={(v) => updateProxy("upstream_api_key", v)}
          placeholder="Optional; prefer env vars for real secrets"
        />
        <ConfigInput
          label="Target Agents"
          value={(config.integration.proxy.target_agents ?? []).join(", ")}
          onChange={(v) =>
            updateProxy(
              "target_agents",
              v.split(",").map((item) => item.trim()).filter(Boolean),
            )
          }
          placeholder="codex, openclaw"
        />
        <ConfigToggle
          label="Auto Takeover"
          checked={config.integration.proxy.auto_takeover}
          onChange={(v) => updateProxy("auto_takeover", v)}
        />
        <ConfigToggle
          label="Crash Recovery"
          checked={config.integration.proxy.crash_recovery}
          onChange={(v) => updateProxy("crash_recovery", v)}
        />
      </ConfigCard>

      {/* Guards Section — grouped by pipeline */}
      {[
        { title: "Ingress Guards", guards: ingressGuards },
        { title: "Egress Guards", guards: egressGuards },
        { title: "Output Guards", guards: outputGuards },
      ].map((group) => (
        <ConfigCard key={group.title} title={group.title}>
          {group.guards.map((guardName) => {
            const gc = config.guards.config[guardName];
            const enabled = config.guards.enabled.includes(guardName);
            return (
              <div
                key={guardName}
                className="py-2 px-3 bg-[var(--bg-card)] rounded-lg border-l-2 border-[var(--border-subtle)]"
              >
                <div className="flex items-center gap-3 mb-2">
                  <ConfigToggle
                    label={guardName}
                    checked={enabled}
                    onChange={() => toggleGuardEnabled(guardName)}
                  />
                </div>
                {enabled && gc && (
                  <div className="ml-36 space-y-2">
                    <ConfigSelect
                      label="Mode"
                      value={gc.mode || "observe"}
                      options={GUARD_MODES}
                      onChange={(v) => updateGuardConfig(guardName, "mode", v)}
                    />
                    {gc.slm_confidence_threshold !== null && gc.slm_confidence_threshold !== undefined && (
                      <ConfigInput
                        label="SLM Threshold"
                        value={gc.slm_confidence_threshold}
                        onChange={(v) =>
                          updateGuardConfig(guardName, "slm_confidence_threshold", parseFloat(v) || 0.7)
                        }
                        type="number"
                      />
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </ConfigCard>
      ))}
    </div>
  );
}
