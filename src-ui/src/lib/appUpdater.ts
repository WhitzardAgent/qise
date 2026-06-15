export type UpdatePhase =
  | "idle"
  | "checking"
  | "current"
  | "deferred"
  | "downloading"
  | "installing"
  | "restarting"
  | "failed";

export interface AppUpdateState {
  phase: UpdatePhase;
  currentVersion: string;
  latestVersion: string | null;
  downloadedBytes: number;
  totalBytes: number | null;
  error: string | null;
}

export interface ProtectionSnapshot {
  known: boolean;
  enabled: boolean;
}

export type UpdateDownloadEvent =
  | { event: "Started"; data: { contentLength?: number } }
  | { event: "Progress"; data: { chunkLength: number } }
  | { event: "Finished" };

export interface AvailableUpdate {
  version: string;
  downloadAndInstall: (
    onEvent: (event: UpdateDownloadEvent) => void,
  ) => Promise<void>;
}

export interface UpdateDependencies {
  getCurrentVersion: () => Promise<string>;
  check: () => Promise<AvailableUpdate | null>;
  relaunch: () => Promise<void>;
}

export type NativeUpdateDownloadEvent =
  | { event: "Started"; data: { contentLength?: number } }
  | { event: "Progress"; data: { chunkLength: number } }
  | { event: "Finished"; data?: unknown };

export interface NativeAvailableUpdate {
  version: string;
  downloadAndInstall: (
    onEvent: (event: NativeUpdateDownloadEvent) => void,
  ) => Promise<void>;
}

export interface NativeUpdateApi {
  getVersion: () => Promise<string>;
  check: () => Promise<NativeAvailableUpdate | null>;
  relaunch: () => Promise<void>;
}

export type UpdateDisplayTone = "neutral" | "blue" | "green" | "yellow" | "red";

export interface UpdateDisplay {
  label: string;
  detail: string;
  percentage: number | null;
  tone: UpdateDisplayTone;
}

export const initialUpdateState: AppUpdateState = {
  phase: "idle",
  currentVersion: "",
  latestVersion: null,
  downloadedBytes: 0,
  totalBytes: null,
  error: null,
};

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export function describeUpdateState(
  state: AppUpdateState,
  locale: "en" | "zh",
): UpdateDisplay {
  const percentage = state.totalBytes && state.totalBytes > 0
    ? Math.min(100, Math.round((state.downloadedBytes / state.totalBytes) * 100))
    : null;

  const displays: Record<UpdatePhase, UpdateDisplay> = locale === "zh"
    ? {
        idle: {
          label: "尚未检查",
          detail: "Qise 启动后会自动检查更新。",
          percentage: null,
          tone: "neutral",
        },
        checking: {
          label: "正在检查更新",
          detail: "正在查询最新的稳定版本。",
          percentage: null,
          tone: "blue",
        },
        current: {
          label: "已是最新版本",
          detail: "当前安装与最新稳定版本一致。",
          percentage: null,
          tone: "green",
        },
        deferred: {
          label: "更新已延迟",
          detail: "Qise 正在保护智能体，将在下次安全启动时重新检查并自动更新。",
          percentage: null,
          tone: "yellow",
        },
        downloading: {
          label: "正在下载更新",
          detail: percentage === null ? "正在下载更新包。" : `已下载 ${percentage}%。`,
          percentage,
          tone: "blue",
        },
        installing: {
          label: "正在安装更新",
          detail: "下载完成，正在验证并安装。",
          percentage: 100,
          tone: "blue",
        },
        restarting: {
          label: "正在重启 Qise",
          detail: "更新安装完成，应用即将重新启动。",
          percentage: 100,
          tone: "green",
        },
        failed: {
          label: "更新失败",
          detail: state.error || "无法完成更新，当前版本仍可继续使用。",
          percentage: null,
          tone: "red",
        },
      }
    : {
        idle: {
          label: "Not checked yet",
          detail: "Qise checks for updates automatically after startup.",
          percentage: null,
          tone: "neutral",
        },
        checking: {
          label: "Checking for updates",
          detail: "Querying the latest stable release.",
          percentage: null,
          tone: "blue",
        },
        current: {
          label: "Up to date",
          detail: "This installation matches the latest stable release.",
          percentage: null,
          tone: "green",
        },
        deferred: {
          label: "Update deferred",
          detail: "Qise is protecting an Agent and will retry on the next safe startup.",
          percentage: null,
          tone: "yellow",
        },
        downloading: {
          label: "Downloading update",
          detail: percentage === null ? "Downloading the update package." : `Downloaded ${percentage}%.`,
          percentage,
          tone: "blue",
        },
        installing: {
          label: "Installing update",
          detail: "Download complete. Verifying and installing the update.",
          percentage: 100,
          tone: "blue",
        },
        restarting: {
          label: "Restarting Qise",
          detail: "The update is installed and Qise is relaunching.",
          percentage: 100,
          tone: "green",
        },
        failed: {
          label: "Update failed",
          detail: state.error || "The current version remains available.",
          percentage: null,
          tone: "red",
        },
      };

  return displays[state.phase];
}

export function createUpdateDependencies(api: NativeUpdateApi): UpdateDependencies {
  return {
    getCurrentVersion: api.getVersion,
    relaunch: api.relaunch,
    check: async () => {
      const nativeUpdate = await api.check();
      if (!nativeUpdate) return null;

      return {
        version: nativeUpdate.version,
        downloadAndInstall: (onEvent) => nativeUpdate.downloadAndInstall((event) => {
          switch (event.event) {
            case "Started":
              onEvent({
                event: "Started",
                data: { contentLength: event.data.contentLength },
              });
              break;
            case "Progress":
              onEvent({
                event: "Progress",
                data: { chunkLength: event.data.chunkLength },
              });
              break;
            case "Finished":
              onEvent({ event: "Finished" });
              break;
          }
        }),
      };
    },
  };
}

export class AppUpdater {
  private busy = false;
  private state: AppUpdateState = initialUpdateState;

  constructor(private readonly dependencies: UpdateDependencies) {}

  async checkAndInstall(
    protection: ProtectionSnapshot,
    onState: (state: AppUpdateState) => void,
  ): Promise<boolean> {
    if (this.busy) return false;
    this.busy = true;

    const emit = (patch: Partial<AppUpdateState>) => {
      this.state = { ...this.state, ...patch };
      onState({ ...this.state });
    };

    emit({
      phase: "checking",
      latestVersion: null,
      downloadedBytes: 0,
      totalBytes: null,
      error: null,
    });

    try {
      const currentVersion = await this.dependencies.getCurrentVersion();
      emit({ currentVersion });

      const update = await this.dependencies.check();
      if (!update) {
        emit({ phase: "current" });
        return true;
      }

      emit({ latestVersion: update.version });
      if (!protection.known || protection.enabled) {
        emit({ phase: "deferred" });
        return true;
      }

      let downloadedBytes = 0;
      emit({ phase: "downloading" });
      await update.downloadAndInstall((event) => {
        switch (event.event) {
          case "Started":
            downloadedBytes = 0;
            emit({
              phase: "downloading",
              downloadedBytes,
              totalBytes: event.data.contentLength ?? null,
            });
            break;
          case "Progress":
            downloadedBytes += event.data.chunkLength;
            emit({ phase: "downloading", downloadedBytes });
            break;
          case "Finished":
            emit({ phase: "installing" });
            break;
        }
      });

      emit({ phase: "restarting" });
      await this.dependencies.relaunch();
      return true;
    } catch (error) {
      emit({ phase: "failed", error: errorMessage(error) });
      return true;
    } finally {
      this.busy = false;
    }
  }
}
