import { describe, expect, it, vi } from "vitest";
import {
  AppUpdater,
  createUpdateDependencies,
  describeUpdateState,
  initialUpdateState,
  type AppUpdateState,
  type AvailableUpdate,
  type UpdateDependencies,
} from "./appUpdater";


function makeUpdate(
  version = "0.4.0",
  downloadAndInstall: AvailableUpdate["downloadAndInstall"] = vi.fn(async () => undefined),
): AvailableUpdate {
  return { version, downloadAndInstall };
}


function makeDependencies(overrides: Partial<UpdateDependencies> = {}): UpdateDependencies {
  return {
    getCurrentVersion: vi.fn(async () => "0.3.0"),
    check: vi.fn(async () => null),
    relaunch: vi.fn(async () => undefined),
    ...overrides,
  };
}


function captureStates(): {
  states: AppUpdateState[];
  onState: (state: AppUpdateState) => void;
} {
  const states: AppUpdateState[] = [];
  return {
    states,
    onState: (state) => states.push(state),
  };
}


describe("AppUpdater", () => {
  it("reports current when no update exists", async () => {
    const dependencies = makeDependencies();
    const updater = new AppUpdater(dependencies);
    const capture = captureStates();

    await updater.checkAndInstall({ known: true, enabled: false }, capture.onState);

    expect(capture.states[capture.states.length - 1]).toEqual({
      ...initialUpdateState,
      phase: "current",
      currentVersion: "0.3.0",
    });
    expect(dependencies.relaunch).not.toHaveBeenCalled();
  });

  it("defers an update when protection state is unknown", async () => {
    const update = makeUpdate();
    const dependencies = makeDependencies({ check: vi.fn(async () => update) });
    const updater = new AppUpdater(dependencies);
    const capture = captureStates();

    await updater.checkAndInstall({ known: false, enabled: true }, capture.onState);

    expect(capture.states[capture.states.length - 1]?.phase).toBe("deferred");
    expect(capture.states[capture.states.length - 1]?.latestVersion).toBe("0.4.0");
    expect(update.downloadAndInstall).not.toHaveBeenCalled();
  });

  it("defers an update while an Agent is protected", async () => {
    const update = makeUpdate();
    const dependencies = makeDependencies({ check: vi.fn(async () => update) });
    const updater = new AppUpdater(dependencies);
    const capture = captureStates();

    await updater.checkAndInstall({ known: true, enabled: true }, capture.onState);

    expect(capture.states[capture.states.length - 1]?.phase).toBe("deferred");
    expect(update.downloadAndInstall).not.toHaveBeenCalled();
    expect(dependencies.relaunch).not.toHaveBeenCalled();
  });

  it("downloads, installs, and relaunches in a known safe state", async () => {
    const downloadAndInstall = vi.fn(async (onEvent) => {
      onEvent({ event: "Started", data: { contentLength: 100 } });
      onEvent({ event: "Progress", data: { chunkLength: 25 } });
      onEvent({ event: "Progress", data: { chunkLength: 75 } });
      onEvent({ event: "Finished" });
    });
    const update = makeUpdate("0.4.0", downloadAndInstall);
    const dependencies = makeDependencies({ check: vi.fn(async () => update) });
    const updater = new AppUpdater(dependencies);
    const capture = captureStates();

    await updater.checkAndInstall({ known: true, enabled: false }, capture.onState);

    expect(downloadAndInstall).toHaveBeenCalledOnce();
    expect(dependencies.relaunch).toHaveBeenCalledOnce();
    expect(capture.states.some((state) => (
      state.phase === "downloading"
      && state.downloadedBytes === 25
      && state.totalBytes === 100
    ))).toBe(true);
    expect(capture.states.some((state) => state.phase === "installing")).toBe(true);
    expect(capture.states[capture.states.length - 1]?.phase).toBe("restarting");
  });

  it("ignores a second check while one is active", async () => {
    let resolveCheck: ((value: AvailableUpdate | null) => void) | undefined;
    const check = vi.fn(() => new Promise<AvailableUpdate | null>((resolve) => {
      resolveCheck = resolve;
    }));
    const dependencies = makeDependencies({ check });
    const updater = new AppUpdater(dependencies);
    const capture = captureStates();

    const first = updater.checkAndInstall({ known: true, enabled: false }, capture.onState);
    await Promise.resolve();
    const secondStarted = await updater.checkAndInstall(
      { known: true, enabled: false },
      capture.onState,
    );
    resolveCheck?.(null);
    const firstStarted = await first;

    expect(firstStarted).toBe(true);
    expect(secondStarted).toBe(false);
    expect(check).toHaveBeenCalledOnce();
  });

  it("reports failure while preserving the resolved current version", async () => {
    const dependencies = makeDependencies({
      check: vi.fn(async () => {
        throw new Error("network unavailable");
      }),
    });
    const updater = new AppUpdater(dependencies);
    const capture = captureStates();

    await updater.checkAndInstall({ known: true, enabled: false }, capture.onState);

    expect(capture.states[capture.states.length - 1]).toMatchObject({
      phase: "failed",
      currentVersion: "0.3.0",
      error: "network unavailable",
    });
  });

  it("adapts native update progress into the controller contract", async () => {
    const nativeDownload = vi.fn(async (onEvent) => {
      onEvent({ event: "Started", data: { contentLength: 64 } });
      onEvent({ event: "Progress", data: { chunkLength: 64 } });
      onEvent({ event: "Finished", data: {} });
    });
    const dependencies = createUpdateDependencies({
      getVersion: vi.fn(async () => "0.3.0"),
      check: vi.fn(async () => ({
        version: "0.4.0",
        downloadAndInstall: nativeDownload,
      })),
      relaunch: vi.fn(async () => undefined),
    });
    const update = await dependencies.check();
    const events: string[] = [];

    await update?.downloadAndInstall((event) => events.push(event.event));

    expect(events).toEqual(["Started", "Progress", "Finished"]);
    expect(await dependencies.getCurrentVersion()).toBe("0.3.0");
    await dependencies.relaunch();
  });
});


describe("describeUpdateState", () => {
  it("describes a current installation", () => {
    expect(describeUpdateState({
      ...initialUpdateState,
      phase: "current",
      currentVersion: "0.3.0",
    }, "en")).toMatchObject({
      label: "Up to date",
      tone: "green",
      percentage: null,
    });
  });

  it("explains deferred updates in Chinese", () => {
    const display = describeUpdateState({
      ...initialUpdateState,
      phase: "deferred",
      currentVersion: "0.3.0",
      latestVersion: "0.4.0",
    }, "zh");

    expect(display.label).toBe("更新已延迟");
    expect(display.detail).toContain("下次安全启动");
    expect(display.tone).toBe("yellow");
  });

  it("calculates known download progress", () => {
    expect(describeUpdateState({
      ...initialUpdateState,
      phase: "downloading",
      downloadedBytes: 25,
      totalBytes: 100,
    }, "en").percentage).toBe(25);
  });

  it("leaves progress indeterminate without a total", () => {
    expect(describeUpdateState({
      ...initialUpdateState,
      phase: "downloading",
      downloadedBytes: 25,
      totalBytes: null,
    }, "en").percentage).toBeNull();
  });

  it.each([
    ["installing", "Installing update"],
    ["restarting", "Restarting Qise"],
  ] as const)("describes %s", (phase, label) => {
    expect(describeUpdateState({
      ...initialUpdateState,
      phase,
    }, "en").label).toBe(label);
  });

  it("shows the updater error", () => {
    expect(describeUpdateState({
      ...initialUpdateState,
      phase: "failed",
      error: "network unavailable",
    }, "en")).toMatchObject({
      label: "Update failed",
      detail: "network unavailable",
      tone: "red",
    });
  });
});
