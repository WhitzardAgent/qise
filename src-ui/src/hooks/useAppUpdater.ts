import { useCallback, useEffect, useRef, useState } from "react";
import { getVersion } from "@tauri-apps/api/app";
import { relaunch } from "@tauri-apps/plugin-process";
import { check } from "@tauri-apps/plugin-updater";
import {
  AppUpdater,
  createUpdateDependencies,
  initialUpdateState,
  type AppUpdateState,
  type NativeAvailableUpdate,
  type ProtectionSnapshot,
} from "../lib/appUpdater";


export interface UseAppUpdaterResult {
  state: AppUpdateState;
  checkForUpdates: () => Promise<void>;
}


function createController(): AppUpdater {
  return new AppUpdater(createUpdateDependencies({
    getVersion,
    relaunch,
    check: async () => await check() as NativeAvailableUpdate | null,
  }));
}


export function useAppUpdater(
  protection: ProtectionSnapshot,
  startupReady: boolean,
): UseAppUpdaterResult {
  const controllerRef = useRef<AppUpdater | null>(null);
  const protectionRef = useRef(protection);
  const startupAttemptedRef = useRef(false);
  const [state, setState] = useState<AppUpdateState>(initialUpdateState);

  if (controllerRef.current === null) {
    controllerRef.current = createController();
  }
  protectionRef.current = protection;

  const checkForUpdates = useCallback(async () => {
    await controllerRef.current?.checkAndInstall(protectionRef.current, setState);
  }, []);

  useEffect(() => {
    if (!startupReady || startupAttemptedRef.current) return;
    startupAttemptedRef.current = true;
    void checkForUpdates();
  }, [checkForUpdates, startupReady]);

  return { state, checkForUpdates };
}
