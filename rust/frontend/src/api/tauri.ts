import { invoke } from "@tauri-apps/api/core";
import { setAppState } from "../stores/app";

/**
 * Typed wrapper around Tauri's invoke.
 * Sets app-level error state on failure.
 */
export async function tauriInvoke<T>(
  cmd: string,
  args?: Record<string, unknown>,
): Promise<T> {
  try {
    setAppState("error", null);
    return await invoke<T>(cmd, args);
  } catch (err) {
    const message = typeof err === "string" ? err : String(err);
    setAppState("error", message);
    throw new Error(message);
  }
}

/**
 * Execute a mutation operation with vault lock acquisition.
 *
 * Acquires the lock before calling `fn`, releases it afterwards
 * (even on failure).
 */
export async function withLock<T>(
  operation: string,
  fn: () => Promise<T>,
): Promise<T> {
  await tauriInvoke("acquire_lock", { operation });
  try {
    return await fn();
  } finally {
    await tauriInvoke("release_lock");
  }
}
