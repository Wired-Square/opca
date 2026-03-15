import { tauriInvoke, withLock } from "./tauri";
import type { CrlInfo } from "./types";

export async function getCrlInfo(): Promise<CrlInfo> {
  return tauriInvoke<CrlInfo>("get_crl_info");
}

export async function generateCrl(): Promise<CrlInfo> {
  return withLock("generate_crl", () =>
    tauriInvoke<CrlInfo>("generate_crl"),
  );
}

export async function uploadCrl(): Promise<void> {
  return tauriInvoke<void>("upload_crl");
}
