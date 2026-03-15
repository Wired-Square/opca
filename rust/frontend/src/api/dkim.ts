import { tauriInvoke, withLock } from "./tauri";
import type {
  DkimKeyItem,
  DkimKeyDetail,
  CreateDkimRequest,
  CreateDkimResult,
  DkimVerifyResult,
  DkimRoute53Result,
} from "./types";

export async function listDkimKeys(): Promise<DkimKeyItem[]> {
  return tauriInvoke<DkimKeyItem[]>("list_dkim_keys");
}

export async function getDkimInfo(
  domain: string,
  selector: string,
): Promise<DkimKeyDetail> {
  return tauriInvoke<DkimKeyDetail>("get_dkim_info", { domain, selector });
}

export async function createDkimKey(
  request: CreateDkimRequest,
): Promise<CreateDkimResult> {
  return withLock("create_dkim", () =>
    tauriInvoke<CreateDkimResult>("create_dkim_key", { request }),
  );
}

export async function deleteDkimKey(
  domain: string,
  selector: string,
): Promise<boolean> {
  return withLock("delete_dkim", () =>
    tauriInvoke<boolean>("delete_dkim_key", { domain, selector }),
  );
}

export async function verifyDkimDns(
  domain: string,
  selector: string,
): Promise<DkimVerifyResult> {
  return tauriInvoke<DkimVerifyResult>("verify_dkim_dns", { domain, selector });
}

export async function deployDkimRoute53(
  domain: string,
  selector: string,
): Promise<DkimRoute53Result> {
  return tauriInvoke<DkimRoute53Result>("deploy_dkim_route53", { domain, selector });
}
