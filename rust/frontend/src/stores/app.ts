import { createStore } from "solid-js/store";

export type VaultState = "disconnected" | "valid_ca" | "empty_vault" | "invalid_ca";

export interface AppStore {
  connected: boolean;
  vaultState: VaultState;
  vault: string;
  account: string | null;
  loading: boolean;
  error: string | null;
}

const [appState, setAppState] = createStore<AppStore>({
  connected: false,
  vaultState: "disconnected",
  vault: "",
  account: null,
  loading: false,
  error: null,
});

/** Convenience: true when the vault contains a valid CA. */
export const hasCA = () => appState.vaultState === "valid_ca";

export { appState, setAppState };
