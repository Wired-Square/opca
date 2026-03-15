import { createSignal, Show, For, onMount } from "solid-js";
import { useNavigate } from "@solidjs/router";
import { invoke } from "@tauri-apps/api/core";
import { setAppState, type VaultState } from "../stores/app";
import { themeMode, toggleTheme } from "../stores/theme";

interface ConnectionInfo {
  connected: boolean;
  vault: string;
  account: string | null;
  vault_state: string;
}

interface OpCliStatus {
  found: boolean;
  path: string | null;
}

interface SavedLogin {
  vault: string;
  account: string | null;
}

const STORAGE_KEY = "opca_saved_logins";

function loadSavedLogins(): SavedLogin[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}

function persistLogins(logins: SavedLogin[]) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(logins));
}

function addLogin(vault: string, account: string | null): SavedLogin[] {
  const logins = loadSavedLogins().filter(
    (l) => !(l.vault === vault && l.account === account),
  );
  logins.unshift({ vault, account });
  persistLogins(logins);
  return logins;
}

function removeLogin(vault: string, account: string | null): SavedLogin[] {
  const logins = loadSavedLogins().filter(
    (l) => !(l.vault === vault && l.account === account),
  );
  persistLogins(logins);
  return logins;
}

export default function Connect() {
  const navigate = useNavigate();
  const [vault, setVault] = createSignal("");
  const [account, setAccount] = createSignal("");
  const [loading, setLoading] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);
  const [saved, setSaved] = createSignal<SavedLogin[]>([]);
  const [dropdownOpen, setDropdownOpen] = createSignal(false);
  const [opCli, setOpCli] = createSignal<OpCliStatus | null>(null);

  onMount(async () => {
    setSaved(loadSavedLogins());
    try {
      const status = await invoke<OpCliStatus>("check_op_cli");
      setOpCli(status);
    } catch {
      setOpCli({ found: false, path: null });
    }
  });

  function selectLogin(login: SavedLogin) {
    setVault(login.vault);
    setAccount(login.account ?? "");
    setDropdownOpen(false);
  }

  function forgetLogin(e: Event, login: SavedLogin) {
    e.stopPropagation();
    setSaved(removeLogin(login.vault, login.account));
  }

  async function handleConnect(e: Event) {
    e.preventDefault();
    if (!vault().trim()) return;

    setLoading(true);
    setError(null);

    try {
      const info = await invoke<ConnectionInfo>("connect", {
        vault: vault(),
        account: account() || null,
      });
      setAppState({
        connected: info.connected,
        vault: info.vault,
        account: info.account,
        vaultState: info.vault_state as VaultState,
      });
      setSaved(addLogin(info.vault, info.account));
      navigate("/dashboard");
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div class="connect-page" onClick={() => setDropdownOpen(false)}>
      <div class="connect-card">
        <div class="connect-header">
          <div class="connect-brand-row">
            <img src="/logo.svg" alt="" class="connect-logo" />
            <h1 class="connect-title">
              <span class="brand-op">op</span>
              <span class="brand-ca">CA</span>
            </h1>
          </div>
          <p class="connect-subtitle">Certificate Authority Manager</p>
          <p class="connect-byline">by Wired Square</p>
        </div>

        <form class="connect-form" onSubmit={handleConnect}>
          <div class="form-group">
            <label class="form-label" for="vault">1Password Vault</label>
            <div class="input-with-dropdown" onClick={(e) => e.stopPropagation()}>
              <input
                id="vault"
                type="text"
                placeholder="e.g. Private CA"
                value={vault()}
                onInput={(e) => {
                  setVault(e.currentTarget.value);
                  setDropdownOpen(false);
                }}
                onFocus={() => saved().length > 0 && setDropdownOpen(true)}
                autofocus
                autocomplete="off"
                autocorrect="off"
                autocapitalize="off"
                spellcheck={false}
              />
              <Show when={saved().length > 0}>
                <button
                  type="button"
                  class="dropdown-toggle"
                  onClick={() => setDropdownOpen(!dropdownOpen())}
                  tabIndex={-1}
                >
{"\u21BB"}
                </button>
              </Show>
              <Show when={dropdownOpen() && saved().length > 0}>
                <div class="saved-dropdown">
                  <For each={saved()}>
                    {(login) => (
                      <div class="saved-item" onClick={() => selectLogin(login)}>
                        <div class="saved-item-info">
                          <span class="saved-vault">{login.vault}</span>
                          <Show when={login.account}>
                            <span class="saved-account">{login.account}</span>
                          </Show>
                        </div>
                        <button
                          type="button"
                          class="saved-forget"
                          onClick={(e) => forgetLogin(e, login)}
                          title="Forget this login"
                        >
                          &times;
                        </button>
                      </div>
                    )}
                  </For>
                </div>
              </Show>
            </div>
          </div>

          <div class="form-group">
            <label class="form-label" for="account">Account (optional)</label>
            <input
              id="account"
              type="text"
              placeholder="e.g. my.1password.com"
              value={account()}
              onInput={(e) => {
                setAccount(e.currentTarget.value);
                setDropdownOpen(false);
              }}
              autocomplete="off"
              autocorrect="off"
              autocapitalize="off"
              spellcheck={false}
            />
          </div>

          {error() && <p class="connect-error">{error()}</p>}

          <button class="btn-primary connect-btn" type="submit" disabled={loading() || !vault().trim()}>
            {loading() ? "Connecting\u2026" : "Connect"}
          </button>
        </form>

        <button class="btn-ghost theme-toggle-connect" onClick={toggleTheme} title="Toggle theme">
          {themeMode() === "dark" ? "\u2600 Light mode" : "\u263E Dark mode"}
        </button>

        <Show when={opCli()}>
          {(status) => (
            <div class={`op-cli-status ${status().found ? "op-cli-found" : "op-cli-missing"}`}>
              <span class="op-cli-dot" />
              <span class="op-cli-text">
                {status().found ? `op CLI found: ${status().path}` : "op CLI not found on PATH"}
              </span>
            </div>
          )}
        </Show>
      </div>

      <style>{`
        .connect-page {
          display: flex;
          align-items: center;
          justify-content: center;
          height: 100vh;
          width: 100vw;
          background: var(--bg-primary);
        }

        .connect-card {
          width: 100%;
          max-width: 420px;
          padding: 48px 40px;
          background: var(--bg-surface);
          border: 1px solid var(--border);
          border-radius: 16px;
          box-shadow: 0 8px 32px rgba(0, 0, 0, 0.2);
        }

        .connect-header {
          text-align: center;
          margin-bottom: 40px;
        }

        .connect-brand-row {
          display: flex;
          align-items: center;
          justify-content: center;
          gap: 12px;
          margin-bottom: 8px;
        }

        .connect-logo {
          width: 44px;
          height: 44px;
        }

        .connect-title {
          font-family: "Ubuntu", sans-serif;
          font-size: 3rem;
          font-weight: 700;
          letter-spacing: 0.02em;
          line-height: 1;
        }

        .brand-op {
          color: var(--text-primary);
        }

        .brand-ca {
          color: var(--accent);
        }

        .connect-subtitle {
          font-family: "Ubuntu", sans-serif;
          color: var(--text-secondary);
          font-size: 0.9375rem;
          margin-bottom: 4px;
        }

        .connect-byline {
          font-family: "Ubuntu", sans-serif;
          color: var(--text-tertiary);
          font-size: 0.75rem;
          letter-spacing: 0.02em;
        }

        .connect-form {
          display: flex;
          flex-direction: column;
          gap: 20px;
        }

        .form-group {
          display: flex;
          flex-direction: column;
          gap: 6px;
        }

        .form-label {
          font-size: 0.8125rem;
          font-weight: 500;
          color: var(--text-secondary);
        }

        .input-with-dropdown {
          position: relative;
        }

        .input-with-dropdown input {
          width: 100%;
          padding-right: 36px;
          box-sizing: border-box;
        }

        .dropdown-toggle {
          position: absolute;
          right: 1px;
          top: 1px;
          bottom: 1px;
          width: 34px;
          background: var(--accent);
          border: none;
          border-left: 1px solid var(--border);
          color: #fff;
          cursor: pointer;
          display: flex;
          align-items: center;
          justify-content: center;
          border-radius: 0 7px 7px 0;
          transition: opacity 0.15s;
          font-size: 1.25rem;
          line-height: 1;
        }

        .dropdown-toggle:hover {
          opacity: 0.85;
        }

        .saved-dropdown {
          position: absolute;
          top: calc(100% + 4px);
          left: 0;
          right: 0;
          background: var(--bg-surface);
          border: 1px solid var(--border);
          border-radius: 8px;
          box-shadow: 0 8px 24px rgba(0, 0, 0, 0.3);
          z-index: 10;
          overflow: hidden;
        }

        .saved-item {
          display: flex;
          align-items: center;
          justify-content: space-between;
          padding: 10px 12px;
          cursor: pointer;
          transition: background 0.1s;
        }

        .saved-item:hover {
          background: var(--bg-elevated);
        }

        .saved-item + .saved-item {
          border-top: 1px solid var(--border);
        }

        .saved-item-info {
          display: flex;
          flex-direction: column;
          gap: 2px;
          min-width: 0;
        }

        .saved-vault {
          font-size: 0.875rem;
          font-weight: 500;
          color: var(--text-primary);
          white-space: nowrap;
          overflow: hidden;
          text-overflow: ellipsis;
        }

        .saved-account {
          font-size: 0.75rem;
          color: var(--text-tertiary);
          white-space: nowrap;
          overflow: hidden;
          text-overflow: ellipsis;
        }

        .saved-forget {
          flex-shrink: 0;
          width: 24px;
          height: 24px;
          display: flex;
          align-items: center;
          justify-content: center;
          background: none;
          border: none;
          border-radius: 4px;
          color: var(--text-tertiary);
          font-size: 1.125rem;
          cursor: pointer;
          transition: color 0.15s, background 0.15s;
        }

        .saved-forget:hover {
          color: var(--error);
          background: rgba(255, 69, 58, 0.1);
        }

        .connect-error {
          color: var(--error);
          font-size: 0.875rem;
          padding: 8px 12px;
          background: rgba(255, 69, 58, 0.1);
          border-radius: 6px;
        }

        .connect-btn {
          margin-top: 8px;
          padding: 12px;
          font-size: 1rem;
          font-weight: 600;
          border-radius: 10px;
        }

        .connect-btn:disabled {
          opacity: 0.5;
          cursor: not-allowed;
        }

        .theme-toggle-connect {
          display: block;
          margin: 24px auto 0;
          font-size: 0.8125rem;
        }

        .op-cli-status {
          display: flex;
          align-items: center;
          justify-content: center;
          gap: 8px;
          margin-top: 16px;
          font-size: 0.75rem;
        }

        .op-cli-dot {
          width: 8px;
          height: 8px;
          border-radius: 50%;
          flex-shrink: 0;
        }

        .op-cli-found .op-cli-dot {
          background: var(--success);
          box-shadow: 0 0 6px var(--success);
        }

        .op-cli-missing .op-cli-dot {
          background: var(--error);
          box-shadow: 0 0 6px var(--error);
        }

        .op-cli-text {
          color: var(--text-tertiary);
        }
      `}</style>
    </div>
  );
}
