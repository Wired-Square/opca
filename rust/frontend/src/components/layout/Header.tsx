import { Show, Switch, Match } from "solid-js";
import { useNavigate } from "@solidjs/router";
import { invoke } from "@tauri-apps/api/core";
import { appState, setAppState } from "../../stores/app";
import { themeMode, toggleTheme } from "../../stores/theme";

export default function Header() {
  const navigate = useNavigate();

  async function handleLogout() {
    await invoke("disconnect");
    setAppState({
      connected: false,
      vaultState: "disconnected",
      vault: "",
      account: null,
    });
    navigate("/");
  }

  return (
    <header class="app-header">
      <div class="header-info">
        <Show when={appState.connected}>
          <span class="header-vault">
            <span class="header-label">Vault:</span>
            <span class="header-value">{appState.vault}</span>
          </span>
          <Show when={appState.account}>
            <span class="header-account">
              <span class="header-label">Account:</span>
              <span class="header-value">{appState.account}</span>
            </span>
          </Show>
          <Switch>
            <Match when={appState.vaultState === "valid_ca"}>
              <span class="header-badge header-badge-valid">valid CA</span>
            </Match>
            <Match when={appState.vaultState === "empty_vault"}>
              <span class="header-badge header-badge-warning">empty vault</span>
            </Match>
            <Match when={appState.vaultState === "invalid_ca"}>
              <span class="header-badge header-badge-error">invalid CA</span>
            </Match>
          </Switch>
        </Show>
      </div>
      <div class="header-actions">
        <button class="btn-ghost theme-toggle" onClick={toggleTheme} title="Toggle theme">
          {themeMode() === "dark" ? "\u2600" : "\u263E"}
        </button>
        <button class="btn-ghost disconnect-btn" onClick={handleLogout} title="Disconnect">
          <span innerHTML={logoutIcon} />
        </button>
      </div>

      <style>{`
        .app-header {
          height: 48px;
          min-height: 48px;
          display: flex;
          align-items: center;
          justify-content: space-between;
          padding: 0 24px;
          background: var(--bg-surface);
          border-bottom: 1px solid var(--border);
          font-size: 0.8125rem;
        }

        .header-info {
          display: flex;
          gap: 24px;
          align-items: center;
        }

        .header-label {
          color: var(--text-tertiary);
          margin-right: 6px;
        }

        .header-value {
          color: var(--text-primary);
          font-family: "JetBrains Mono", monospace;
          font-size: 0.8125rem;
        }

        .header-badge {
          font-family: "JetBrains Mono", monospace;
          font-size: 0.75rem;
          font-weight: 600;
          padding: 2px 10px;
          border-radius: 4px;
          letter-spacing: 0.02em;
        }

        .header-badge-valid {
          color: var(--success);
          background: rgba(34, 197, 94, 0.1);
        }

        .header-badge-warning {
          color: var(--warning);
          background: rgba(255, 214, 10, 0.1);
        }

        .header-badge-error {
          color: var(--error);
          background: rgba(255, 69, 58, 0.1);
        }

        .header-actions {
          display: flex;
          gap: 4px;
          align-items: center;
        }

        .theme-toggle {
          font-size: 1.25rem;
          padding: 4px 8px;
          border-radius: 6px;
        }

        .disconnect-btn {
          padding: 4px 8px;
          border-radius: 6px;
          display: flex;
          align-items: center;
        }

        .disconnect-btn svg {
          width: 16px;
          height: 16px;
          stroke: currentColor;
          fill: none;
          stroke-width: 1.75;
          stroke-linecap: round;
          stroke-linejoin: round;
        }

        .disconnect-btn:hover {
          color: var(--error);
          background: rgba(255, 69, 58, 0.08);
        }
      `}</style>
    </header>
  );
}

const logoutIcon = `<svg viewBox="0 0 24 24"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>`;
