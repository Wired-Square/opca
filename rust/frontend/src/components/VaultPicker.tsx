import { Show, For, createSignal } from "solid-js";
import { listVaults, createVault } from "../api/vaults";
import Spinner from "./Spinner";
import type { VaultInfo } from "../api/types";

interface VaultPickerProps {
  /** Current vault name value. */
  value: string;
  /** Called when the user selects or types a vault name. */
  onChange: (vault: string) => void;
  /** Placeholder text for the input. */
  placeholder?: string;
}

/**
 * Text input with a "Browse" button that opens a dropdown of 1Password vaults.
 * Includes a "New vault" option to create and auto-select a new vault.
 *
 * Usage:
 *   <VaultPicker value={vault()} onChange={setVault} />
 */
export default function VaultPicker(props: VaultPickerProps) {
  const [open, setOpen] = createSignal(false);
  const [vaultList, setVaultList] = createSignal<VaultInfo[]>([]);
  const [loading, setLoading] = createSignal(false);
  const [fetchError, setFetchError] = createSignal<string | null>(null);

  // New vault creation
  const [showCreate, setShowCreate] = createSignal(false);
  const [newVaultName, setNewVaultName] = createSignal("");
  const [creating, setCreating] = createSignal(false);
  const [createError, setCreateError] = createSignal<string | null>(null);

  function selectVault(name: string) {
    props.onChange(name);
    setOpen(false);
    setShowCreate(false);
  }

  async function fetchVaults() {
    setLoading(true);
    setFetchError(null);
    try {
      const result = await listVaults();
      setVaultList(result);
    } catch (e) {
      setFetchError(String(e));
    } finally {
      setLoading(false);
    }
  }

  function toggleBrowse() {
    const next = !open();
    setOpen(next);
    if (next) {
      setShowCreate(false);
      setCreateError(null);
      fetchVaults();
    }
  }

  async function handleCreateVault() {
    const name = newVaultName().trim();
    if (!name) return;
    setCreating(true);
    setCreateError(null);
    try {
      const vault = await createVault(name);
      setNewVaultName("");
      setShowCreate(false);
      selectVault(vault.name);
    } catch (e) {
      setCreateError(String(e));
    } finally {
      setCreating(false);
    }
  }

  return (
    <div class="vault-picker" onClick={(e) => e.stopPropagation()}>
      <div class="vault-picker-row">
        <input
          type="text"
          placeholder={props.placeholder ?? "e.g. client-vault"}
          value={props.value}
          onInput={(e) => props.onChange(e.currentTarget.value)}
          autocomplete="off"
          autocorrect="off"
          autocapitalize="off"
          spellcheck={false}
        />
        <button
          type="button"
          class="btn-ghost"
          onClick={toggleBrowse}
        >
          Browse
        </button>
      </div>

      <Show when={open()}>
        <div class="vault-picker-dropdown">
          {/* New vault — at the top */}
          <div class="vault-picker-create-section">
            <Show when={!showCreate()}>
              <div
                class="vault-picker-item vault-picker-new"
                onClick={() => { setShowCreate(true); setNewVaultName(""); setCreateError(null); }}
              >
                + New vault
              </div>
            </Show>

            <Show when={showCreate()}>
              <div class="vault-picker-create-form">
                <input
                  ref={(el) => setTimeout(() => el.focus(), 0)}
                  type="text"
                  placeholder="Vault name"
                  value={newVaultName()}
                  onInput={(e) => setNewVaultName(e.currentTarget.value)}
                  onKeyDown={(e) => { if (e.key === "Enter") handleCreateVault(); }}
                  autocomplete="off"
                  autocorrect="off"
                  autocapitalize="off"
                  spellcheck={false}
                />
                <button
                  class="btn-primary btn-sm"
                  onClick={handleCreateVault}
                  disabled={creating() || !newVaultName().trim()}
                >
                  {creating() ? "Creating..." : "Create"}
                </button>
                <button
                  class="btn-ghost btn-sm"
                  onClick={() => { setShowCreate(false); setCreateError(null); }}
                >
                  Cancel
                </button>
              </div>
              <Show when={createError()}>
                <div class="vault-picker-error">{createError()}</div>
              </Show>
            </Show>
          </div>

          <Show when={loading()}>
            <div class="vault-picker-loading">
              <Spinner message="Loading vaults..." small />
            </div>
          </Show>

          <Show when={fetchError()}>
            <div class="vault-picker-error">{fetchError()}</div>
          </Show>

          <Show when={!loading() && vaultList().length > 0}>
            <For each={vaultList()}>
              {(v) => (
                <div
                  class={`vault-picker-item ${v.name === props.value ? "vault-picker-item-selected" : ""}`}
                  onClick={() => selectVault(v.name)}
                >
                  {v.name}
                </div>
              )}
            </For>
          </Show>

          <Show when={!loading() && !fetchError() && vaultList().length === 0}>
            <div class="vault-picker-empty">No vaults found</div>
          </Show>
        </div>
      </Show>

      <style>{`
        .vault-picker {
          position: relative;
        }

        .vault-picker-row {
          display: flex;
          gap: 8px;
          align-items: center;
        }

        .vault-picker-row input {
          flex: 1;
        }

        .vault-picker-dropdown {
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
          max-height: 300px;
          overflow-y: auto;
        }

        .vault-picker-item {
          padding: 8px 12px;
          cursor: pointer;
          font-size: 0.875rem;
          color: var(--text-primary);
          transition: background 0.1s;
        }

        .vault-picker-item:hover {
          background: var(--bg-elevated);
        }

        .vault-picker-item-selected {
          background: var(--accent-glow);
        }

        .vault-picker-item + .vault-picker-item {
          border-top: 1px solid var(--border);
        }

        .vault-picker-new {
          color: var(--accent);
          font-weight: 500;
        }

        .vault-picker-create-section {
          border-top: 1px solid var(--border);
        }

        .vault-picker-create-form {
          display: flex;
          gap: 6px;
          align-items: center;
          padding: 8px 10px;
        }

        .vault-picker-create-form input {
          flex: 1;
          font-size: 0.8125rem;
          padding: 5px 8px;
        }

        .vault-picker-loading,
        .vault-picker-error,
        .vault-picker-empty {
          padding: 12px;
          font-size: 0.8125rem;
          color: var(--text-secondary);
        }

        .vault-picker-error {
          color: var(--error);
        }

        .btn-sm {
          padding: 4px 10px;
          font-size: 0.75rem;
        }
      `}</style>
    </div>
  );
}
