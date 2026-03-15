import { tauriInvoke } from "../api/tauri";

interface PemInputProps {
  label: string;
  placeholder?: string;
  value: string;
  onInput: (value: string) => void;
  rows?: number;
}

/**
 * Reusable PEM input — textarea for pasting PEM content, with a Browse button
 * that opens a native file picker and reads the selected file via Tauri.
 */
export default function PemInput(props: PemInputProps) {
  async function handleBrowse() {
    const { open } = await import("@tauri-apps/plugin-dialog");
    const path = await open({
      multiple: false,
      filters: [{ name: "PEM", extensions: ["pem", "crt", "cer", "key"] }],
    });
    if (!path) return;

    const content = await tauriInvoke<string>("read_text_file", {
      path: path as string,
    });
    props.onInput(content);
  }

  function handleClear() {
    props.onInput("");
  }

  return (
    <div class="form-group">
      <label class="form-label">{props.label}</label>
      <div class="pem-input-row">
        <textarea
          class="pem-textarea"
          placeholder={props.placeholder ?? "Paste PEM content or use Browse\u2026"}
          value={props.value}
          onInput={(e) => props.onInput(e.currentTarget.value)}
          rows={props.rows ?? 6}
          autocomplete="off"
          autocorrect="off"
          autocapitalize="off"
          spellcheck={false}
        />
        <div class="pem-btn-col">
          <button type="button" class="btn-ghost pem-action-btn" onClick={handleBrowse}>
            Browse
          </button>
          <button
            type="button"
            class="btn-ghost pem-action-btn"
            onClick={handleClear}
            disabled={!props.value}
          >
            Clear
          </button>
        </div>
      </div>

      <style>{`
        .pem-input-row {
          display: flex;
          gap: 8px;
          align-items: flex-start;
        }

        .pem-textarea {
          flex: 1;
          font-family: "JetBrains Mono", "SF Mono", "Fira Code", monospace;
          font-size: 0.75rem;
          line-height: 1.5;
          resize: vertical;
          min-height: 80px;
        }

        .pem-btn-col {
          display: flex;
          flex-direction: column;
          gap: 4px;
          flex-shrink: 0;
        }

        .pem-action-btn {
          font-size: 0.8125rem;
          padding: 4px 10px;
        }
      `}</style>
    </div>
  );
}
