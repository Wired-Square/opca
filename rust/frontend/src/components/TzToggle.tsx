import { tzMode, toggleTzMode } from "../utils/dates";

/**
 * Small inline button to toggle between UTC and local time display.
 */
export default function TzToggle() {
  return (
    <>
      <button class="tz-toggle" onClick={toggleTzMode} title="Toggle timezone">
        {tzMode() === "utc" ? "UTC" : "Local"}
      </button>
      <style>{`
        .tz-toggle {
          display: inline-flex;
          align-items: center;
          padding: 2px 8px;
          font-size: 0.6875rem;
          font-weight: 600;
          font-family: "SF Mono", "Cascadia Code", "Fira Code", monospace;
          color: var(--accent);
          background: var(--accent-glow);
          border: 1px solid var(--accent);
          border-radius: 4px;
          cursor: pointer;
          transition: all 0.15s ease;
          vertical-align: middle;
          margin-left: 6px;
          line-height: 1.4;
        }

        .tz-toggle:hover {
          background: var(--accent);
          color: #fff;
        }
      `}</style>
    </>
  );
}
