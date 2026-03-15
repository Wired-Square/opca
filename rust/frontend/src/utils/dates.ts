/**
 * Date display utilities for opCA.
 *
 * Dates are stored in ASN1 GeneralizedTime format: "20270415051336Z"
 * We parse them and display in a human-friendly format, with the ability
 * to toggle between UTC and local time.
 */

import { createSignal } from "solid-js";

export type TimeZoneMode = "utc" | "local";

const [tzMode, setTzMode] = createSignal<TimeZoneMode>("utc");

export { tzMode };

export function toggleTzMode() {
  setTzMode((m) => (m === "utc" ? "local" : "utc"));
}

/**
 * Parse an ASN1 GeneralizedTime string ("20270415051336Z") into a Date.
 * Falls back to trying Date.parse for other formats.
 */
function parseAsn1Date(value: string): Date | null {
  // ASN1 format: YYYYMMDDHHmmSSZ (15 chars)
  const m = value.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/);
  if (m) {
    return new Date(
      Date.UTC(
        parseInt(m[1]),
        parseInt(m[2]) - 1,
        parseInt(m[3]),
        parseInt(m[4]),
        parseInt(m[5]),
        parseInt(m[6]),
      ),
    );
  }
  // Fallback: try native parsing (handles "Apr 15 05:13:36 2027 GMT" etc.)
  const d = new Date(value);
  return isNaN(d.getTime()) ? null : d;
}

/**
 * Format a date string for display.
 *
 * Returns a human-friendly string in either UTC or local time,
 * depending on the current timezone mode.
 */
export function formatDate(
  value: string | null | undefined,
  mode?: TimeZoneMode,
): string {
  if (!value) return "\u2014";
  const date = parseAsn1Date(value);
  if (!date) return value; // Can't parse — return raw

  const tz = mode ?? tzMode();

  if (tz === "utc") {
    return date.toLocaleString("en-AU", {
      timeZone: "UTC",
      day: "numeric",
      month: "short",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    }) + " UTC";
  }

  return date.toLocaleString("en-AU", {
    day: "numeric",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
    timeZoneName: "short",
  });
}
