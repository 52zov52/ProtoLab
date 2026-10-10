import { clsx, type ClassValue } from "clsx";

export function cn(...inputs: ClassValue[]): string {
  return clsx(inputs);
}

// --------------------------------------------------------------------------
// Formatting
// --------------------------------------------------------------------------

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes)) return "-";
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KiB", "MiB", "GiB", "TiB"];
  let value = bytes / 1024;
  let index = 0;
  while (value >= 1024 && index < units.length - 1) {
    value /= 1024;
    index += 1;
  }
  return `${value.toFixed(value >= 100 ? 0 : 1)} ${units[index]}`;
}

export function formatNumber(value: number): string {
  return new Intl.NumberFormat("en-US").format(value);
}

export function formatTimestamp(epochSeconds: number): string {
  if (!epochSeconds) return "-";
  const date = new Date(epochSeconds * 1000);
  return date.toISOString().replace("T", " ").replace(".000Z", "Z");
}

export function formatDuration(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 0) return "-";
  if (seconds < 1) return `${(seconds * 1000).toFixed(1)} ms`;
  if (seconds < 60) return `${seconds.toFixed(3)} s`;
  const minutes = Math.floor(seconds / 60);
  return `${minutes}m ${(seconds % 60).toFixed(0)}s`;
}

export function formatPercent(value: number, digits = 1): string {
  if (!Number.isFinite(value)) return "-";
  return `${(value * 100).toFixed(digits)}%`;
}

// --------------------------------------------------------------------------
// Status presentation
//
// Status is never conveyed by colour alone: every badge carries a text label,
// which is an accessibility requirement and also keeps the UI readable for
// colour-blind users.
// --------------------------------------------------------------------------

export type StatusTone = "ok" | "warn" | "bad" | "info" | "unknown" | "neutral";

const TONE_CLASSES: Record<StatusTone, string> = {
  ok: "border-status-ok/40 text-status-ok bg-status-ok/10",
  warn: "border-status-warn/40 text-status-warn bg-status-warn/10",
  bad: "border-status-bad/40 text-status-bad bg-status-bad/10",
  info: "border-status-info/40 text-status-info bg-status-info/10",
  unknown: "border-status-unknown/40 text-status-unknown bg-status-unknown/10",
  neutral: "border-line-strong text-text-muted bg-surface-raised",
};

export function toneClasses(tone: StatusTone): string {
  return TONE_CLASSES[tone];
}

export function completenessTone(status: string): StatusTone {
  switch (status) {
    case "complete":
      return "ok";
    case "open_at_capture_end":
      return "info";
    case "truncated_start":
    case "truncated_end":
    case "partial":
      return "warn";
    case "reset":
      return "bad";
    default:
      return "unknown";
  }
}

export function verdictTone(verdict: string): StatusTone {
  switch (verdict) {
    case "consistent_with_corpus":
      return "ok";
    case "partially_consistent":
      return "warn";
    case "contradicted":
      return "bad";
    case "no_data":
    case "canceled":
      return "unknown";
    default:
      return "neutral";
  }
}

export function roleTone(confidence: string): StatusTone {
  switch (confidence) {
    case "syn_observed":
      return "ok";
    case "heuristic_first_payload":
      return "warn";
    default:
      return "unknown";
  }
}

export function hypothesisTone(status: string): StatusTone {
  switch (status) {
    case "supported":
      return "ok";
    case "contradicted":
      return "bad";
    case "testing":
    case "proposed":
    case "revised":
      return "info";
    case "rejected":
      return "neutral";
    default:
      return "unknown";
  }
}

export function checkTone(verdict: string): StatusTone {
  switch (verdict) {
    case "pass":
      return "ok";
    case "fail":
      return "bad";
    case "unknown":
      return "warn";
    default:
      return "neutral";
  }
}

// --------------------------------------------------------------------------
// Hex helpers
// --------------------------------------------------------------------------

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/[^0-9a-fA-F]/g, "");
  const out = new Uint8Array(Math.floor(clean.length / 2));
  for (let i = 0; i < out.length; i += 1) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export function asciiPreview(bytes: Uint8Array): string {
  let out = "";
  for (const byte of bytes) {
    out += byte >= 0x20 && byte < 0x7f ? String.fromCharCode(byte) : ".";
  }
  return out;
}

/** Rows are ``[offset, cells, ascii]``; gaps are rendered explicitly. */
export interface HexRow {
  offset: number;
  cells: string[];
  ascii: string;
  isGap: boolean;
}

export function toHexRows(
  lines: { offset: number; hex: string[]; ascii: string[]; length: number }[],
): HexRow[] {
  return lines.map((line) => ({
    offset: line.offset,
    cells: line.hex,
    ascii: line.ascii[0] ?? "",
    isGap: line.hex.includes("GAP"),
  }));
}