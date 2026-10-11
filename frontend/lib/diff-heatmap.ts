/**
 * Capture-diff heat map colouring.
 *
 * Pure functions, so the colour scale can be asserted without a browser.  A
 * difference in a capture is not an anomaly: the colour encodes *how much*
 * something changed and in which direction, never whether it is suspicious.
 */

const BAD = [201, 88, 79]; // #c9584f
const WARN = [201, 162, 39]; // #c9a227
const OK = [78, 168, 122]; // #4ea87a
const INFO = [91, 143, 214]; // #5b8fd6

function clamp(value: number, low: number, high: number): number {
  return Math.max(low, Math.min(high, value));
}

function mix(a: number[], b: number[], t: number): number[] {
  return a.map((channel, index) => Math.round(channel + (b[index] - channel) * t));
}

function rgb(channels: number[], alpha = 1): string {
  const [r, g, b] = channels;
  return alpha >= 1 ? `rgb(${r}, ${g}, ${b})` : `rgba(${r}, ${g}, ${b}, ${alpha})`;
}

/** Similarity 0 (nothing in common) → 1 (identical): red → amber → green. */
export function similarityColor(similarity: number): string {
  const t = clamp(similarity, 0, 1);
  const channels = t < 0.5 ? mix(BAD, WARN, t / 0.5) : mix(WARN, OK, (t - 0.5) / 0.5);
  return rgb(channels);
}

/** Similarity as a short human label; never claims safety or danger. */
export function similarityLabel(similarity: number): string {
  if (similarity >= 0.999) return "identical";
  if (similarity >= 0.8) return "very similar";
  if (similarity >= 0.55) return "matched";
  return "weak match";
}

/**
 * A delta cell: direction sets the hue (growth = info, shrink = warn), and the
 * magnitude relative to the largest delta in the table sets the opacity. A zero
 * delta is left transparent so "no change" reads as empty.
 */
export function deltaColor(value: number, magnitude: number): string {
  if (!Number.isFinite(value) || value === 0) return "rgba(0, 0, 0, 0)";
  const ratio = magnitude > 0 ? clamp(Math.abs(value) / magnitude, 0, 1) : 1;
  const alpha = 0.12 + ratio * 0.5;
  return rgb(value > 0 ? INFO : WARN, Number(alpha.toFixed(2)));
}

export interface HeatRow {
  similarity: number;
  byte_delta?: number;
  packet_delta?: number;
}

/**
 * The (session × metric) grid used by the heat map, with each cell already
 * coloured. Magnitudes are shared across the table so a cell's shade is
 * comparable with every other cell, not just its own row.
 */
export interface HeatCell {
  key: "similarity" | "bytes" | "packets";
  label: string;
  value: number;
  color: string;
  title: string;
}

export function heatCells(row: HeatRow, maxByte: number, maxPacket: number): HeatCell[] {
  const byteDelta = row.byte_delta ?? 0;
  const packetDelta = row.packet_delta ?? 0;
  return [
    {
      key: "similarity",
      label: "similarity",
      value: row.similarity,
      color: similarityColor(row.similarity),
      title: `similarity ${row.similarity.toFixed(3)} (${similarityLabel(row.similarity)})`,
    },
    {
      key: "bytes",
      label: "byte Δ",
      value: byteDelta,
      color: deltaColor(byteDelta, maxByte),
      title: `byte delta ${byteDelta > 0 ? "+" : ""}${byteDelta}`,
    },
    {
      key: "packets",
      label: "packet Δ",
      value: packetDelta,
      color: deltaColor(packetDelta, maxPacket),
      title: `packet delta ${packetDelta > 0 ? "+" : ""}${packetDelta}`,
    },
  ];
}

export function maxAbs(values: number[]): number {
  return values.reduce((max, value) => Math.max(max, Math.abs(value)), 0);
}