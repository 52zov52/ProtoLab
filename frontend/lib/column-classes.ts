/**
 * Presentation for byte-column classes produced by the backend.
 *
 * A class describes the *shape* of a column (constant, counter, enum,
 * high_entropy, variable), never the meaning of a field, so the colours are a
 * reading aid and the labels never claim to know what a byte means.
 */
import type { StatusTone } from "@/lib/format";

export interface ColumnClassMeta {
  label: string;
  color: string;
  tone: StatusTone;
  description: string;
}

export const COLUMN_CLASS_META: Record<string, ColumnClassMeta> = {
  constant: {
    label: "constant",
    color: "#5d6772",
    tone: "neutral",
    description: "The same byte in every message that reaches this offset.",
  },
  counter: {
    label: "counter",
    color: "#5b8fd6",
    tone: "info",
    description: "Rises across consecutive messages; a counter or running id.",
  },
  enum: {
    label: "enum",
    color: "#4ea87a",
    tone: "ok",
    description: "A small set of values; a type or status code.",
  },
  high_entropy: {
    label: "high entropy",
    color: "#c9a227",
    tone: "warn",
    description:
      "Near-uniform and always changing: random, compressed, encrypted or a checksum — indistinguishable here.",
  },
  variable: {
    label: "variable",
    color: "#8d97a3",
    tone: "neutral",
    description: "Changes, but no stronger reading is supported.",
  },
  absent: {
    label: "absent",
    color: "#3a3f47",
    tone: "unknown",
    description: "Never present in the corpus.",
  },
  unknown: {
    label: "unknown",
    color: "#5d6772",
    tone: "unknown",
    description: "Not classified.",
  },
};

export const UNKNOWN_COLUMN_CLASS = "unknown";

export function columnClassMeta(name: string): ColumnClassMeta {
  return COLUMN_CLASS_META[name] ?? COLUMN_CLASS_META[UNKNOWN_COLUMN_CLASS];
}

/** The legend, in the order classes most often appear while reading a column. */
export function columnClassLegend(): ColumnClassMeta[] {
  return [
    COLUMN_CLASS_META.constant,
    COLUMN_CLASS_META.counter,
    COLUMN_CLASS_META.enum,
    COLUMN_CLASS_META.high_entropy,
    COLUMN_CLASS_META.variable,
  ];
}
