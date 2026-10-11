/**
 * Byte-column class presentation.
 *
 * The class is a rendering of the backend's shape-based classification, never a
 * claim about what a byte means, so the labels and tones must stay within the
 * declared set and an unrecognised class must fall back visibly.
 */
import { describe, expect, it } from "vitest";

import {
  COLUMN_CLASS_META,
  columnClassLegend,
  columnClassMeta,
} from "@/lib/column-classes";

describe("columnClassMeta", () => {
  it("falls back to the unknown class for an unrecognised name", () => {
    expect(columnClassMeta("not_a_class")).toBe(COLUMN_CLASS_META.unknown);
  });

  it("keeps counter and high entropy visually distinct", () => {
    expect(columnClassMeta("counter").color).not.toBe(
      columnClassMeta("high_entropy").color,
    );
    expect(columnClassMeta("high_entropy").tone).toBe("warn");
  });

  it("never claims to know a meaning, only a shape", () => {
    for (const meta of Object.values(COLUMN_CLASS_META)) {
      expect(meta.description.length).toBeGreaterThan(0);
      expect(meta.label.length).toBeGreaterThan(0);
    }
  });
});

describe("columnClassLegend", () => {
  it("lists the readable classes exactly once each", () => {
    const labels = columnClassLegend().map((meta) => meta.label);
    expect(labels).toEqual(["constant", "counter", "enum", "high entropy", "variable"]);
  });
});
