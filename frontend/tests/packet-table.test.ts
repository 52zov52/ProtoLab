/**
 * Packet table virtualisation.
 *
 * Only the rows inside (or just outside) the visible viewport may be rendered;
 * a windowing bug would either drop rows or render all of them, and both are
 * silently invisible to an analyst. These tests pin the pure slice logic.
 */
import { describe, expect, it } from "vitest";

import { visibleSlice } from "@/components/packet-table";

describe("visibleSlice", () => {
  it("renders the first viewport worth of rows", () => {
    const items = Array.from({ length: 100 }, (_, index) => index);
    const slice = visibleSlice(items, 0, 300, 30);
    expect(slice[0]).toBe(0);
    expect(slice.length).toBeGreaterThanOrEqual(10);
    expect(slice.length).toBeLessThan(20);
  });

  it("windows a middle scroll position without dropping the row under the fold", () => {
    const items = Array.from({ length: 1000 }, (_, index) => index);
    const slice = visibleSlice(items, 300 * 30, 300, 30);
    // The viewport is 300px tall, so it shows rows ~300..310; with overscan
    // the slice must straddle that window on both sides.
    expect(slice[0]).toBeLessThanOrEqual(300);
    const last = slice[slice.length - 1];
    expect(last).toBeGreaterThanOrEqual(309);
  });

  it("clamps a stale scroll position to the tail instead of dropping all rows", () => {
    const items = Array.from({ length: 5 }, (_, index) => index);
    const slice = visibleSlice(items, 10_000, 1000, 30);
    expect(slice[slice.length - 1]).toBe(4);
    expect(slice.every((value) => value < 5)).toBe(true);
  });

  it("returns an empty window for a hidden viewport", () => {
    expect(visibleSlice([1, 2, 3], 0, 0, 30)).toEqual([]);
  });
});