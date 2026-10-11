/**
 * Capture-diff heat map colouring.
 *
 * The colour must encode similarity and delta magnitude deterministically, and
 * a zero delta must read as empty rather than as a colour. The map never claims
 * that a change is suspicious.
 */
import { describe, expect, it } from "vitest";

import {
  deltaColor,
  heatCells,
  maxAbs,
  similarityColor,
  similarityLabel,
} from "@/lib/diff-heatmap";

describe("similarityColor", () => {
  it("is red at 0 and green at 1", () => {
    expect(similarityColor(0)).toBe("rgb(201, 88, 79)");
    expect(similarityColor(1)).toBe("rgb(78, 168, 122)");
  });

  it("clamps out-of-range similarity", () => {
    expect(similarityColor(-5)).toBe(similarityColor(0));
    expect(similarityColor(9)).toBe(similarityColor(1));
  });
});

describe("deltaColor", () => {
  it("leaves no-change cells transparent", () => {
    expect(deltaColor(0, 100)).toBe("rgba(0, 0, 0, 0)");
  });

  it("grows opacity with magnitude and clamps at the table maximum", () => {
    expect(deltaColor(1, 100)).toContain("0.13");
    expect(deltaColor(100, 100)).toContain("0.62");
    // Larger than the shared maximum must not exceed the top of the scale.
    expect(deltaColor(1000, 100)).toContain("0.62");
  });

  it("uses a different hue for growth and shrink", () => {
    expect(deltaColor(50, 100)).not.toBe(deltaColor(-50, 100));
  });
});

describe("heatCells", () => {
  it("produces one coloured cell per metric", () => {
    const cells = heatCells({ similarity: 0.9, byte_delta: 10, packet_delta: -2 }, 20, 4);
    expect(cells.map((cell) => cell.key)).toEqual(["similarity", "bytes", "packets"]);
    expect(cells[0].color).toBe(similarityColor(0.9));
    expect(cells[2].color).toBe(deltaColor(-2, 4));
  });
});

describe("maxAbs", () => {
  it("is zero for an empty table and the largest magnitude otherwise", () => {
    expect(maxAbs([])).toBe(0);
    expect(maxAbs([3, -9, 5])).toBe(9);
  });
});

describe("similarityLabel", () => {
  it("never claims safety, only how close the match is", () => {
    expect(similarityLabel(1)).toBe("identical");
    expect(similarityLabel(0.1)).toBe("weak match");
  });
});
