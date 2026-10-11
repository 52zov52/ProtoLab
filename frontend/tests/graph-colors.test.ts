/**
 * Network-graph colouring.
 *
 * The colour must come from the detected protocol, never from a port, and an
 * unknown protocol must be visibly unclassified rather than silently assigned
 * the colour of a familiar one.
 */
import { describe, expect, it } from "vitest";

import { edgeColor, protocolMeta, UNKNOWN_PROTOCOL_COLOR } from "@/lib/graph-colors";

describe("edgeColor", () => {
  it("uses the detected protocol, not the order of the list", () => {
    const blue = edgeColor({ protocols: ["unknown_binary", "tls"] });
    expect(blue).toBe(protocolMeta("tls").color);
  });

  it("falls back to the first label when none is known", () => {
    expect(edgeColor({ protocols: ["custom_binary"] })).toBe(UNKNOWN_PROTOCOL_COLOR);
  });

  it("is grey and unclassified for an empty protocol list", () => {
    expect(edgeColor({ protocols: [] })).toBe(UNKNOWN_PROTOCOL_COLOR);
  });

  it("never keys a colour off a port number", () => {
    // A label that merely looks like a port must not resolve to a real colour.
    expect(protocolMeta("443").color).toBe(UNKNOWN_PROTOCOL_COLOR);
    expect(protocolMeta("443").label).toBe("443");
  });
});