/**
 * The graph's mapping to cytoscape elements.
 *
 * Cytoscape draws onto a canvas, which jsdom does not provide, so a test that
 * tried to render it would be a test that quietly stops asserting anything. The
 * part that can be wrong without a canvas is the mapping: a node sized on a
 * linear scale so everything looks like a dot, an edge that silently points at a
 * filtered-out endpoint, a hub that lost its ring. Those are checked here.
 */

import { describe, expect, it } from "vitest";

import {
  buildElements,
  edgeWidth,
  nodeSize,
  type GraphEdge,
  type GraphNode,
} from "@/components/graph-view";

const NODE_MIN = 8;
const NODE_MAX = 34;

function node(id: string, bytes: number, hub = false): GraphNode {
  return { id, label: `10.0.0.${id}`, bytes_total: bytes, hub_candidate: hub };
}

function edge(source: string, target: string, bytes: number): GraphEdge {
  return { source, target, bytes_total: bytes, protocols: ["tcp"] };
}

const colorFor = (protocols: string[]) => (protocols.includes("tls") ? "#c9a227" : "#3fb6c8");

describe("nodeSize", () => {
  it("uses a square-root scale, so a quiet endpoint is not flattened into the floor", () => {
    // A linear scale would put an endpoint at a tenth of the largest at ~10.6pt,
    // barely distinguishable from the 8pt floor. The square root makes it ~16pt,
    // which is what makes the drawing comparable rather than merely present.
    const span = NODE_MAX - NODE_MIN;
    expect(nodeSize(10_000, 10_000)).toBe(NODE_MAX);
    expect(nodeSize(1_000, 10_000)).toBeGreaterThan(NODE_MIN + span * 0.25);
    expect(nodeSize(1_000, 10_000)).toBeLessThan(NODE_MIN + span * 0.4);
  });

  it("keeps a quiet endpoint visible and clamps above the largest", () => {
    expect(nodeSize(0, 1000)).toBe(NODE_MIN);
    expect(nodeSize(5000, 1000)).toBe(NODE_MAX);
    expect(nodeSize(1, 0)).toBe(NODE_MIN);
  });

  it("grows monotonically with volume", () => {
    const sizes = [0, 100, 1_000, 5_000, 10_000].map((bytes) => nodeSize(bytes, 10_000));
    expect([...sizes].sort((a, b) => a - b)).toEqual(sizes);
  });
});

describe("edgeWidth", () => {
  it("grows with observed volume and never disappears", () => {
    expect(edgeWidth(0, 1000)).toBe(1);
    expect(edgeWidth(1000, 1000)).toBeGreaterThan(edgeWidth(10, 1000));
    expect(edgeWidth(1, 0)).toBe(1);
  });
});

describe("buildElements", () => {
  it("carries the node facts the stylesheet depends on", () => {
    const built = buildElements(
      [node("1", 500, true), node("2", 100)],
      [edge("1", "2", 400)],
      colorFor,
      null,
      500,
    );

    expect(built.nodes).toHaveLength(2);
    expect(built.nodes[0].data).toMatchObject({ id: "1", bytes: 500, hub: true });
    expect(built.nodes[1].data).toMatchObject({ id: "2", bytes: 100, hub: false });
  });

  it("drops an edge whose endpoint was filtered out instead of drawing a phantom", () => {
    const built = buildElements(
      [node("1", 500)],
      [edge("1", "2", 400)],
      colorFor,
      null,
      500,
    );
    expect(built.edges).toHaveLength(0);
  });

  it("gives every edge a unique id, so parallel traffic cannot merge", () => {
    const built = buildElements(
      [node("1", 500), node("2", 500)],
      [edge("1", "2", 400), edge("1", "2", 900)],
      colorFor,
      null,
      900,
    );
    expect(built.edges).toHaveLength(2);
    expect(built.edges[0].data.id).not.toBe(built.edges[1].data.id);
    expect(built.edges[1].data.width).toBeGreaterThan(built.edges[0].data.width);
  });

  it("colours an edge by its detected protocol", () => {
    const built = buildElements(
      [node("1", 500), node("2", 500)],
      [{ source: "1", target: "2", bytes_total: 400, protocols: ["tls"] }],
      colorFor,
      null,
      500,
    );
    expect(built.edges[0].data.color).toBe("#c9a227");
  });

  it("survives a single-node graph without throwing", () => {
    const built = buildElements([node("1", 10)], [], colorFor, null, 10);
    expect(built.nodes).toHaveLength(1);
    expect(built.edges).toEqual([]);
  });

  it("handles an empty capture", () => {
    const built = buildElements([], [], colorFor, null, 0);
    expect(built.nodes).toEqual([]);
    expect(built.edges).toEqual([]);
  });
});