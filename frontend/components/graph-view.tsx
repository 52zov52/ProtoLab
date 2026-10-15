"use client";

import { useEffect, useImperativeHandle, useRef, type Ref } from "react";

/**
 * The interaction graph, on Cytoscape.
 *
 * What the library actually buys here, rather than merely being used:
 *
 *  * the layout is force-directed (`cose`), so a busy capture's hubs find their
 *    own positions instead of being evenly spaced around a circle - which is the
 *    difference between "who talks to whom" and "who is in the middle";
 *  * pan, pinch and box zoom, with node/edge hit-testing that follows the curve
 *    rather than its bounding box;
 *  * the graph keeps working at a few hundred endpoints, which a hand-rolled SVG
 *    does not.
 *
 * What is deliberately unchanged: the meaning of a node. Size is observed
 * volume, the dashed ring is a hub *candidate*, edge colour is the detected
 * protocol, and selection is the same one the side panels read. Cytoscape draws
 * the picture; it does not decide what the picture claims.
 *
 * The mapping from domain objects to cytoscape elements is a pure function
 * (`buildElements`) so it can be asserted without a canvas - jsdom has none,
 * and a test that needs a real canvas is a test that silently stops running.
 */

export interface GraphNode {
  id: string;
  label: string;
  bytes_total: number;
  hub_candidate: boolean;
}

export interface GraphEdge {
  source: string;
  target: string;
  bytes_total: number;
  /** Optional: the API reports `packets`; the drawing does not need it. */
  packets_total?: number;
  protocols: string[];
}

export const ACCENT = "#3fb6c8";
const SURFACE = "#171b21";
const HUB = "#c9a227";
const MUTED = "#8d97a3";

/** Smallest and largest node diameter, in points. */
const NODE_MIN = 8;
const NODE_MAX = 34;

export interface GraphElements {
  nodes: Array<{
    data: { id: string; label: string; bytes: number; hub: boolean };
    position?: { x: number; y: number };
  }>;
  edges: Array<{
    data: {
      id: string;
      source: string;
      target: string;
      color: string;
      width: number;
      bytes: number;
      label: string;
    };
  }>;
}

/**
 * Nodes are sized by observed volume on a square-root scale: a linear scale would
 * make every endpoint below the largest one look like a dot.
 */
export function nodeSize(bytes: number, maxBytes: number): number {
  if (maxBytes <= 0) return NODE_MIN;
  const ratio = Math.sqrt(Math.max(0, bytes) / maxBytes);
  return NODE_MIN + (NODE_MAX - NODE_MIN) * Math.min(1, ratio);
}

export function edgeWidth(bytes: number, maxBytes: number): number {
  if (maxBytes <= 0) return 1;
  return 1 + 5 * Math.min(1, bytes / maxBytes);
}

export function buildElements(
  nodes: GraphNode[],
  edges: GraphEdge[],
  colorFor: (protocols: string[]) => string,
  selected: string | null,
  maxBytes: number,
): GraphElements {
  const known = new Set(nodes.map((node) => node.id));
  return {
    nodes: nodes.map((node) => ({
      data: {
        id: node.id,
        label: node.label,
        bytes: node.bytes_total,
        hub: node.hub_candidate,
      },
    })),
    // An edge to an endpoint that was filtered out would be silently dropped by
    // cytoscape; the caller filters first, and this keeps the promise explicit.
    edges: edges
      .filter((edge) => known.has(edge.source) && known.has(edge.target))
      .map((edge, index) => ({
        data: {
          id: `${edge.source}->${edge.target}#${index}`,
          source: edge.source,
          target: edge.target,
          color: colorFor(edge.protocols),
          width: edgeWidth(edge.bytes_total, maxBytes),
          bytes: edge.bytes_total,
          label: edge.protocols.join(", "),
        },
      })),
  };
}

/** Stylesheet: one place, so "what colour means what" is answerable. */
function stylesheet(): Record<string, unknown>[] {
  return [
    {
      selector: "node",
      style: {
        "background-color": SURFACE,
        "border-color": MUTED,
        "border-width": 1.5,
        label: "data(label)",
        color: MUTED,
        "font-size": 9,
        "font-family": "ui-monospace, SFMono-Regular, Menlo, monospace",
        "text-valign": "bottom",
        "text-margin-y": 4,
        "text-halign": "center",
        "overlay-opacity": 0,
      },
    },
    {
      selector: "node[?hub]",
      style: {
        "border-color": HUB,
        "border-style": "dashed",
        "border-width": 2,
      },
    },
    {
      selector: "node:selected",
      style: {
        "background-color": ACCENT,
        "border-color": ACCENT,
        "border-style": "solid",
        color: "#d6dbe1",
        "z-index": 10,
      },
    },
    {
      selector: "edge",
      style: {
        width: "data(width)",
        "line-color": "data(color)",
        "curve-style": "bezier",
        "target-arrow-shape": "none",
        opacity: 0.6,
        "overlay-opacity": 0,
      },
    },
    {
      // While something is selected, everything not touching it recedes. The
      // dimming is a view choice and changes nothing about the analysis.
      selector: "edge:selected",
      style: { "line-color": ACCENT, opacity: 0.95, "z-index": 9 },
    },
  ];
}

export interface GraphHandle {
  zoomIn: () => void;
  zoomOut: () => void;
  reset: () => void;
  fit: () => void;
}

export function GraphView({
  nodes,
  edges,
  colorFor,
  selected,
  onSelect,
  handleRef,
}: {
  nodes: GraphNode[];
  edges: GraphEdge[];
  colorFor: (protocols: string[]) => string;
  selected: string | null;
  onSelect: (id: string | null) => void;
  handleRef?: Ref<GraphHandle>;
}) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const cyRef = useRef<{
    layout: (options: Record<string, unknown>) => void;
    zoom: (factor: number) => void;
    fit: (padding?: number) => void;
    nodes: () => { remove: () => void };
    destroy: () => void;
  } | null>(null);
  // Read inside the cytoscape callbacks, which are registered once. Synced in an
  // effect rather than during render: the callbacks only ever fire on user
  // interaction, which is after the commit.
  const onSelectRef = useRef(onSelect);
  const selectedRef = useRef(selected);
  useEffect(() => {
    onSelectRef.current = onSelect;
    selectedRef.current = selected;
  }, [onSelect, selected]);

  useImperativeHandle(
    handleRef,
    () => ({
      zoomIn: () => cyRef.current?.zoom(1.2),
      zoomOut: () => cyRef.current?.zoom(1 / 1.2),
      reset: () => cyRef.current?.fit(40),
      fit: () => cyRef.current?.fit(40),
    }),
    [],
  );

  useEffect(() => {
    let disposed = false;
    let cleanup = () => {};
    const maxBytes = Math.max(1, ...nodes.map((node) => node.bytes_total));
    const elements = buildElements(nodes, edges, colorFor, selected, maxBytes);

    // Loaded on demand: cytoscape is only needed once there is a graph to draw,
    // and a page that shows the "no project" state never pays for it.
    void (async () => {
      const { default: cytoscape } = await import("cytoscape");
      if (disposed || !containerRef.current) return;
      const cy = cytoscape({
        container: containerRef.current,
        elements,
        style: stylesheet() as never,
        // Deterministic seed: the same capture must draw the same picture twice,
        // because "it moved" is not information an analyst can use.
        layout: {
          name: "cose",
          animate: false,
          randomize: false,
          nodeRepulsion: () => 9000,
          idealEdgeLength: () => 90,
          nodeOverlap: 12,
          padding: 30,
        },
        minZoom: 0.2,
        maxZoom: 4,
        wheelSensitivity: 0.2,
      });
      cyRef.current = cy as never;

      cy.on("tap", "node", (event) => {
        // Tapping the selected node clears the selection, which is what the
        // hand-rolled SVG did and what an analyst expects.
        const id = event.target.id();
        onSelectRef.current(selectedRef.current === id ? null : id);
      });
      cy.on("tap", (event) => {
        if (event.target === cy) onSelectRef.current(null);
      });

      cleanup = () => {
        cy.destroy();
        cyRef.current = null;
      };
    })();

    return () => {
      disposed = true;
      cleanup();
      cyRef.current?.nodes().remove();
    };
    // The graph is rebuilt whenever the data or the filters change; the instance
    // is never mutated in place, so a stale node cannot survive a filter change.
  }, [nodes, edges, colorFor, selected]);

  // Selection is a view state: apply it to the existing instance instead of
  // rebuilding the layout, or picking a node would reshuffle the whole picture.
  useEffect(() => {
    const cy = cyRef.current as unknown as {
      nodes: (selector?: string) => { removeClass: (name: string) => void; addClass: (name: string) => void };
    } | null;
    if (!cy) return;
    cy.nodes().removeClass("selected");
    if (selected) cy.nodes(selected).addClass("selected");
  }, [selected]);

  return (
    <div className="flex justify-center">
      <div
        ref={containerRef}
        className="h-[520px] w-full max-w-[720px] touch-none"
        role="img"
        aria-label={`Network graph with ${nodes.length} nodes and ${edges.length} edges`}
      />
    </div>
  );
}