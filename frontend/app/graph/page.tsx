"use client";

import { useSearchParams } from "next/navigation";
import { useEffect, useMemo, useRef, useState } from "react";

import {
  Badge,
  Caveat,
  EmptyState,
  ErrorState,
  Panel,
  Skeleton,
} from "@/components/ui";
import { useAsync } from "@/hooks/use-async";
import { useWorkspace } from "@/hooks/use-workspace";
import { api } from "@/lib/api";
import { edgeColor, protocolMeta } from "@/lib/graph-colors";
import { cn, formatNumber } from "@/lib/format";

type Node = {
  id: string;
  kind: string;
  label: string;
  bytes_total: number;
  connections: number;
  unique_peers: number;
  degree: number;
  degree_centrality: number;
  betweenness: number | null;
  protocols: string[];
  hub_candidate: boolean;
  hub_reason: string | null;
};

type Edge = {
  source: string;
  target: string;
  bytes_total: number;
  packets: number;
  protocols: string[];
  link_status: string;
};

export default function GraphPage() {
  const workspace = useWorkspace();
  const params = useSearchParams();
  const projectId = params.get("project") ?? workspace.projectId;
  const [selected, setSelected] = useState<string | null>(null);
  const [minBytes, setMinBytes] = useState(0);
  const [view, setView] = useState({ x: 0, y: 0, k: 1 });
  const [drag, setDrag] = useState<{
    startX: number;
    startY: number;
    originX: number;
    originY: number;
    scale: number;
  } | null>(null);
  const svgRef = useRef<SVGSVGElement | null>(null);

  const captures = useAsync(
    () => (projectId ? api.projectCaptures(projectId) : Promise.resolve([])),
    [projectId, workspace.revision],
  );

  const graph = useAsync(
    async () => {
      const ids = (captures.data ?? [])
        .filter((c) => c.analysis_status === "completed")
        .map((c) => c.id);
      if (ids.length === 0) return null;
      return api.graph(ids);
    },
    [captures.data, projectId],
  );

  // Memoised so the fallback array is not a fresh reference on every render,
  // which would invalidate every downstream memo.
  const allNodes = useMemo(
    () => ((graph.data?.nodes ?? []) as Node[]) ?? [],
    [graph.data],
  );
  const allEdges = useMemo(
    () => ((graph.data?.edges ?? []) as Edge[]) ?? [],
    [graph.data],
  );

  // The traffic filter is applied client-side so the operator can narrow the
  // view without re-running the analysis. Hiding a node also hides any edge
  // that depended on it: an edge to an invisible endpoint would be a claim
  // about traffic the filter has excluded.
  const nodes = useMemo(
    () => (minBytes > 0 ? allNodes.filter((n) => n.bytes_total >= minBytes) : allNodes),
    [allNodes, minBytes],
  );
  const visibleIds = useMemo(() => new Set(nodes.map((n) => n.id)), [nodes]);
  const edges = useMemo(
    () => allEdges.filter((e) => visibleIds.has(e.source) && visibleIds.has(e.target)),
    [allEdges, visibleIds],
  );

  const layout = useMemo(() => {
    // A deterministic circular layout: reproducible across renders, which a
    // force simulation would not be.
    const size = 420;
    const radius = size / 2 - 40;
    const positions = new Map<string, { x: number; y: number }>();
    nodes.forEach((node, index) => {
      const angle = (index / Math.max(1, nodes.length)) * Math.PI * 2 - Math.PI / 2;
      positions.set(node.id, {
        x: size / 2 + Math.cos(angle) * radius,
        y: size / 2 + Math.sin(angle) * radius,
      });
    });
    return { size, positions };
  }, [nodes]);

  const maxBytes = Math.max(1, ...nodes.map((n) => n.bytes_total));
  const centrality = (graph.data?.centrality ?? []) as {
    rank: number;
    label: string;
    node: Node;
  }[];

  // Zoom with the wheel. Registered non-passively so the page does not scroll
  // while the pointer is over the graph.
  useEffect(() => {
    const element = svgRef.current;
    if (!element) return;
    const onWheel = (event: WheelEvent) => {
      event.preventDefault();
      setView((current) => {
        const factor = event.deltaY < 0 ? 1.12 : 1 / 1.12;
        const k = Math.min(4, Math.max(0.4, current.k * factor));
        return { ...current, k };
      });
    };
    element.addEventListener("wheel", onWheel, { passive: false });
    return () => element.removeEventListener("wheel", onWheel);
  }, [graph.data]);

  const legendProtocols = useMemo(() => {
    const names = new Set<string>();
    for (const edge of edges) {
      for (const protocol of edge.protocols) names.add(protocol);
    }
    return [...names].sort();
  }, [edges]);

  const hubNodes = useMemo(
    () => nodes.filter((node) => node.hub_candidate),
    [nodes],
  );

  const selectedNode = nodes.find((n) => n.id === selected) ?? null;
  const connectedEdges = selected
    ? edges.filter((e) => e.source === selected || e.target === selected)
    : [];

  if (!projectId) {
    return (
      <div className="p-4">
        <EmptyState title="No project selected" />
      </div>
    );
  }

  return (
    <div className="flex h-full flex-col">
      <div className="border-b border-line px-4 py-3">
        <h1 className="text-sm font-semibold tracking-tight text-text">Network Graph</h1>
        <p className="mt-0.5 max-w-3xl text-2xs leading-relaxed text-text-muted">
          Edges exist only where traffic was actually observed. Node size reflects
          observed volume; centrality is a triage aid, not an accusation.
        </p>
      </div>

      <div className="flex shrink-0 flex-wrap items-center gap-3 border-b border-line px-4 py-2">
        <label className="flex items-center gap-2 text-2xs text-text-muted">
          <span className="uppercase tracking-wider">Min traffic</span>
          <input
            type="number"
            min={0}
            step={64}
            value={minBytes}
            onChange={(event) => setMinBytes(Math.max(0, Number(event.target.value) || 0))}
            className="input w-28"
          />
          <span>bytes</span>
        </label>
        <span className="text-2xs text-text-faint">
          {nodes.length} of {allNodes.length} endpoints shown · {edges.length} of{" "}
          {allEdges.length} interactions
        </span>
        {minBytes > 0 && (
          <button type="button" className="btn" onClick={() => setMinBytes(0)}>
            Clear filter
          </button>
        )}
        <Caveat>
          Filtering hides endpoints below the threshold, and any interaction with
          them. It does not change the underlying analysis.
        </Caveat>
      </div>

      <div className="grid min-h-0 flex-1 grid-cols-1 gap-3 overflow-auto p-3 lg:grid-cols-[1fr_340px]">
        <div className="space-y-3">
          <Panel title="Interaction graph">
            {captures.state === "loading" ? (
              <Skeleton rows={8} />
            ) : graph.state === "error" ? (
              <ErrorState message={graph.error ?? ""} onRetry={graph.reload} />
            ) : graph.data ? (
              <div className="p-3">
                <div className="flex items-center justify-between gap-2 pb-2">
                  <div className="flex flex-wrap items-center gap-2">
                    {legendProtocols.map((protocol) => {
                      const meta = protocolMeta(protocol);
                      return (
                        <span
                          key={protocol}
                          className="flex items-center gap-1 text-2xs text-text-faint"
                        >
                          <span
                            className="inline-block h-1.5 w-4 rounded-full"
                            style={{ background: meta.color }}
                          />
                          {meta.label}
                        </span>
                      );
                    })}
                  </div>
                  <div className="flex items-center gap-1">
                    <button
                      type="button"
                      className="btn"
                      title="Zoom out"
                      onClick={() =>
                        setView((v) => ({ ...v, k: Math.max(0.4, v.k / 1.2) }))
                      }
                    >
                      −
                    </button>
                    <button
                      type="button"
                      className="btn"
                      title="Zoom in"
                      onClick={() =>
                        setView((v) => ({ ...v, k: Math.min(4, v.k * 1.2) }))
                      }
                    >
                      +
                    </button>
                    <button
                      type="button"
                      className="btn"
                      onClick={() => setView({ x: 0, y: 0, k: 1 })}
                    >
                      reset
                    </button>
                  </div>
                </div>
                <svg
                  ref={svgRef}
                  viewBox={`0 0 ${layout.size} ${layout.size}`}
                  className={cn(
                    "mx-auto h-auto w-full max-w-[560px] touch-none select-none",
                    drag ? "cursor-grabbing" : "cursor-grab",
                  )}
                  role="img"
                  aria-label={`Network graph with ${nodes.length} nodes and ${edges.length} edges`}
                  onMouseDown={(event) => {
                    const rect = svgRef.current?.getBoundingClientRect();
                    if (!rect) return;
                    setDrag({
                      startX: event.clientX,
                      startY: event.clientY,
                      originX: view.x,
                      originY: view.y,
                      scale: layout.size / rect.width,
                    });
                  }}
                  onMouseMove={(event) => {
                    if (!drag) return;
                    setView((v) => ({
                      ...v,
                      x: drag.originX + (event.clientX - drag.startX) * drag.scale,
                      y: drag.originY + (event.clientY - drag.startY) * drag.scale,
                    }));
                  }}
                  onMouseUp={() => setDrag(null)}
                  onMouseLeave={() => setDrag(null)}
                  onDoubleClick={() => setView({ x: 0, y: 0, k: 1 })}
                >
                  <g transform={`translate(${view.x} ${view.y}) scale(${view.k})`}>
                    <g>
                      {edges.map((edge, index) => {
                        const a = layout.positions.get(edge.source);
                        const b = layout.positions.get(edge.target);
                        if (!a || !b) return null;
                        const active =
                          selected === edge.source || selected === edge.target;
                        return (
                          <line
                            key={index}
                            x1={a.x}
                            y1={a.y}
                            x2={b.x}
                            y2={b.y}
                            stroke={active ? "#3fb6c8" : edgeColor(edge)}
                            strokeWidth={1 + (edge.bytes_total / maxBytes) * 6}
                            strokeOpacity={active ? 0.95 : selected ? 0.25 : 0.6}
                          />
                        );
                      })}
                    </g>
                    <g>
                      {nodes.map((node) => {
                        const point = layout.positions.get(node.id);
                        if (!point) return null;
                        const r = 5 + (node.bytes_total / maxBytes) * 14;
                        const active = node.id === selected;
                        return (
                          <g
                            key={node.id}
                            onClick={() => setSelected(active ? null : node.id)}
                            className="cursor-pointer"
                            role="button"
                            tabIndex={0}
                            onKeyDown={(event) => {
                              if (event.key === "Enter" || event.key === " ") {
                                setSelected(active ? null : node.id);
                              }
                            }}
                          >
                            {node.hub_candidate ? (
                              <circle
                                cx={point.x}
                                cy={point.y}
                                r={r + 4}
                                fill="none"
                                stroke="#c9a227"
                                strokeWidth={1.5}
                                strokeDasharray="3 2"
                              />
                            ) : null}
                            <circle
                              cx={point.x}
                              cy={point.y}
                              r={r}
                              fill={active ? "#3fb6c8" : "#171b21"}
                              stroke={
                                active
                                  ? "#3fb6c8"
                                  : node.hub_candidate
                                    ? "#c9a227"
                                    : "#8d97a3"
                              }
                              strokeWidth={1.5}
                            />
                            <text
                              x={point.x}
                              y={point.y + r + 11}
                              textAnchor="middle"
                              className="fill-[#8d97a3] font-mono text-[9px]"
                            >
                              {node.label}
                            </text>
                          </g>
                        );
                      })}
                    </g>
                  </g>
                </svg>
                <p className="mt-1 text-2xs text-text-faint">
                  drag to pan · wheel or ± to zoom · double-click to reset
                </p>
                <div className="mt-2 flex flex-wrap items-center gap-3 text-2xs text-text-faint">
                  <span>
                    nodes: {nodes.length} · edges: {edges.length} ·{" "}
                    {formatNumber(edges.reduce((sum, e) => sum + e.bytes_total, 0))} bytes
                    observed
                  </span>
                  {hubNodes.length > 0 && (
                    <span className="flex items-center gap-1 text-status-warn">
                      <span className="inline-block h-2 w-2 rounded-full border border-dashed border-status-warn" />
                      {hubNodes.length} hub candidate(s)
                    </span>
                  )}
                  {selected && (
                    <button type="button" className="btn" onClick={() => setSelected(null)}>
                      clear selection
                    </button>
                  )}
                </div>
                {(graph.data.warnings as string[] | undefined)?.map((warning, index) => (
                  <p key={index} className="mt-2 text-2xs text-status-warn">
                    {warning}
                  </p>
                ))}
              </div>
            ) : (
              <EmptyState
                title="No analysed captures"
                description="Run an analysis on at least one capture to build the graph."
              />
            )}
          </Panel>
        </div>

        <div className="space-y-3">
          {selectedNode && (
            <Panel title={`Node: ${selectedNode.label}`}>
              <div className="space-y-2 p-3">
                <dl className="grid grid-cols-2 gap-1 font-mono text-2xs">
                  <Stat label="bytes" value={formatNumber(selectedNode.bytes_total)} />
                  <Stat label="peers" value={String(selectedNode.unique_peers)} />
                  <Stat
                    label="degree"
                    value={selectedNode.degree_centrality.toFixed(3)}
                  />
                  <Stat
                    label="betweenness"
                    value={
                      selectedNode.betweenness === null
                        ? "not computed"
                        : selectedNode.betweenness.toFixed(4)
                    }
                  />
                </dl>
                {selectedNode.hub_candidate ? (
                  <div className="space-y-1">
                    <Badge tone="warn">hub candidate</Badge>
                    <p className="text-2xs text-text-muted">{selectedNode.hub_reason}</p>
                  </div>
                ) : null}
                <div>
                  <p className="mb-1 text-2xs uppercase tracking-wider text-text-faint">
                    Observed connections
                  </p>
                  <ul className="space-y-0.5 font-mono text-2xs">
                    {connectedEdges.map((edge, index) => (
                      <li key={index} className="flex justify-between gap-2">
                        <span className="text-text-muted">
                          {edge.source === selectedNode.id ? edge.target : edge.source}
                        </span>
                        <span className="text-text-faint">
                          {formatNumber(edge.bytes_total)} B
                        </span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            </Panel>
          )}

          <Panel title="Centrality ranking">
            {centrality.length === 0 ? (
              <EmptyState title="No centrality computed" />
            ) : (
              <ol className="space-y-1 p-3">
                {centrality.map((entry) => (
                  <li
                    key={entry.rank}
                    className={cn(
                      "rounded-sm border border-line px-2 py-1.5",
                      selected === entry.node.id && "border-accent-dim bg-accent-faint",
                    )}
                  >
                    <button
                      type="button"
                      className="w-full text-left"
                      onClick={() => setSelected(entry.node.id)}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-mono text-2xs text-text">
                          {entry.rank}. {entry.node.label}
                        </span>
                        <span className="flex items-center gap-1">
                          {entry.node.hub_candidate ? (
                            <Badge tone="warn">hub</Badge>
                          ) : null}
                          <Badge tone="info">
                            deg {entry.node.degree_centrality.toFixed(2)}
                          </Badge>
                        </span>
                      </div>
                      <p className="mt-0.5 text-2xs text-text-faint">
                        betweenness{" "}
                        {entry.node.betweenness === null
                          ? "n/a"
                          : entry.node.betweenness.toFixed(4)}
                      </p>
                    </button>
                  </li>
                ))}
              </ol>
            )}
            {graph.data && (
              <div className="px-3 pb-3">
                <Caveat tone="warn">{String(graph.data.interpretation_note)}</Caveat>
              </div>
            )}
          </Panel>
        </div>
      </div>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="text-text-faint">{label}</dt>
      <dd className="text-text">{value}</dd>
    </div>
  );
}