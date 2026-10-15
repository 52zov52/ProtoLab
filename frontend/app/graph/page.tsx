"use client";

import { useSearchParams } from "next/navigation";
import { useMemo, useRef, useState } from "react";

import {
  GraphView,
  type GraphHandle,
  type GraphNode,
} from "@/components/graph-view";
import {
  Badge,
  Caveat,
  EmptyState,
  ErrorState,
  Panel,
  Skeleton,
} from "@/components/ui";
import { useAsync } from "@/hooks/use-async";
import { useProtocolFilter } from "@/hooks/use-protocol-filter";
import { useWorkspace } from "@/hooks/use-workspace";
import { api } from "@/lib/api";
import { edgeColor, protocolMeta } from "@/lib/graph-colors";
import { cn, formatNumber } from "@/lib/format";
import { useI18n } from "@/lib/i18n";

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
  const { t } = useI18n();
  const protocolFilter = useProtocolFilter();
  const projectId = params.get("project") ?? workspace.projectId;
  const [selected, setSelected] = useState<string | null>(null);
  const [minBytes, setMinBytes] = useState(0);
  // Pan, zoom and layout live inside the graph component; the page only needs
  // to be able to ask for a zoom or a reset.
  const graphRef = useRef<GraphHandle | null>(null);

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

  // The protocol filter is a second, independent view filter. An interaction is
  // hidden only when *every* protocol label it carries is hidden, so hiding a
  // noisy label never masks an interaction that also carried a label the
  // analyst still wants to see.
  const edgesShown = useMemo(
    () => edges.filter((e) => !e.protocols.every((p) => protocolFilter.isHidden(p))),
    [edges, protocolFilter],
  );

  const centrality = (graph.data?.centrality ?? []) as {
    rank: number;
    label: string;
    node: Node;
  }[];

  const legendProtocols = useMemo(() => {
    const names = new Set<string>();
    for (const edge of edges) {
      for (const protocol of edge.protocols) names.add(protocol);
    }
    return [...names].sort();
  }, [edges]);

  const hiddenCount = useMemo(
    () => legendProtocols.filter((protocol) => protocolFilter.isHidden(protocol)).length,
    [legendProtocols, protocolFilter],
  );

  const hubNodes = useMemo(
    () => nodes.filter((node) => node.hub_candidate),
    [nodes],
  );

  const selectedNode = nodes.find((n) => n.id === selected) ?? null;
  const connectedEdges = selected
    ? edgesShown.filter((e) => e.source === selected || e.target === selected)
    : [];

  if (!projectId) {
    return (
      <div className="p-4">
        <EmptyState title={t("No project selected")} />
      </div>
    );
  }

  return (
    <div className="flex h-full flex-col">
      <div className="border-b border-line px-4 py-3">
        <h1 className="text-sm font-semibold tracking-tight text-text">{t("Network Graph")}</h1>
        <p className="mt-0.5 max-w-3xl text-2xs leading-relaxed text-text-muted">
          {t(
            "Edges exist only where traffic was actually observed. Node size reflects observed volume; centrality is a triage aid, not an accusation.",
          )}
        </p>
      </div>

      <div className="flex shrink-0 flex-wrap items-center gap-3 border-b border-line px-4 py-2">
        <label className="flex items-center gap-2 text-2xs text-text-muted">
          <span className="uppercase tracking-wider">{t("Min traffic")}</span>
          <input
            type="number"
            min={0}
            step={64}
            value={minBytes}
            onChange={(event) => setMinBytes(Math.max(0, Number(event.target.value) || 0))}
            className="input w-28"
          />
          <span>{t("bytes")}</span>
        </label>
        <span className="text-2xs text-text-faint">
          {t("{shown} of {total} endpoints shown · {shownEdges} of {totalEdges} interactions", {
            shown: formatNumber(nodes.length),
            total: formatNumber(allNodes.length),
            shownEdges: formatNumber(edgesShown.length),
            totalEdges: formatNumber(allEdges.length),
          })}
        </span>
        {minBytes > 0 && (
          <button type="button" className="btn" onClick={() => setMinBytes(0)}>
            {t("Clear filter")}
          </button>
        )}
        {hiddenCount > 0 && (
          <button type="button" className="btn" onClick={protocolFilter.showAll}>
            {t("Show {count} hidden protocol(s)", { count: hiddenCount })}
          </button>
        )}
        <Caveat>
          {t(
            "Filtering hides endpoints below the threshold, and any interaction with them. It does not change the underlying analysis.",
          )}
        </Caveat>
      </div>

      <div className="grid min-h-0 flex-1 grid-cols-1 gap-3 overflow-auto p-3 lg:grid-cols-[1fr_340px]">
        <div className="space-y-3">
          <Panel title={t("Interaction graph")}>
            {captures.state === "loading" ? (
              <Skeleton rows={8} />
            ) : graph.state === "error" ? (
              <ErrorState message={graph.error ?? ""} onRetry={graph.reload} />
            ) : graph.data ? (
              <div className="p-3">
                <div className="flex items-start justify-between gap-2 pb-2">
                  <div className="flex flex-wrap items-center gap-1.5">
                    {legendProtocols.map((protocol) => {
                      const meta = protocolMeta(protocol);
                      const hidden = protocolFilter.isHidden(protocol);
                      return (
                        <button
                          key={protocol}
                          type="button"
                          onClick={() => protocolFilter.toggle(protocol)}
                          aria-pressed={!hidden}
                          title={hidden ? t("Show this protocol") : t("Hide this protocol")}
                          className={cn(
                            "flex items-center gap-1 rounded-sm border px-1.5 py-0.5 text-2xs transition-colors",
                            hidden
                              ? "border-line text-text-faint line-through opacity-60"
                              : "border-line-strong text-text-muted hover:border-accent-dim hover:text-text",
                          )}
                        >
                          <span
                            className="inline-block h-1.5 w-4 rounded-full"
                            style={{ background: meta.color, opacity: hidden ? 0.4 : 1 }}
                          />
                          {t(meta.label)}
                        </button>
                      );
                    })}
                  </div>
                  <div className="flex shrink-0 items-center gap-1">
                    <button
                      type="button"
                      className="btn"
                      title={t("Zoom out")}
                      onClick={() => graphRef.current?.zoomOut()}
                    >
                      −
                    </button>
                    <button
                      type="button"
                      className="btn"
                      title={t("Zoom in")}
                      onClick={() => graphRef.current?.zoomIn()}
                    >
                      +
                    </button>
                    <button
                      type="button"
                      className="btn"
                      onClick={() => graphRef.current?.reset()}
                    >
                      {t("reset")}
                    </button>
                  </div>
                </div>
                <GraphView
                  nodes={nodes as GraphNode[]}
                  edges={edgesShown}
                  colorFor={(protocols) => edgeColor({ protocols } as never)}
                  selected={selected}
                  onSelect={setSelected}
                  handleRef={graphRef}
                />
                <p className="mt-1 text-2xs text-text-faint">
                  {t(
                    "drag to pan · wheel or ± to zoom · reset fits the view · select a node on the canvas or from the centrality list",
                  )}
                </p>
                <div className="mt-2 flex flex-wrap items-center gap-3 text-2xs text-text-faint">
                  <span>
                    {t("nodes: {nodes} · edges: {edges} · {bytes} bytes observed", {
                      nodes: formatNumber(nodes.length),
                      edges: formatNumber(edgesShown.length),
                      bytes: formatNumber(
                        edgesShown.reduce((sum, e) => sum + e.bytes_total, 0),
                      ),
                    })}
                  </span>
                  {hubNodes.length > 0 && (
                    <span className="flex items-center gap-1 text-status-warn">
                      <span className="inline-block h-2 w-2 rounded-full border border-dashed border-status-warn" />
                      {t("{count} hub candidate(s)", { count: hubNodes.length })}
                    </span>
                  )}
                  {selected && (
                    <button type="button" className="btn" onClick={() => setSelected(null)}>
                      {t("clear selection")}
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
                title={t("No analysed captures")}
                description={t("Run an analysis on at least one capture to build the graph.")}
              />
            )}
          </Panel>
        </div>

        <div className="space-y-3">
          {selectedNode && (
            <Panel title={t("Node: {label}", { label: selectedNode.label })}>
              <div className="space-y-2 p-3">
                <dl className="grid grid-cols-2 gap-1 font-mono text-2xs">
                  <Stat label={t("bytes")} value={formatNumber(selectedNode.bytes_total)} />
                  <Stat label={t("peers")} value={String(selectedNode.unique_peers)} />
                  <Stat
                    label={t("degree")}
                    value={selectedNode.degree_centrality.toFixed(3)}
                  />
                  <Stat
                    label={t("betweenness")}
                    value={
                      selectedNode.betweenness === null
                        ? t("not computed")
                        : selectedNode.betweenness.toFixed(4)
                    }
                  />
                </dl>
                {selectedNode.hub_candidate ? (
                  <div className="space-y-1">
                    <Badge tone="warn">{t("hub candidate")}</Badge>
                    <p className="text-2xs text-text-muted">{selectedNode.hub_reason}</p>
                  </div>
                ) : null}
                <div>
                  <p className="mb-1 text-2xs uppercase tracking-wider text-text-faint">
                    {t("Observed connections")}
                  </p>
                  <ul className="space-y-0.5 font-mono text-2xs">
                    {connectedEdges.map((edge, index) => (
                      <li key={index} className="flex justify-between gap-2">
                        <span className="text-text-muted">
                          {edge.source === selectedNode.id ? edge.target : edge.source}
                        </span>
                        <span className="text-text-faint">
                          {t("{bytes} B", { bytes: formatNumber(edge.bytes_total) })}
                        </span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            </Panel>
          )}

          <Panel title={t("Centrality ranking")}>
            {centrality.length === 0 ? (
              <EmptyState title={t("No centrality computed")} />
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
                            <Badge tone="warn">{t("hub")}</Badge>
                          ) : null}
                          <Badge tone="info">
                            {t("deg {value}", {
                              value: entry.node.degree_centrality.toFixed(2),
                            })}
                          </Badge>
                        </span>
                      </div>
                      <p className="mt-0.5 text-2xs text-text-faint">
                        {entry.node.betweenness === null
                          ? t("betweenness n/a")
                          : t("betweenness {value}", {
                              value: entry.node.betweenness.toFixed(4),
                            })}
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
