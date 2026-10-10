"use client";

import { useSearchParams } from "next/navigation";
import { useState } from "react";

import { HexComparison, HexViewer } from "@/components/hex-viewer";
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
import { cn } from "@/lib/format";

type MessageRow = {
  id: string;
  index_in_stream: number;
  start_offset: number;
  end_offset: number;
  present_length: number;
  declared_length: number | null;
  complete: boolean;
  confidence: number;
  framing_method: string;
  features: Record<string, number>;
};

export default function WorkbenchPage() {
  const workspace = useWorkspace();
  const params = useSearchParams();
  const sessionId = params.get("session") ?? workspace.sessionId;
  const captureId = workspace.captureId;

  const [streamId, setStreamId] = useState<string | null>(workspace.streamId);
  const [selected, setSelected] = useState<string[]>([]);
  const [directionFilter, setDirectionFilter] = useState<string>("all");

  const streams = useAsync(
    () => (sessionId ? api.sessionStreams(sessionId) : Promise.resolve(null)),
    [sessionId, workspace.revision],
  );

  const messages = useAsync(
    () =>
      streamId && captureId
        ? api.listMessages(captureId, `?stream_id=${streamId}&limit=500`)
        : Promise.resolve(null),
    [streamId, captureId, workspace.revision],
  );

  const stats = useAsync(
    () => (streamId ? api.fieldStatistics(streamId) : Promise.resolve(null)),
    [streamId, workspace.revision],
  );

  const comparison = useAsync(async () => {
    if (!streamId || selected.length < 2) return null;
    return api.compareMessages(streamId, selected);
  }, [streamId, selected.join(",")]);

  const rows = ((messages.data?.items ?? []) as unknown as MessageRow[]) ?? [];
  const filtered =
    directionFilter === "all"
      ? rows
      : (streams.data ?? []).filter((s) => s.id === streamId) &&
        rows;

  const toggle = (id: string) => {
    setSelected((current) => {
      if (current.includes(id)) return current.filter((item) => item !== id);
      if (current.length >= 6) return [...current.slice(1), id];
      return [...current, id];
    });
  };

  if (!captureId) {
    return (
      <div className="p-4">
        <EmptyState
          title="No capture selected"
          description="The Protocol Workbench compares framed messages from a reconstructed stream."
        />
      </div>
    );
  }

  const candidates = (stats.data?.candidates ?? []) as {
    name: string;
    offset: number;
    size: number;
    endianness: string;
    role: string;
    confidence: number;
    rationale: string;
    support_count: number;
    contradiction_count: number;
  }[];

  const columnStats = (stats.data?.column_stats ?? []) as {
    offset: number;
    present_count: number;
    absent_count: number;
    unique_values: number;
    entropy: number;
    change_rate: number;
    zero_count: number;
    most_common: [number, number][];
  }[];

  return (
    <div className="flex h-full flex-col">
      <div className="flex shrink-0 items-start justify-between gap-4 border-b border-line px-4 py-3">
        <div>
          <h1 className="text-sm font-semibold tracking-tight text-text">Protocol Workbench</h1>
          <p className="mt-0.5 max-w-3xl text-2xs leading-relaxed text-text-muted">
            Compare binary messages side by side, read the per-offset statistics and see
            which field candidates the data actually supports.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-1">
          {(streams.data ?? []).map((s) => (
            <button
              key={s.id}
              type="button"
              className={cn("btn", s.id === streamId && "btn-primary")}
              onClick={() => {
                setStreamId(s.id);
                setSelected([]);
              }}
            >
              {s.direction}
            </button>
          ))}
          {directionFilter !== "all" && (
            <span className="text-2xs text-text-faint">filter: {directionFilter}</span>
          )}
        </div>
      </div>

      <div className="grid min-h-0 flex-1 grid-cols-1 gap-3 overflow-auto p-3 xl:grid-cols-2">
        <Panel
          title="Messages (select 2–6 to compare)"
          actions={
            selected.length > 0 ? (
              <button type="button" className="btn" onClick={() => setSelected([])}>
                clear
              </button>
            ) : null
          }
        >
          {messages.state === "loading" ? (
            <Skeleton rows={12} />
          ) : messages.state === "error" ? (
            <ErrorState message={messages.error ?? ""} onRetry={messages.reload} />
          ) : filtered.length === 0 ? (
            <EmptyState
              title="No framed messages"
              description="Choose a framing rule on the Stream Explorer first."
            />
          ) : (
            <table className="data-table">
              <thead>
                <tr>
                  <th />
                  <th>#</th>
                  <th>Range</th>
                  <th>Len</th>
                  <th>Entropy</th>
                  <th>Unique</th>
                  <th>State</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((message) => {
                  const active = selected.includes(message.id);
                  return (
                    <tr
                      key={message.id}
                      className={cn("cursor-pointer", active && "bg-accent-faint")}
                      onClick={() => toggle(message.id)}
                    >
                      <td>
                        <input type="checkbox" checked={active} readOnly />
                      </td>
                      <td className="text-text-faint">{message.index_in_stream}</td>
                      <td className="text-text-muted">
                        {message.start_offset}…{message.end_offset}
                      </td>
                      <td>{message.present_length}</td>
                      <td>{(message.features.entropy ?? 0).toFixed(2)}</td>
                      <td>{message.features.unique_bytes ?? "-"}</td>
                      <td>
                        <Badge tone={message.complete ? "ok" : "warn"}>
                          {message.complete ? "complete" : "partial"}
                        </Badge>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </Panel>

        <Panel title="Per-offset alignment">
          {selected.length < 2 ? (
            <EmptyState
              title="Select at least two messages"
              description="Alignment is positional: a byte at offset N in one message is compared with offset N in another. Where a message is shorter, the position is shown as absent, never as zero."
            />
          ) : comparison.state === "loading" ? (
            <Skeleton rows={12} />
          ) : comparison.data ? (
            <div className="flex h-full min-h-0 flex-col">
              <div className="border-b border-line p-2">
                <p className="text-2xs text-text-muted">
                  {String((comparison.data.alignment as { description: string }).description)}
                </p>
              </div>
              <HexComparison
                labels={selected.map((id) => `#${rows.find((r) => r.id === id)?.index_in_stream ?? "?"}`)}
                rows={(comparison.data.rows as never[]) ?? []}
              />
            </div>
          ) : (
            <EmptyState title="No comparison" />
          )}
        </Panel>

        <Panel title="Field candidates inferred from the bytes">
          {stats.state === "loading" ? (
            <Skeleton rows={8} />
          ) : candidates.length === 0 ? (
            <EmptyState
              title="No candidates"
              description="Insufficient messages or no structure detected yet."
            />
          ) : (
            <div className="space-y-2 p-3">
              {candidates.slice(0, 10).map((candidate, index) => (
                <div
                  key={index}
                  className="rounded-sm border border-line bg-surface-raised p-2.5"
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge tone={index === 0 ? "ok" : "neutral"}>{candidate.role}</Badge>
                    <span className="font-mono text-2xs text-accent">
                      {candidate.name} @ {candidate.offset} ({candidate.size}B{" "}
                      {candidate.endianness})
                    </span>
                    <span className="ml-auto font-mono text-2xs text-text-muted">
                      {(candidate.confidence * 100).toFixed(0)}%
                    </span>
                  </div>
                  <p className="mt-1 text-2xs leading-relaxed text-text-muted">
                    {candidate.rationale}
                  </p>
                  <p className="mt-1 font-mono text-2xs text-text-faint">
                    supports {candidate.support_count} · contradicts{" "}
                    {candidate.contradiction_count}
                  </p>
                </div>
              ))}
              <Caveat tone="warn">
                These are hypotheses generated from observed bytes. A candidate name is
                a label, not a claim: nothing here proves what a field <em>means</em>.
              </Caveat>
            </div>
          )}
        </Panel>

        <Panel title="Column statistics">
          {columnStats.length === 0 ? (
            <EmptyState title="No statistics" />
          ) : (
            <div className="overflow-x-auto">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Offset</th>
                    <th>Present</th>
                    <th>Absent</th>
                    <th>Unique</th>
                    <th>Entropy</th>
                    <th>Change rate</th>
                    <th>Most common</th>
                  </tr>
                </thead>
                <tbody>
                  {columnStats.slice(0, 64).map((column) => (
                    <tr key={column.offset}>
                      <td className="text-text-faint">{column.offset}</td>
                      <td>{column.present_count}</td>
                      <td className={cn(column.absent_count > 0 && "text-status-warn")}>
                        {column.absent_count}
                      </td>
                      <td>{column.unique_values}</td>
                      <td>{column.entropy.toFixed(2)}</td>
                      <td>{column.change_rate.toFixed(2)}</td>
                      <td className="text-text-muted">
                        {column.most_common
                          .slice(0, 3)
                          .map(([value, count]) => `0x${value.toString(16)}=${count}`)
                          .join(" ")}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <div className="p-3">
                <Caveat>
                  A position that is absent from some messages is counted as absent.
                  Missing bytes are never filled with zero, and a field that only
                  exists in some messages is reported as such.
                </Caveat>
              </div>
            </div>
          )}
        </Panel>
      </div>
    </div>
  );
}

/** Re-exported for the message detail drawer used by other pages. */
export { HexViewer };