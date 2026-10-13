"use client";

import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { useState } from "react";

import { HexComparison, HexViewer } from "@/components/hex-viewer";
import { MessageTable } from "@/components/message-table";
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
import { columnClassLegend, columnClassMeta } from "@/lib/column-classes";
import { cn } from "@/lib/format";
import { useI18n } from "@/lib/i18n";

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
  const { t } = useI18n();
  const sessionId = params.get("session") ?? workspace.sessionId;
  const captureId = workspace.captureId;

  const [streamId, setStreamId] = useState<string | null>(workspace.streamId);
  const [selected, setSelected] = useState<string[]>([]);

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
  // Direction is selected by choosing the stream above: each stream is one
  // direction of the session, so filtering by direction again would be
  // redundant. Messages shown are exactly the selected stream's messages.
  const filtered = rows;

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
          title={t("No capture selected")}
          description={t(
            "The Protocol Workbench compares framed messages from a reconstructed stream. Select an analysed capture and a session, then apply a framing rule to the stream.",
          )}
          action={
            <Link href="/captures" className="btn btn-primary">
              {t("Go to Captures")}
            </Link>
          }
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
    monotonic_ratio: number;
    zero_count: number;
    most_common: [number, number][];
    classification: string;
    classification_rationale: string;
  }[];

  return (
    <div className="flex h-full flex-col">
      <div className="flex shrink-0 items-start justify-between gap-4 border-b border-line px-4 py-3">
        <div>
          <h1 className="text-sm font-semibold tracking-tight text-text">{t("Protocol Workbench")}</h1>
          <p className="mt-0.5 max-w-3xl text-2xs leading-relaxed text-text-muted">
            {t(
              "Compare binary messages side by side, read the per-offset statistics and see which field candidates the data actually supports.",
            )}
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
          <span className="text-2xs text-text-faint">
            {t("one stream per direction")}
          </span>
        </div>
      </div>

      <div className="grid min-h-0 flex-1 grid-cols-1 gap-3 overflow-auto p-3 xl:grid-cols-2">
        <Panel
          title={t("Messages (select 2–6 to compare)")}
          actions={
            selected.length > 0 ? (
              <button type="button" className="btn" onClick={() => setSelected([])}>
                {t("clear")}
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
              title={t("No framed messages")}
              description={t("Choose a framing rule on the Stream Explorer first.")}
            />
          ) : (
            <MessageTable
              items={filtered}
              selected={selected}
              onToggle={toggle}
            />
          )}
        </Panel>

        <Panel title={t("Per-offset alignment")}>
          {selected.length < 2 ? (
            <EmptyState
              title={t("Select at least two messages")}
              description={t(
                "Alignment is positional: a byte at offset N in one message is compared with offset N in another. Where a message is shorter, the position is shown as absent, never as zero.",
              )}
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
            <EmptyState title={t("No comparison")} />
          )}
        </Panel>

        <Panel title={t("Field candidates inferred from the bytes")}>
          {stats.state === "loading" ? (
            <Skeleton rows={8} />
          ) : candidates.length === 0 ? (
            <EmptyState
              title={t("No candidates")}
              description={t("Insufficient messages or no structure detected yet.")}
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
                    {t("supports {supports} · contradicts {contradicts}", {
                      supports: candidate.support_count,
                      contradicts: candidate.contradiction_count,
                    })}
                  </p>
                </div>
              ))}
              <Caveat tone="warn">
                {t(
                  "These are hypotheses generated from observed bytes. A candidate name is a label, not a claim: nothing here proves what a field",
                )}{" "}
                <em>{t("means")}</em>.
              </Caveat>
            </div>
          )}
        </Panel>

        <Panel title={t("Column statistics")}>
          {columnStats.length === 0 ? (
            <EmptyState title={t("No statistics")} />
          ) : (
            <div className="overflow-x-auto">
              <div className="flex flex-col gap-2 border-b border-line p-3">
                <div className="flex flex-wrap items-center gap-3 text-2xs text-text-faint">
                  {columnClassLegend().map((meta) => (
                    <span key={meta.label} className="flex items-center gap-1" title={t(meta.description)}>
                      <span
                        className="inline-block h-3 w-3 rounded-sm"
                        style={{ background: meta.color }}
                      />
                      {t(meta.label)}
                    </span>
                  ))}
                </div>
                <div className="flex items-end gap-px" aria-label={t("Byte class per offset")}>
                  {columnStats.slice(0, 64).map((column) => {
                    const meta = columnClassMeta(column.classification);
                    return (
                      <span
                        key={column.offset}
                        className="w-3 rounded-sm"
                        style={{ background: meta.color, height: 18 }}
                        title={t("offset {offset}: {label}", {
                          offset: column.offset,
                          label: t(meta.label),
                        })}
                      />
                    );
                  })}
                </div>
              </div>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>{t("Offset")}</th>
                    <th>{t("Class")}</th>
                    <th>{t("Present")}</th>
                    <th>{t("Absent")}</th>
                    <th>{t("Unique")}</th>
                    <th>{t("Entropy")}</th>
                    <th>{t("Change rate")}</th>
                    <th>{t("Most common")}</th>
                  </tr>
                </thead>
                <tbody>
                  {columnStats.slice(0, 64).map((column) => {
                    const meta = columnClassMeta(column.classification);
                    return (
                      <tr key={column.offset}>
                        <td className="text-text-faint">{column.offset}</td>
                        <td>
                          <span
                            className="flex items-center gap-1.5"
                            title={column.classification_rationale}
                          >
                            <span
                              className="inline-block h-3 w-3 rounded-sm"
                              style={{ background: meta.color }}
                            />
                            <Badge tone={meta.tone}>{t(meta.label)}</Badge>
                          </span>
                        </td>
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
                    );
                  })}
                </tbody>
              </table>
              <div className="p-3">
                <Caveat>
                  {t(
                    "A position that is absent from some messages is counted as absent. Missing bytes are never filled with zero, and a field that only exists in some messages is reported as such.",
                  )}
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