"use client";


import { useMemo, useState } from "react";

import { TcpStateDiagram } from "@/components/tcp-state-diagram";
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
import {
  completenessTone,
  formatDuration,
  formatTimestamp,
  roleTone,
} from "@/lib/format";
import { useI18n } from "@/lib/i18n";

type TimelineEvent = {
  packet_index: number;
  timestamp: number;
  direction: string;
  source: string;
  destination: string;
  sequence: number | null;
  acknowledgment: number | null;
  flags: number;
  flags_text: string;
  window: number | null;
  payload_length: number;
  options: string | null;
};

export default function SessionsPage() {
  const workspace = useWorkspace();
  const { t } = useI18n();

  const captureId = workspace.captureId;
  const [selected, setSelected] = useState<string | null>(workspace.sessionId);

  const sessions = useAsync(
    () => (captureId ? api.listSessions(captureId) : Promise.resolve(null)),
    [captureId, workspace.revision],
  );

  const timeline = useAsync(
    () => (selected ? api.timeline(selected) : Promise.resolve(null)),
    [selected],
  );

  const diagnostics = useAsync(
    () => (selected ? api.diagnostics(selected) : Promise.resolve(null)),
    [selected],
  );

  // The reconstruction records which packets were retransmissions, out-of-order
  // arrivals, duplicates or zero-window advertisements. We fold those per-stream
  // lists into one packet-index set per kind so the diagram can mark them.
  const anomalies = useMemo(() => {
    const index = {
      retransmissions: [] as number[],
      out_of_order: [] as number[],
      duplicates: [] as number[],
      zero_windows: [] as number[],
    };
    const streams = ((diagnostics.data?.streams ?? []) as Record<string, unknown>[]) ?? [];
    for (const stream of streams) {
      for (const key of Object.keys(index) as Array<keyof typeof index>) {
        for (const record of (stream[key] ?? []) as Record<string, unknown>[]) {
          if (typeof record.packet_index === "number") index[key].push(record.packet_index);
        }
      }
    }
    return index;
  }, [diagnostics.data]);

  if (!captureId) {
    return (
      <div className="p-4">
        <EmptyState
          title={t("No capture selected")}
          description={t("Pick a capture on the Captures page first; TCP sessions are derived from it.")}
        />
      </div>
    );
  }

  const events = ((timeline.data?.events ?? []) as TimelineEvent[]) ?? [];
  const summary = (timeline.data ?? {}) as Record<string, unknown>;

  return (
    <div className="flex h-full flex-col">
      <div className="border-b border-line px-4 py-3">
        <h1 className="text-sm font-semibold tracking-tight text-text">{t("TCP Sessions")}</h1>
        <p className="mt-0.5 max-w-3xl text-2xs leading-relaxed text-text-muted">
          {t(
            "A 4-tuple is not a session. Port reuse and a new SYN split the flow; the splitting policy is recorded on every session so a result can be explained later.",
          )}
        </p>
      </div>

      <div className="grid min-h-0 flex-1 grid-cols-1 gap-3 overflow-hidden p-3 lg:grid-cols-[320px_1fr]">
        <Panel title={t("Sessions")}>
          {sessions.state === "error" ? (
            <ErrorState message={sessions.error ?? ""} onRetry={sessions.reload} />
          ) : sessions.state === "loading" ? (
            <Skeleton rows={8} />
          ) : !sessions.data || sessions.data.items.length === 0 ? (
            <EmptyState
              title={t("No TCP sessions")}
              description={t("This capture has not been analysed, or contains no TCP traffic.")}
            />
          ) : (
            <ul>
              {sessions.data.items.map((item) => {
                const row = item as unknown as {
                  id: string;
                  session_identity: string;
                  client_endpoint: string | null;
                  server_endpoint: string | null;
                  completeness_status: string;
                  role_confidence: string;
                  start_time: number;
                  end_time: number;
                };
                const active = row.id === selected;
                return (
                  <li key={row.id}>
                    <button
                      type="button"
                      onClick={() => {
                        setSelected(row.id);
                        workspace.selectSession(row.id);
                      }}
                      className={`w-full border-b border-line/60 px-3 py-2 text-left transition-colors ${
                        active ? "bg-accent-faint" : "hover:bg-surface-raised"
                      }`}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className={`font-mono text-2xs ${active ? "text-accent" : "text-text"}`}>
                          {row.session_identity}
                        </span>
                        <Badge tone={completenessTone(row.completeness_status)}>
                          {row.completeness_status}
                        </Badge>
                      </div>
                      <p className="mt-0.5 truncate font-mono text-2xs text-text-muted">
                        {row.client_endpoint ?? "?"} → {row.server_endpoint ?? "?"}
                      </p>
                      <p className="mt-0.5 text-2xs text-text-faint">
                        {formatDuration(row.end_time - row.start_time)} ·{" "}
                        {formatTimestamp(row.start_time)}
                      </p>
                    </button>
                  </li>
                );
              })}
            </ul>
          )}
        </Panel>

        <div className="flex min-h-0 flex-col gap-3 overflow-auto">
          {!selected ? (
            <Panel>
              <EmptyState
                title={t("Select a session")}
                description={t(
                  "The timeline shows only what the capture observed. It is not a reconstruction of either TCP stack.",
                )}
              />
            </Panel>
          ) : (
            <>
              <Panel
                title={t("Observed state diagram")}
                actions={
                  <span className="text-2xs text-text-faint">
                    {t("R retransmission · O out of order · Z zero window")}
                  </span>
                }
              >
                <div className="p-2">
                  <TcpStateDiagram events={events} anomalies={anomalies} />
                </div>
              </Panel>

              <Panel
                title={t("Connection state (observed)")}
                actions={
                  <div className="flex gap-1">
                    <Badge tone={summary.saw_syn ? "ok" : "unknown"}>
                      {t("SYN {state}", { state: summary.saw_syn ? t("seen") : t("not seen") })}
                    </Badge>
                    <Badge tone={summary.saw_fin ? "ok" : "unknown"}>
                      {t("FIN {state}", { state: summary.saw_fin ? t("seen") : t("not seen") })}
                    </Badge>
                    <Badge tone={summary.saw_rst ? "bad" : "unknown"}>
                      {t("RST {state}", { state: summary.saw_rst ? t("seen") : t("not seen") })}
                    </Badge>
                  </div>
                }
              >
                <div className="space-y-2 p-3">
                  <p className="text-2xs text-text-muted">
                    <Badge tone={roleTone(String(summary.role_confidence ?? ""))}>
                      {String(summary.role_confidence ?? "unknown")}
                    </Badge>{" "}
                    {String(summary.role_rationale ?? "")}
                  </p>
                  {timeline.data ? (
                    <Caveat>{String(timeline.data.disclaimer ?? "")}</Caveat>
                  ) : null}
                  <div className="overflow-x-auto">
                    <table className="data-table">
                      <thead>
                        <tr>
                          <th>#</th>
                          <th>{t("Time")}</th>
                          <th>{t("Dir")}</th>
                          <th>{t("Source")}</th>
                          <th>{t("Flags")}</th>
                          <th>{t("Seq")}</th>
                          <th>{t("Ack")}</th>
                          <th>{t("Win")}</th>
                          <th>{t("Payload")}</th>
                          <th>{t("Options")}</th>
                        </tr>
                      </thead>
                      <tbody>
                        {events.map((event) => (
                          <tr key={event.packet_index}>
                            <td className="text-text-faint">{event.packet_index}</td>
                            <td className="text-text-muted">
                              {event.timestamp.toFixed(6)}
                            </td>
                            <td>
                              <Badge tone={event.direction === "a2b" ? "info" : "neutral"}>
                                {event.direction}
                              </Badge>
                            </td>
                            <td className="text-text-muted">{event.source}</td>
                            <td
                              className={
                                event.flags_text.includes("RST")
                                  ? "text-status-bad"
                                  : event.flags_text.includes("SYN")
                                    ? "text-status-ok"
                                    : "text-text"
                              }
                            >
                              {event.flags_text}
                            </td>
                            <td className="text-text-faint">
                              {event.sequence ?? "-"}
                            </td>
                            <td className="text-text-faint">
                              {event.acknowledgment ?? "-"}
                            </td>
                            <td className="text-text-faint">{event.window ?? "-"}</td>
                            <td>{event.payload_length}</td>
                            <td className="text-text-faint">{event.options ?? "-"}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </Panel>

              <Panel title={t("Reconstruction diagnostics")}>
                {diagnostics.state === "loading" ? (
                  <Skeleton rows={6} />
                ) : diagnostics.data ? (
                  <DiagnosticsView data={diagnostics.data as Record<string, unknown>} />
                ) : (
                  <EmptyState title={t("No diagnostics")} />
                )}
              </Panel>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

function DiagnosticsView({ data }: { data: Record<string, unknown> }) {
  const { t } = useI18n();
  const explanations = (data.explanations ?? {}) as Record<string, string>;
  const streams = (data.streams ?? []) as Record<string, unknown>[];

  return (
    <div className="space-y-3 p-3">
      {streams.length === 0 && (
        <p className="text-2xs text-text-faint">
          {t("No stream payload was observed for this session.")}
        </p>
      )}
      {streams.map((stream) => {
        const direction = String(stream.direction);
        const conflicts = (stream.conflicts ?? []) as Record<string, unknown>[];
        const holes = (stream.holes ?? []) as { reason: string; start: number; end: number }[];
        const retransmissions = (stream.retransmissions ?? []) as Record<string, unknown>[];
        const outOfOrder = (stream.out_of_order ?? []) as Record<string, unknown>[];
        const duplicates = (stream.duplicates ?? []) as Record<string, unknown>[];
        const zeroWindows = (stream.zero_windows ?? []) as Record<string, unknown>[];

        return (
          <div key={String(stream.stream_id)} className="rounded-sm border border-line p-2.5">
            <div className="mb-2 flex items-center justify-between">
              <span className="font-mono text-2xs text-accent">{direction}</span>
              <span className="text-2xs text-text-faint">
                {t("conflict policy: {policy}", { policy: String(stream.conflict_policy ?? "-") })}
              </span>
            </div>
            <div className="grid grid-cols-2 gap-1.5 md:grid-cols-4">
              <Count label={t("retransmissions")} value={retransmissions.length} note={explanations.retransmission} />
              <Count label={t("exact duplicates")} value={duplicates.length} note={explanations.retransmission} />
              <Count label={t("out of order")} value={outOfOrder.length} note={explanations.out_of_order} />
              <Count label={t("holes")} value={holes.length} note={explanations.hole} tone={holes.length ? "warn" : undefined} />
              <Count label={t("byte conflicts")} value={conflicts.length} note={explanations.conflict} tone={conflicts.length ? "bad" : undefined} />
              <Count label={t("zero window")} value={zeroWindows.length} note={explanations.zero_window} />
            </div>

            {holes.length > 0 && (
              <ul className="mt-2 space-y-0.5 font-mono text-2xs text-status-warn">
                {holes.slice(0, 8).map((hole, index) => (
                  <li key={index}>
                    {t("gap {start}..{end} ({reason})", {
                      start: hole.start,
                      end: hole.end,
                      reason: hole.reason,
                    })}
                  </li>
                ))}
              </ul>
            )}

            {conflicts.length > 0 && (
              <ul className="mt-2 space-y-1 border-t border-line pt-2">
                {conflicts.slice(0, 4).map((conflict, index) => (
                  <li key={index} className="font-mono text-2xs text-status-bad">
                    {t("offsets {start}..{end}: kept {kept} / rejected {rejected} ({resolution})", {
                      start: String(conflict.start_offset),
                      end: String(conflict.end_offset),
                      kept: String(conflict.kept_hex),
                      rejected: String(conflict.rejected_hex),
                      resolution: String(conflict.resolution),
                    })}
                  </li>
                ))}
              </ul>
            )}
          </div>
        );
      })}

      <details className="rounded-sm border border-line p-2">
        <summary className="cursor-pointer text-2xs text-text-muted">
          {t("What these labels mean")}
        </summary>
        <dl className="mt-2 space-y-1.5">
          {Object.entries(explanations).map(([key, text]) => (
            <div key={key}>
              <dt className="font-mono text-2xs text-accent">{key}</dt>
              <dd className="text-2xs text-text-muted">{text}</dd>
            </div>
          ))}
        </dl>
      </details>
    </div>
  );
}

function Count({
  label,
  value,
  note,
  tone,
}: {
  label: string;
  value: number;
  note?: string;
  tone?: "warn" | "bad";
}) {
  return (
    <div className="rounded-sm bg-surface-raised px-2 py-1" title={note}>
      <p className="text-2xs uppercase tracking-wider text-text-faint">{label}</p>
      <p
        className={`font-mono text-xs ${
          tone === "bad"
            ? "text-status-bad"
            : tone === "warn"
              ? "text-status-warn"
              : "text-text"
        }`}
      >
        {value}
      </p>
    </div>
  );
}
