"use client";

import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { useEffect, useMemo, useState } from "react";

import { HexViewer } from "@/components/hex-viewer";
import {
  Badge,
  Caveat,
  EmptyState,
  ErrorState,
  Panel,
  Skeleton,
} from "@/components/ui";
import { useAction, useAsync } from "@/hooks/use-async";
import { useProtocolFilter } from "@/hooks/use-protocol-filter";
import { useWorkspace } from "@/hooks/use-workspace";
import { api } from "@/lib/api";
import { cn, formatNumber } from "@/lib/format";
import { useI18n } from "@/lib/i18n";

const WINDOW = 512;

export default function StreamsPage() {
  const workspace = useWorkspace();
  const params = useSearchParams();
  const { t } = useI18n();
  const protocolFilter = useProtocolFilter();
  const sessionId = params.get("session") ?? workspace.sessionId;
  const [streamId, setStreamId] = useState<string | null>(workspace.streamId);
  const [offset, setOffset] = useState(0);
  const [selectedMessage, setSelectedMessage] = useState<{
    start: number;
    end: number;
    label: string;
  } | null>(null);

  const streams = useAsync(
    () => (sessionId ? api.sessionStreams(sessionId) : Promise.resolve(null)),
    [sessionId, workspace.revision],
  );

  const messages = useAsync(
    () =>
      streamId
        ? api.listMessages(
            (workspace.captureId as string) ?? "",
            `?stream_id=${streamId}&limit=200`,
          )
        : Promise.resolve(null),
    [streamId, workspace.captureId, workspace.revision],
  );

  const bytes = useAsync(
    () =>
      streamId
        ? api.streamBytes(streamId, offset, WINDOW)
        : Promise.resolve(null),
    [streamId, offset],
  );

  const suggestions = useAsync(
    () => (streamId ? api.framingSuggestions(streamId) : Promise.resolve(null)),
    [streamId, workspace.revision],
  );

  const tls = useAsync(
    () => (streamId ? api.tlsFingerprints(streamId) : Promise.resolve(null)),
    [streamId, workspace.revision],
  );

  const apply = useAction();

  // Protocol labels present in this session, and the ones the analyst chose to
  // hide. Hiding removes the stream from the selector; it never deletes data.
  const protocolLabels = useMemo(() => {
    const names = new Set<string>();
    for (const item of streams.data ?? []) names.add(item.protocol_label);
    return [...names].sort();
  }, [streams.data]);

  const visibleStreams = useMemo(
    () => (streams.data ?? []).filter((s) => !protocolFilter.isHidden(s.protocol_label)),
    [streams.data, protocolFilter],
  );

  useEffect(() => {
    if (visibleStreams.length === 0) return;
    if (!visibleStreams.some((s) => s.id === streamId)) {
      const first = visibleStreams[0];
      setStreamId(first.id);
      workspace.selectStream(first.id);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [visibleStreams, streamId]);

  const stream = streams.data?.find((s) => s.id === streamId) ?? null;
  const holes = useMemo(
    () =>
      ((bytes.data?.holes ?? []) as { start: number; end: number; length: number; reason: string }[]) ?? [],
    [bytes.data],
  );

  return (
    <div className="flex h-full flex-col">
      <div className="border-b border-line px-4 py-3">
        <h1 className="text-sm font-semibold tracking-tight text-text">{t("Stream Explorer")}</h1>
        <p className="mt-0.5 max-w-3xl text-2xs leading-relaxed text-text-muted">
          {t(
            "The reconstructed byte stream, its coverage map and the packets that produced each byte. Missing ranges are shown as gaps and are never filled with zeros.",
          )}
        </p>
      </div>

      <div className="flex min-h-0 flex-1 flex-col overflow-hidden">
        {sessionId ? null : (
          <div className="p-4">
            <EmptyState
              title={t("No TCP session selected")}
              description={t(
                "The Stream Explorer works on one reconstructed direction of one TCP session. Open TCP Sessions to choose the connection, or import and analyse a capture first.",
              )}
              action={
                <Link href="/sessions" className="btn btn-primary">
                  {t("Go to TCP Sessions")}
                </Link>
              }
            />
          </div>
        )}
        <div className="border-b border-line bg-surface px-3 py-1.5">
          <div className="flex flex-wrap items-center gap-2">
            {protocolLabels.map((label) => {
              const hidden = protocolFilter.isHidden(label);
              return (
                <button
                  key={label}
                  type="button"
                  onClick={() => protocolFilter.toggle(label)}
                  aria-pressed={!hidden}
                  title={hidden ? t("Show this protocol") : t("Hide this protocol")}
                  className={cn(
                    "tag",
                    hidden
                      ? "border-line text-text-faint line-through opacity-60"
                      : "border-line-strong text-text-muted hover:border-accent-dim hover:text-text",
                  )}
                >
                  <span className="font-mono">{label}</span>
                </button>
              );
            })}
            {protocolLabels.length > 0 && (
              <span className="text-2xs uppercase tracking-wider text-text-faint">
                {t("Protocols")}
              </span>
            )}
            {protocolLabels.some((label) => protocolFilter.isHidden(label)) && (
              <button type="button" className="btn" onClick={protocolFilter.showAll}>
                {t("Show all")}
              </button>
            )}
          </div>
          <div className="mt-1.5 flex flex-wrap items-center gap-2">
            {visibleStreams.map((s) => (
              <button
                key={s.id}
                type="button"
                onClick={() => {
                  setStreamId(s.id);
                  setOffset(0);
                  workspace.selectStream(s.id);
                }}
                className={cn("btn", s.id === streamId && "btn-primary")}
              >
                {s.direction} · {s.local_endpoint} → {s.remote_endpoint}
                <span className="text-text-faint">
                  {t("{present}/{total} B", {
                    present: formatNumber(s.present_bytes),
                    total: formatNumber(s.stream_length),
                  })}
                </span>
              </button>
            ))}
            {streams.data && visibleStreams.length === 0 && (
              <span className="text-2xs text-text-faint">
                {t("All streams are hidden by the protocol filter.")}
              </span>
            )}
            {stream && (
              <Badge tone={stream.protocol_label === "unknown_binary" ? "unknown" : "info"}>
                {t("protocol: {label} ({confidence})", {
                  label: stream.protocol_label,
                  confidence: stream.protocol_confidence.toFixed(2),
                })}
              </Badge>
            )}
            <span className="ml-auto flex items-center gap-1">
              <button type="button" className="btn" onClick={() => setOffset(Math.max(0, offset - WINDOW))}>
                {t("← prev")}
              </button>
              <span className="font-mono text-2xs text-text-muted">
                {t("offset {start} … {end}", {
                  start: formatNumber(offset),
                  end: formatNumber(offset + WINDOW),
                })}
              </span>
              <button
                type="button"
                className="btn"
                onClick={() => setOffset(offset + WINDOW)}
                disabled={stream ? offset + WINDOW >= stream.stream_length : true}
              >
                {t("next →")}
              </button>
            </span>
          </div>
        </div>

        <div className="grid min-h-0 flex-1 grid-cols-1 gap-3 overflow-auto p-3 lg:grid-cols-[1fr_360px]">
          <div className="flex min-h-0 flex-col gap-3">
            <Panel
              title={t("Reconstructed bytes")}
              actions={
                selectedMessage ? (
                  <Badge tone="info">
                    {t("highlighting message {label}", { label: selectedMessage.label })}
                  </Badge>
                ) : (
                  <span className="text-2xs text-text-faint">
                    {t("select a message below")}
                  </span>
                )
              }
            >
              {bytes.state === "error" ? (
                <ErrorState message={bytes.error ?? ""} onRetry={bytes.reload} />
              ) : bytes.state === "loading" ? (
                <Skeleton rows={12} />
              ) : bytes.data ? (
                <HexViewer
                  lines={bytes.data.lines}
                  holes={holes}
                  highlightRange={
                    selectedMessage
                      ? { start: selectedMessage.start, end: selectedMessage.end }
                      : null
                  }
                />
              ) : (
                <EmptyState title={t("No stream selected")} />
              )}
            </Panel>

            {holes.length > 0 && (
              <Panel title={t("Coverage gaps")}>
                <div className="space-y-1.5 p-3">
                  {holes.map((hole, index) => (
                    <div key={index} className="flex items-center justify-between font-mono text-2xs">
                      <span className="text-status-warn">
                        {t("{start} … {end} ({length} bytes)", {
                          start: hole.start,
                          end: hole.end,
                          length: hole.length,
                        })}
                      </span>
                      <span className="text-text-faint">{hole.reason}</span>
                    </div>
                  ))}
                  <Caveat tone="warn">
                    {t(
                      "These bytes were never captured. They are not recoverable from this file, and nothing in the analysis substitutes a guess for them.",
                    )}
                  </Caveat>
                </div>
              </Panel>
            )}

            {tls.state === "ready" &&
              ((tls.data?.handshakes ?? []) as Record<string, unknown>[]).length > 0 && (
                <Panel title={t("TLS fingerprints (JA3 / JA3S)")}>
                  <div className="space-y-2 p-3">
                    {(
                      (tls.data?.handshakes ?? []) as Record<string, unknown>[]
                    ).map((handshake, index) => (
                      <div
                        key={index}
                        className="space-y-1 rounded-sm border border-line bg-surface-raised p-2 font-mono text-2xs"
                      >
                        <div className="flex flex-wrap items-center gap-2">
                          <Badge tone="info">{String(handshake.kind)}</Badge>
                          {/* A truncated handshake is reported as such and never hashed. */}
                          <Badge tone={handshake.reliable ? "ok" : "warn"}>
                            {handshake.reliable ? t("reliable") : t("unreliable")}
                          </Badge>
                          <span className="text-text">
                            {String(handshake.md5 ?? t("no hash computed"))}
                          </span>
                          <span className="text-text-faint">
                            {String(handshake.version ?? "")}
                          </span>
                        </div>
                        <div className="break-all text-text-muted">
                          {String(handshake.raw ?? "")}
                        </div>
                        <div className="flex flex-wrap gap-3 text-text-faint">
                          {handshake.sni ? (
                            <span>{t("sni: {value}", { value: String(handshake.sni) })}</span>
                          ) : null}
                          {Array.isArray(handshake.alpn) && handshake.alpn.length ? (
                            <span>
                              {t("alpn: {value}", {
                                value: (handshake.alpn as string[]).join(", "),
                              })}
                            </span>
                          ) : null}
                          {Array.isArray(handshake.supported_groups) &&
                          handshake.supported_groups.length ? (
                            <span>
                              {t("groups: {value}", {
                                value: (handshake.supported_groups as number[])
                                  .map((g) => `0x${g.toString(16)}`)
                                  .join(", "),
                              })}
                            </span>
                          ) : null}
                        </div>
                        {!handshake.reliable ? (
                          <p className="text-status-warn">
                            {String(handshake.reason_if_unreliable ?? "")}
                          </p>
                        ) : null}
                        {handshake.match ? (
                          <p className="text-text-muted">
                            {t(String((handshake.match as { interpretation?: string }).interpretation ?? ""))}
                          </p>
                        ) : null}
                      </div>
                    ))}
                    <Caveat>
                      {t(String(tls.data?.interpretation_note ?? ""))}
                    </Caveat>
                  </div>
                </Panel>
              )}

            <Panel title={t("Framing candidates for this stream")}>
              {suggestions.state === "loading" ? (
                <Skeleton rows={4} />
              ) : suggestions.data ? (
                <div className="space-y-1.5 p-3">
                  {suggestions.data.suggestions.slice(0, 6).map((s, index) => (
                    <div
                      key={index}
                      className="flex flex-wrap items-center gap-2 rounded-sm border border-line bg-surface-raised px-2.5 py-1.5"
                    >
                      <Badge tone={index === 0 ? "ok" : "neutral"}>
                        {t("score {value}", { value: s.score.toFixed(3) })}
                      </Badge>
                      <span className="font-mono text-2xs text-text">
                        {s.method} {JSON.stringify(s.config)}
                      </span>
                      <span className="text-2xs text-text-faint">
                        {JSON.stringify(s.evidence)}
                      </span>
                      {index === 0 && stream && (
                        <button
                          type="button"
                          className="btn btn-primary ml-auto"
                          disabled={apply.pending}
                          onClick={() =>
                            void apply
                              .run(
                                () =>
                                  api.analyze(workspace.captureId as string, {
                                    framing: { method: s.method, config: s.config },
                                  }),
                                t("Framing rule applied; messages regenerated."),
                              )
                              .then(() => workspace.invalidate())
                          }
                        >
                          {t("Apply and re-frame")}
                        </button>
                      )}
                    </div>
                  ))}
                  <Caveat>{t(String(suggestions.data.disclaimer))}</Caveat>
                </div>
              ) : (
                <EmptyState title={t("No candidates")} />
              )}
            </Panel>
          </div>

          <div className="flex min-h-0 flex-col gap-3">
            <Panel title={t("Framed messages")}>
              {messages.state === "loading" ? (
                <Skeleton rows={10} />
              ) : messages.data && messages.data.items.length > 0 ? (
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>#</th>
                      <th>{t("Range")}</th>
                      <th>{t("Len")}</th>
                      <th>{t("Declared")}</th>
                      <th>{t("State")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {messages.data.items.map((item) => {
                      const row = item as unknown as {
                        id: string;
                        index_in_stream: number;
                        start_offset: number;
                        end_offset: number;
                        present_length: number;
                        declared_length: number | null;
                        complete: boolean;
                        packet_references: { packet_index: number }[];
                      };
                      const active =
                        selectedMessage?.start === row.start_offset &&
                        selectedMessage?.end === row.end_offset;
                      return (
                        <tr
                          key={row.id}
                          onClick={() => {
                            setSelectedMessage({
                              start: row.start_offset,
                              end: row.end_offset,
                              label: `#${row.index_in_stream}`,
                            });
                            workspace.selectMessage(row.id);
                          }}
                          className={cn("cursor-pointer", active && "bg-accent-faint")}
                        >
                          <td className="text-text-faint">{row.index_in_stream}</td>
                          <td className="text-text-muted">
                            {row.start_offset}…{row.end_offset}
                          </td>
                          <td>{row.present_length}</td>
                          <td className="text-text-muted">{row.declared_length ?? "-"}</td>
                          <td>
                            <Badge tone={row.complete ? "ok" : "warn"}>
                              {row.complete ? t("complete") : t("partial")}
                            </Badge>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              ) : (
                <EmptyState
                  title={t("No messages framed")}
                  description={t("Apply a framing rule to split the byte stream into messages.")}
                />
              )}
            </Panel>

            <Panel title={t("Packets behind the current window")}>
              {bytes.data?.packet_references?.length ? (
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>{t("Packet")}</th>
                      <th>{t("Stream offsets")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(bytes.data.packet_references as { packet_index: number; start_offset: number; end_offset: number }[]).map(
                      (ref, index) => (
                        <tr key={index}>
                          <td className="text-accent">#{ref.packet_index}</td>
                          <td className="text-text-muted">
                            {ref.start_offset}…{ref.end_offset}
                          </td>
                        </tr>
                      ),
                    )}
                  </tbody>
                </table>
              ) : (
                <EmptyState
                  title={t("No packets in this window")}
                  description={t("Bytes with no packet behind them are holes.")}
                />
              )}
            </Panel>
          </div>
        </div>
      </div>
    </div>
  );
}