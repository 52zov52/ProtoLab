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
import { useWorkspace } from "@/hooks/use-workspace";
import { api } from "@/lib/api";
import { cn, formatNumber } from "@/lib/format";

const WINDOW = 512;

export default function StreamsPage() {
  const workspace = useWorkspace();
  const params = useSearchParams();
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

  useEffect(() => {
    if (streams.data && streams.data.length > 0 && !streamId) {
      const first = streams.data[0];
      setStreamId(first.id);
      workspace.selectStream(first.id);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [streams.data]);

  const stream = streams.data?.find((s) => s.id === streamId) ?? null;
  const holes = useMemo(
    () =>
      ((bytes.data?.holes ?? []) as { start: number; end: number; length: number; reason: string }[]) ?? [],
    [bytes.data],
  );

  return (
    <div className="flex h-full flex-col">
      <div className="border-b border-line px-4 py-3">
        <h1 className="text-sm font-semibold tracking-tight text-text">Stream Explorer</h1>
        <p className="mt-0.5 max-w-3xl text-2xs leading-relaxed text-text-muted">
          The reconstructed byte stream, its coverage map and the packets that produced
          each byte. Missing ranges are shown as gaps and are never filled with zeros.
        </p>
      </div>

      <div className="flex min-h-0 flex-1 flex-col overflow-hidden">
        {sessionId ? null : (
          <div className="p-4">
            <EmptyState
              title="No TCP session selected"
              description="The Stream Explorer works on one reconstructed direction of one TCP session. Open TCP Sessions to choose the connection, or import and analyse a capture first."
              action={
                <Link href="/sessions" className="btn btn-primary">
                  Go to TCP Sessions
                </Link>
              }
            />
          </div>
        )}
        <div className="flex flex-wrap items-center gap-2 border-b border-line bg-surface px-3 py-1.5">
          {(streams.data ?? []).map((s) => (
            <button
              key={s.id}
              type="button"
              onClick={() => {
                setStreamId(s.id);
                setOffset(0);
                workspace.selectStream(s.id);
              }}
              className={cn(
                "btn",
                s.id === streamId && "btn-primary",
              )}
            >
              {s.direction} · {s.local_endpoint} → {s.remote_endpoint}
              <span className="text-text-faint">
                {formatNumber(s.present_bytes)}/{formatNumber(s.stream_length)} B
              </span>
            </button>
          ))}
          {stream && (
            <Badge tone={stream.protocol_label === "unknown_binary" ? "unknown" : "info"}>
              protocol: {stream.protocol_label} ({stream.protocol_confidence.toFixed(2)})
            </Badge>
          )}
          <span className="ml-auto flex items-center gap-1">
            <button type="button" className="btn" onClick={() => setOffset(Math.max(0, offset - WINDOW))}>
              ← prev
            </button>
            <span className="font-mono text-2xs text-text-muted">
              offset {formatNumber(offset)} … {formatNumber(offset + WINDOW)}
            </span>
            <button
              type="button"
              className="btn"
              onClick={() => setOffset(offset + WINDOW)}
              disabled={stream ? offset + WINDOW >= stream.stream_length : true}
            >
              next →
            </button>
          </span>
        </div>

        <div className="grid min-h-0 flex-1 grid-cols-1 gap-3 overflow-auto p-3 lg:grid-cols-[1fr_360px]">
          <div className="flex min-h-0 flex-col gap-3">
            <Panel
              title="Reconstructed bytes"
              actions={
                selectedMessage ? (
                  <Badge tone="info">
                    highlighting message {selectedMessage.label}
                  </Badge>
                ) : (
                  <span className="text-2xs text-text-faint">select a message below</span>
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
                <EmptyState title="No stream selected" />
              )}
            </Panel>

            {holes.length > 0 && (
              <Panel title="Coverage gaps">
                <div className="space-y-1.5 p-3">
                  {holes.map((hole, index) => (
                    <div key={index} className="flex items-center justify-between font-mono text-2xs">
                      <span className="text-status-warn">
                        {hole.start} … {hole.end} ({hole.length} bytes)
                      </span>
                      <span className="text-text-faint">{hole.reason}</span>
                    </div>
                  ))}
                  <Caveat tone="warn">
                    These bytes were never captured. They are not recoverable from this
                    file, and nothing in the analysis substitutes a guess for them.
                  </Caveat>
                </div>
              </Panel>
            )}

            {tls.state === "ready" &&
              ((tls.data?.handshakes ?? []) as Record<string, unknown>[]).length > 0 && (
                <Panel title="TLS fingerprints (JA3 / JA3S)">
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
                            {handshake.reliable ? "reliable" : "unreliable"}
                          </Badge>
                          <span className="text-text">
                            {String(handshake.md5 ?? "no hash computed")}
                          </span>
                          <span className="text-text-faint">
                            {String(handshake.version ?? "")}
                          </span>
                        </div>
                        <div className="break-all text-text-muted">
                          {String(handshake.raw ?? "")}
                        </div>
                        <div className="flex flex-wrap gap-3 text-text-faint">
                          {handshake.sni ? <span>sni: {String(handshake.sni)}</span> : null}
                          {Array.isArray(handshake.alpn) && handshake.alpn.length ? (
                            <span>alpn: {handshake.alpn.join(", ")}</span>
                          ) : null}
                          {Array.isArray(handshake.supported_groups) &&
                          handshake.supported_groups.length ? (
                            <span>
                              groups:{" "}
                              {(handshake.supported_groups as number[])
                                .map((g) => `0x${g.toString(16)}`)
                                .join(", ")}
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
                            {String((handshake.match as { interpretation?: string }).interpretation ?? "")}
                          </p>
                        ) : null}
                      </div>
                    ))}
                    <Caveat>
                      {String(tls.data?.interpretation_note ?? "")}
                    </Caveat>
                  </div>
                </Panel>
              )}

            <Panel title="Framing candidates for this stream">
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
                        score {s.score.toFixed(3)}
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
                                "Framing rule applied; messages regenerated.",
                              )
                              .then(() => workspace.invalidate())
                          }
                        >
                          Apply and re-frame
                        </button>
                      )}
                    </div>
                  ))}
                  <Caveat>{suggestions.data.disclaimer}</Caveat>
                </div>
              ) : (
                <EmptyState title="No candidates" />
              )}
            </Panel>
          </div>

          <div className="flex min-h-0 flex-col gap-3">
            <Panel title="Framed messages">
              {messages.state === "loading" ? (
                <Skeleton rows={10} />
              ) : messages.data && messages.data.items.length > 0 ? (
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>#</th>
                      <th>Range</th>
                      <th>Len</th>
                      <th>Declared</th>
                      <th>State</th>
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
                              {row.complete ? "complete" : "partial"}
                            </Badge>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              ) : (
                <EmptyState
                  title="No messages framed"
                  description="Apply a framing rule to split the byte stream into messages."
                />
              )}
            </Panel>

            <Panel title="Packets behind the current window">
              {bytes.data?.packet_references?.length ? (
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Packet</th>
                      <th>Stream offsets</th>
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
                  title="No packets in this window"
                  description="Bytes with no packet behind them are holes."
                />
              )}
            </Panel>
          </div>
        </div>
      </div>
    </div>
  );
}