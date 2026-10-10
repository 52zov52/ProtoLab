"use client";

import { useSearchParams } from "next/navigation";
import { useEffect, useState } from "react";
import { Play, Trash2, Upload } from "lucide-react";

import { Badge, Caveat, EmptyState, ErrorState, Panel, Skeleton } from "@/components/ui";
import { useAction, useAsync } from "@/hooks/use-async";
import { useWorkspace } from "@/hooks/use-workspace";
import { api } from "@/lib/api";
import { cn, formatBytes, formatTimestamp } from "@/lib/format";

export default function CapturesPage() {
  const workspace = useWorkspace();
  const params = useSearchParams();
  const projectId = params.get("project") ?? workspace.projectId;
  const [busy, setBusy] = useState(false);
  const [importError, setImportError] = useState<string | null>(null);

  const metrics = useAsync(
    () => (projectId ? api.metrics(projectId) : Promise.resolve(null)),
    [projectId, workspace.revision],
  );

  // The capture list. Without it an analyst who imports two captures can only
  // ever see the last one they imported, and cannot switch between them.
  const listed = useAsync(
    () => (projectId ? api.projectCaptures(projectId) : Promise.resolve([])),
    [projectId, workspace.revision],
  );

  // Select the first capture automatically so a deep link into a project lands
  // on something useful rather than an empty panel.
  useEffect(() => {
    const rows = listed.data;
    if (!workspace.captureId && rows && rows.length > 0) {
      workspace.selectCapture(rows[0].id);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [listed.data]);

  const sessions = useAsync(
    () =>
      workspace.captureId ? api.listSessions(workspace.captureId) : Promise.resolve(null),
    [workspace.captureId, workspace.revision],
  );

  const capture = useAsync(
    () =>
      workspace.captureId ? api.getCapture(workspace.captureId) : Promise.resolve(null),
    [workspace.captureId, workspace.revision],
  );

  const analyze = useAction();
  const remove = useAction();

  const doImport = async (file: File) => {
    if (!projectId) return;
    setBusy(true);
    setImportError(null);
    try {
      const imported = await api.importCapture(projectId, file, file.name);
      workspace.selectCapture(imported.id);
      workspace.invalidate();
    } catch (error) {
      setImportError(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(false);
    }
  };

  if (!projectId) {
    return (
      <div className="p-4">
        <EmptyState
          title="No project selected"
          description="Open a project on the Overview page first."
        />
      </div>
    );
  }

  const stats = (capture.data?.stats ?? {}) as Record<string, unknown>;
  const readerDiagnostics = (stats.reader_diagnostics ?? {}) as {
    errors?: string[];
    warnings?: string[];
  };

  return (
    <div className="flex h-full flex-col">
      <div className="flex shrink-0 items-start justify-between gap-4 border-b border-line px-4 py-3">
        <div>
          <h1 className="text-sm font-semibold tracking-tight text-text">Captures</h1>
          <p className="mt-0.5 max-w-3xl text-2xs leading-relaxed text-text-muted">
            Imported files are immutable. Analysis reads them and writes derived artefacts
            alongside; the original bytes are never rewritten.
          </p>
        </div>
        <label className="btn btn-primary cursor-pointer">
          <Upload className="h-3 w-3" aria-hidden />
          {busy ? "Importing…" : "Import PCAP"}
          <input
            type="file"
            accept=".pcap,.pcapng,.cap"
            className="hidden"
            onChange={(event) => {
              const file = event.target.files?.[0];
              if (file) void doImport(file);
              event.target.value = "";
            }}
          />
        </label>
      </div>

      <div className="min-h-0 flex-1 overflow-auto p-4">
        {importError && (
          <div className="mb-3 rounded-sm border border-status-bad/40 bg-status-bad/5 p-2 text-2xs text-status-bad">
            {importError}
          </div>
        )}

        <div className="grid gap-4 lg:grid-cols-3">
          <div className="space-y-4 lg:col-span-1">
            <Panel title="Project totals">
              {metrics.state === "loading" ? (
                <Skeleton rows={5} />
              ) : metrics.data ? (
                <dl className="space-y-1 p-3 font-mono text-2xs">
                  <Line label="captures" value={metrics.data.captures} />
                  <Line label="packets" value={metrics.data.packets} />
                  <Line label="tcp sessions" value={metrics.data.tcp_sessions} />
                  <Line label="messages" value={metrics.data.messages} />
                  <Line label="bytes stored" value={formatBytes(metrics.data.bytes_stored)} />
                </dl>
              ) : null}
            </Panel>

            <Panel title="Captures in this project">
              {listed.state === "loading" ? (
                <Skeleton rows={3} />
              ) : listed.state === "error" ? (
                <ErrorState message={listed.error ?? ""} onRetry={listed.reload} />
              ) : (listed.data ?? []).length === 0 ? (
                <EmptyState
                  title="No captures yet"
                  description="Import a PCAP or PCAPNG file to begin. The original bytes are stored immutably and hashed."
                />
              ) : (
                <ul className="divide-y divide-line/60">
                  {(listed.data ?? []).map((row) => (
                    <li key={row.id}>
                      <button
                        type="button"
                        className={cn(
                          "flex w-full items-center justify-between gap-2 px-3 py-2 text-left transition-colors hover:bg-surface-raised",
                          row.id === workspace.captureId && "bg-accent-faint",
                        )}
                        onClick={() => {
                          workspace.selectCapture(row.id);
                          workspace.invalidate();
                        }}
                      >
                        <span className="min-w-0">
                          <span className="block truncate text-2xs font-medium text-text">
                            {row.name}
                          </span>
                          <span className="block font-mono text-2xs text-text-faint">
                            {row.format} · {formatBytes(row.file_size)} ·{" "}
                            {row.sha256.slice(0, 12)}…
                          </span>
                        </span>
                        <Badge
                          tone={
                            row.analysis_status === "completed"
                              ? "ok"
                              : row.analysis_status === "failed"
                                ? "bad"
                                : "neutral"
                          }
                        >
                          {row.analysis_status}
                        </Badge>
                      </button>
                    </li>
                  ))}
                </ul>
              )}
            </Panel>

            <Panel title="Selected capture">
              {!workspace.captureId ? (
                <EmptyState title="No capture selected" description="Import a file to begin." />
              ) : capture.state === "loading" ? (
                <Skeleton rows={6} />
              ) : capture.data ? (
                <div className="space-y-2 p-3">
                  <dl className="space-y-1 font-mono text-2xs">
                    <Line label="name" value={capture.data.name} />
                    <Line label="format" value={capture.data.format} />
                    <Line label="size" value={formatBytes(capture.data.file_size)} />
                    <Line label="sha256" value={`${capture.data.sha256.slice(0, 24)}…`} />
                    <Line
                      label="imported"
                      value={formatTimestamp(Date.parse(capture.data.imported_at) / 1000)}
                    />
                    <Line label="status" value={capture.data.analysis_status} />
                  </dl>
                  <div className="flex flex-wrap gap-2 pt-1">
                    <button
                      type="button"
                      className="btn btn-primary"
                      disabled={analyze.pending}
                      onClick={() =>
                        void analyze.run(
                          () => api.analyze(capture.data!.id, {}),
                          "Analysis finished.",
                        ).then((result) => {
                          if (result) workspace.invalidate();
                        })
                      }
                    >
                      <Play className="h-3 w-3" aria-hidden />
                      {analyze.pending ? "Analysing…" : "Run analysis"}
                    </button>
                    <button
                      type="button"
                      className="btn"
                      disabled={analyze.pending}
                      onClick={() =>
                        void analyze
                          .run(() => api.analyzeAsync(capture.data!.id), "Queued as a background job.")
                          .then((result) => {
                            if (result) workspace.invalidate();
                          })
                      }
                    >
                      Queue in background
                    </button>
                    <button
                      type="button"
                      className="btn btn-danger"
                      disabled={remove.pending}
                      onClick={() => {
                        if (
                          !window.confirm(
                            `Delete "${capture.data!.name}" and everything derived from it?\n\n` +
                              "This cannot be undone.",
                          )
                        ) {
                          return;
                        }
                        void remove
                          .run(() => api.deleteCapture(capture.data!.id), "Capture deleted.")
                          .then((ok) => {
                            if (ok) {
                              workspace.selectCapture(null);
                              workspace.invalidate();
                            }
                          });
                      }}
                    >
                      <Trash2 className="h-3 w-3" aria-hidden />
                      Delete
                    </button>
                  </div>
                  {analyze.notice && (
                    <p className="text-2xs text-status-ok">{analyze.notice}</p>
                  )}
                  {(analyze.error || remove.error) && (
                    <p className="text-2xs text-status-bad">{analyze.error ?? remove.error}</p>
                  )}
                </div>
              ) : null}
            </Panel>
          </div>

          <div className="space-y-4 lg:col-span-2">
            <Panel title="Analysis result">
              {Object.keys(stats).length === 0 ? (
                <EmptyState
                  title="Not analysed yet"
                  description="Run the analysis to index packets, split TCP sessions and reconstruct the byte streams."
                />
              ) : (
                <div className="space-y-3 p-3">
                  <div className="grid grid-cols-2 gap-2 md:grid-cols-4">
                    <Stat label="sessions" value={String(stats.sessions ?? 0)} />
                    <Stat label="streams" value={String(stats.streams ?? 0)} />
                    <Stat label="messages" value={String(stats.messages ?? 0)} />
                    <Stat
                      label="sessions with problems"
                      value={String(stats.sessions_with_problems ?? 0)}
                      tone={Number(stats.sessions_with_problems ?? 0) > 0 ? "warn" : "ok"}
                    />
                  </div>

                  <div>
                    <p className="mb-1 text-2xs uppercase tracking-wider text-text-faint">
                      Reader diagnostics
                    </p>
                    {readerDiagnostics.errors?.length ? (
                      <ul className="space-y-1">
                        {readerDiagnostics.errors.map((error, index) => (
                          <li key={index} className="font-mono text-2xs text-status-bad">
                            {error}
                          </li>
                        ))}
                      </ul>
                    ) : (
                      <p className="text-2xs text-status-ok">No read errors.</p>
                    )}
                    {readerDiagnostics.warnings?.map((warning, index) => (
                      <p key={index} className="mt-1 font-mono text-2xs text-status-warn">
                        {warning}
                      </p>
                    ))}
                  </div>

                  {stats.options ? (
                    <div>
                      <p className="mb-1 text-2xs uppercase tracking-wider text-text-faint">
                        Analysis options (recorded for reproducibility)
                      </p>
                      <pre className="overflow-x-auto rounded-sm border border-line bg-surface-sunken p-2 font-mono text-2xs">
                        {JSON.stringify(stats.options, null, 2)}
                      </pre>
                    </div>
                  ) : null}

                  <Caveat>
                    These counts come from the options recorded above. Re-running with a
                    different framing rule or conflict policy produces a different set of
                    rows from the same bytes.
                  </Caveat>
                </div>
              )}
            </Panel>

            <Panel title="TCP sessions in this capture">
              {sessions.state === "error" ? (
                <ErrorState message={sessions.error ?? ""} onRetry={sessions.reload} />
              ) : !workspace.captureId ? (
                <EmptyState title="No capture selected" />
              ) : sessions.state === "loading" ? (
                <Skeleton rows={5} />
              ) : sessions.data && sessions.data.items.length > 0 ? (
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Identity</th>
                      <th>Endpoints</th>
                      <th>Completeness</th>
                      <th>Role basis</th>
                    </tr>
                  </thead>
                  <tbody>
                    {sessions.data.items.map((row) => {
                      const session = row as unknown as {
                        id: string;
                        session_identity: string;
                        client_endpoint: string | null;
                        server_endpoint: string | null;
                        completeness_status: string;
                        role_confidence: string;
                      };
                      return (
                        <tr key={session.id}>
                          <td className="text-accent">{session.session_identity}</td>
                          <td>
                            {session.client_endpoint ?? "?"} → {session.server_endpoint ?? "?"}
                          </td>
                          <td>
                            <Badge
                              tone={
                                session.completeness_status === "complete" ? "ok" : "warn"
                              }
                            >
                              {session.completeness_status}
                            </Badge>
                          </td>
                          <td className="text-text-muted">{session.role_confidence}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              ) : (
                <EmptyState
                  title="No sessions"
                  description="This capture contains no TCP conversations."
                />
              )}
            </Panel>
          </div>
        </div>
      </div>
    </div>
  );
}

function Line({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="flex justify-between gap-2">
      <dt className="text-text-faint">{label}</dt>
      <dd className={cn("text-text")}>{value}</dd>
    </div>
  );
}

function Stat({
  label,
  value,
  tone,
}: {
  label: string;
  value: string;
  tone?: "ok" | "warn";
}) {
  return (
    <div className="rounded-sm border border-line bg-surface-raised px-2 py-1.5">
      <p className="text-2xs uppercase tracking-wider text-text-faint">{label}</p>
      <p
        className={cn(
          "font-mono text-sm",
          tone === "warn" ? "text-status-warn" : tone === "ok" ? "text-status-ok" : "text-text",
        )}
      >
        {value}
      </p>
    </div>
  );
}