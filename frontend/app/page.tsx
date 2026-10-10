"use client";

import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { useEffect } from "react";

import { CapturePicker, ProjectPicker } from "@/components/pickers";
import {
  Badge,
  Caveat,
  EmptyState,
  ErrorState,
  Metric,
  Panel,
  Skeleton,
} from "@/components/ui";
import { useAsync } from "@/hooks/use-async";
import { useWorkspace } from "@/hooks/use-workspace";
import { formatBytes, formatNumber } from "@/lib/format";

export default function OverviewPage() {
  const workspace = useWorkspace();
  const params = useSearchParams();
  const projectParam = params.get("project");

  // A project passed in the URL becomes the active one.
  useEffect(() => {
    if (projectParam && projectParam !== workspace.projectId) {
      workspace.selectProject(projectParam, workspace.projectName ?? projectParam.slice(0, 12));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [projectParam]);

  const metrics = useAsync(
    () =>
      workspace.projectId
        ? api_metrics(workspace.projectId)
        : Promise.resolve(null),
    [workspace.projectId, workspace.revision],
  );

  const integrity = useAsync(
    () =>
      workspace.projectId
        ? import("@/lib/api").then((m) => m.api.integrity(workspace.projectId!))
        : Promise.resolve(null),
    [workspace.projectId, workspace.revision],
  );

  const analyzers = useAsync(
    () =>
      workspace.projectId
        ? import("@/lib/api").then((m) => m.api.anomaliesStatus())
        : Promise.resolve(null),
    [workspace.projectId],
  );

  const data = metrics.data;

  return (
    <div className="flex h-full flex-col">
      <div className="border-b border-line px-4 py-3">
        <h1 className="text-sm font-semibold tracking-tight text-text">Overview</h1>
        <p className="mt-0.5 max-w-3xl text-2xs leading-relaxed text-text-muted">
          Every number below is computed from the current project state. Nothing here is
          seeded, estimated or carried over from a demo dataset.
        </p>
      </div>

      <div className="min-h-0 flex-1 overflow-auto p-4">
        {!workspace.projectId ? (
          <div className="mx-auto max-w-3xl">
            <EmptyState
              title="Start an investigation"
              description="A project holds the imported captures, the reconstructed streams, the hypotheses you form and the evidence that supports or contradicts them. Create one, or open an existing one, then import a PCAP."
            />
            <div className="mt-4">
              <ProjectPicker />
            </div>
          </div>
        ) : (
          <div className="space-y-4">
            {metrics.state === "error" && (
              <ErrorState message={metrics.error ?? ""} onRetry={metrics.reload} />
            )}

            <div className="grid grid-cols-2 gap-2 md:grid-cols-4 xl:grid-cols-6">
              <Metric label="Captures" value={data ? formatNumber(data.captures) : "—"} />
              <Metric label="Packets" value={data ? formatNumber(data.packets) : "—"} />
              <Metric
                label="TCP sessions"
                value={data ? formatNumber(data.tcp_sessions) : "—"}
                hint={data?.tcp_sessions ? "5-tuple aware" : undefined}
              />
              <Metric
                label="Streams"
                value={data ? formatNumber(data.streams) : "—"}
                hint="both directions"
              />
              <Metric
                label="Messages"
                value={data ? formatNumber(data.messages) : "—"}
                hint="depends on a framing rule"
              />
              <Metric
                label="Bytes on disk"
                value={data ? formatBytes(data.bytes_stored) : "—"}
              />
              <Metric
                label="Hypotheses"
                value={data ? formatNumber(data.hypotheses) : "—"}
              />
              <Metric
                label="Interpretations"
                value={data ? formatNumber(data.interpretations) : "—"}
                hint="executable rules"
              />
              <Metric label="Validation runs" value={data ? formatNumber(data.validation_runs) : "—"} />
              <Metric
                label="Counterexamples"
                value={data ? formatNumber(data.counterexamples) : "—"}
                tone={data && data.counterexamples > 0 ? "warn" : undefined}
                hint="messages that break a rule"
              />
              <Metric
                label="Problem sessions"
                value={data ? formatNumber(data.sessions_with_reconstruction_problems) : "—"}
                tone={
                  data && data.sessions_with_reconstruction_problems > 0 ? "warn" : "ok"
                }
                hint="incomplete or conflicting"
              />
              <Metric
                label="Anomaly detection"
                value={
                  analyzers.state === "ready"
                    ? analyzers.data?.available
                      ? "available"
                      : "unavailable"
                    : "—"
                }
                tone={analyzers.data?.available ? "ok" : "unknown"}
              />
            </div>

            <div className="grid gap-4 lg:grid-cols-2">
              <Panel title="Source integrity">
                {integrity.state === "loading" ? (
                  <Skeleton rows={4} />
                ) : integrity.data ? (
                  <div className="space-y-2 p-3">
                    <div className="flex items-center gap-2">
                      <Badge tone={integrity.data.all_match ? "ok" : "bad"}>
                        {integrity.data.all_match
                          ? "all captures match their recorded hashes"
                          : "hash mismatch detected"}
                      </Badge>
                    </div>
                    <ul className="space-y-1 font-mono text-2xs">
                      {(integrity.data.captures as { name: string; status: string; expected_sha256: string }[]).map(
                        (row) => (
                          <li key={row.name} className="flex items-center justify-between gap-2">
                            <span className="truncate text-text">{row.name}</span>
                            <Badge
                              tone={
                                row.status === "ok"
                                  ? "ok"
                                  : row.status === "missing"
                                    ? "bad"
                                    : "warn"
                              }
                            >
                              {row.status}
                            </Badge>
                          </li>
                        ),
                      )}
                    </ul>
                    <Caveat>
                      SHA-256 detects unintended modification when a trusted reference
                      exists. It does not prove where a file came from and provides no
                      confidentiality.
                    </Caveat>
                  </div>
                ) : (
                  <EmptyState title="No integrity data" />
                )}
              </Panel>

              <Panel title="Analyzer versions in use">
                <div className="space-y-2 p-3">
                  {data && Object.keys(data.analyst_versions).length > 0 ? (
                    Object.entries(data.analyst_versions).map(([key, version]) => (
                      <div key={key} className="font-mono text-2xs">
                        <span className="text-text-faint">{key}</span>
                        <span className="ml-2 text-text">{version}</span>
                      </div>
                    ))
                  ) : (
                    <p className="text-2xs text-text-faint">
                      Run an analysis to record which analyzer version produced these results.
                    </p>
                  )}
                  <Caveat>
                    Results are only reproducible with the same analyzer version and the
                    same recorded options. Both are stored with every run.
                  </Caveat>
                </div>
              </Panel>
            </div>

            <div className="grid gap-4 lg:grid-cols-2">
              <CapturePicker />
              <Panel title="Research path">
                <ol className="space-y-2 p-3 text-2xs text-text-muted">
                  {[
                    ["Import a capture", "/captures"],
                    ["Reconstruct the TCP session", "/sessions"],
                    ["Inspect the byte stream", "/streams"],
                    ["Frame messages and compare them", "/workbench"],
                    ["Write an interpretation and validate it", "/hypotheses"],
                    ["Export the investigation", "/reports"],
                  ].map(([label, href], index) => (
                    <li key={href} className="flex items-start gap-2">
                      <span className="mt-0.5 font-mono text-text-faint">{index + 1}.</span>
                      <Link className="link" href={`${href}?project=${workspace.projectId}`}>
                        {label}
                      </Link>
                    </li>
                  ))}
                </ol>
              </Panel>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function api_metrics(projectId: string) {
  return import("@/lib/api").then((m) => m.api.metrics(projectId));
}