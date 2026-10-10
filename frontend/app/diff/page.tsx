"use client";

import { useSearchParams } from "next/navigation";
import { useState } from "react";
import { GitCompare } from "lucide-react";

import {
  Badge,
  Caveat,
  EmptyState,
  Panel,
  Skeleton,
} from "@/components/ui";
import { useAction, useAsync } from "@/hooks/use-async";
import { useWorkspace } from "@/hooks/use-workspace";
import { api } from "@/lib/api";

export default function DiffPage() {
  const workspace = useWorkspace();
  const params = useSearchParams();
  const projectId = params.get("project") ?? workspace.projectId;
  const [base, setBase] = useState("");
  const [compare, setCompare] = useState("");
  const [focus, setFocus] = useState("all");
  const action = useAction();

  const captures = useAsync(
    () => (projectId ? api.projectCaptures(projectId) : Promise.resolve([])),
    [projectId, workspace.revision],
  );

  const result = useAsync(
    async () => {
      if (!base || !compare) return null;
      return api.diff({
        base_capture_id: base,
        compare_capture_id: compare,
        focus,
        max_bytes: 4096,
      });
    },
    [base, compare, focus, action.error],
  );

  if (!projectId) {
    return (
      <div className="p-4">
        <EmptyState title="No project selected" />
      </div>
    );
  }

  const sessions = (result.data?.sessions ?? []) as {
    status: string;
    similarity: number;
    endpoints: string;
    reasons: string[];
    base_session_id: string | null;
    compare_session_id: string | null;
    byte_delta?: number;
    packet_delta?: number;
  }[];

  return (
    <div className="flex h-full flex-col">
      <div className="border-b border-line px-4 py-3">
        <h1 className="text-sm font-semibold tracking-tight text-text">Capture Diff</h1>
        <p className="mt-0.5 max-w-3xl text-2xs leading-relaxed text-text-muted">
          Sessions are matched on endpoints, direction, sizes and message-length shape —
          not on packet numbers, which stop corresponding as soon as behaviour changes.
        </p>
      </div>

      <div className="space-y-3 overflow-auto p-3">
        <Panel title="Comparison setup">
          <div className="grid gap-3 p-3 md:grid-cols-4">
            <label className="block">
              <span className="mb-1 block text-2xs uppercase tracking-wider text-text-faint">
                Baseline
              </span>
              <select
                className="input"
                value={base}
                onChange={(event) => setBase(event.target.value)}
              >
                <option value="">select a capture</option>
                {(captures.data ?? []).map((capture) => (
                  <option key={capture.id} value={capture.id}>
                    {capture.name}
                  </option>
                ))}
              </select>
            </label>
            <label className="block">
              <span className="mb-1 block text-2xs uppercase tracking-wider text-text-faint">
                Compare with
              </span>
              <select
                className="input"
                value={compare}
                onChange={(event) => setCompare(event.target.value)}
              >
                <option value="">select a capture</option>
                {(captures.data ?? []).map((capture) => (
                  <option key={capture.id} value={capture.id}>
                    {capture.name}
                  </option>
                ))}
              </select>
            </label>
            <label className="block">
              <span className="mb-1 block text-2xs uppercase tracking-wider text-text-faint">
                Focus
              </span>
              <select
                className="input"
                value={focus}
                onChange={(event) => setFocus(event.target.value)}
              >
                {["all", "endpoints", "sessions", "messages", "bytes", "diagnostics"].map(
                  (option) => (
                    <option key={option} value={option}>
                      {option}
                    </option>
                  ),
                )}
              </select>
            </label>
            <div className="flex items-end">
              <Badge tone={base && compare && base !== compare ? "info" : "warn"}>
                {base && compare && base !== compare
                  ? "ready"
                  : "choose two different captures"}
              </Badge>
            </div>
          </div>
          {action.error && (
            <p className="px-3 pb-3 font-mono text-2xs text-status-bad">{action.error}</p>
          )}
        </Panel>

        {!base || !compare ? (
          <Panel>
            <EmptyState
              title="Select a baseline and a comparison capture"
              description="The result is a heat map of differences. A difference is not an anomaly: it only means this recording differs from that one."
            />
          </Panel>
        ) : result.state === "loading" ? (
          <Panel>
            <Skeleton rows={10} />
          </Panel>
        ) : result.data ? (
          <>
            <Panel title="Session heat map">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Status</th>
                    <th>Endpoints</th>
                    <th>Similarity</th>
                    <th>Byte Δ</th>
                    <th>Packet Δ</th>
                    <th>Why</th>
                  </tr>
                </thead>
                <tbody>
                  {sessions.map((row, index) => (
                    <tr key={index}>
                      <td>
                        <Badge
                          tone={
                            row.status === "changed"
                              ? "warn"
                              : row.status === "added"
                                ? "info"
                                : row.status === "removed"
                                  ? "bad"
                                  : "ok"
                          }
                        >
                          {row.status}
                        </Badge>
                      </td>
                      <td className="text-text-muted">{row.endpoints}</td>
                      <td>{row.similarity.toFixed(3)}</td>
                      <td className={row.byte_delta ? "text-status-warn" : undefined}>
                        {row.byte_delta ?? 0}
                      </td>
                      <td>{row.packet_delta ?? 0}</td>
                      <td className="whitespace-normal text-text-muted">
                        {row.reasons.join("; ") || "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <div className="p-3">
                <Caveat tone="warn">
                  {String(result.data.interpretation_note)}
                </Caveat>
              </div>
            </Panel>

            {typeof result.data.endpoints === "object" &&
              result.data.endpoints !== null && (
                <Panel title="Endpoints">
                  <div className="grid gap-3 p-3 md:grid-cols-3">
                    <EndpointList
                      title="added"
                      items={(result.data.endpoints as { added: string[] }).added}
                      tone="info"
                    />
                    <EndpointList
                      title="removed"
                      items={(result.data.endpoints as { removed: string[] }).removed}
                      tone="bad"
                    />
                    <EndpointList
                      title="common"
                      items={(result.data.endpoints as { common: string[] }).common}
                      tone="ok"
                    />
                  </div>
                </Panel>
              )}

            {Array.isArray(result.data.diagnostics) && (
              <Panel title="Message-level differences">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Dir</th>
                      <th>#</th>
                      <th>Status</th>
                      <th>Base len</th>
                      <th>Compare len</th>
                      <th>Bytes changed</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(
                      result.data.messages as {
                        direction: string;
                        index: number;
                        status: string;
                        changed_count?: number;
                        base?: { length: number };
                        compare?: { length: number };
                      }[]
                    )
                      .slice(0, 200)
                      .map((row, index) => (
                        <tr key={index}>
                          <td>{row.direction}</td>
                          <td className="text-text-faint">{row.index}</td>
                          <td>
                            <Badge
                              tone={
                                row.status === "length_changed"
                                  ? "warn"
                                  : row.status === "added"
                                    ? "info"
                                    : "bad"
                              }
                            >
                              {row.status}
                            </Badge>
                          </td>
                          <td>{row.base?.length ?? "—"}</td>
                          <td>{row.compare?.length ?? "—"}</td>
                          <td className="text-status-warn">{row.changed_count ?? 0}</td>
                        </tr>
                      ))}
                  </tbody>
                </table>
              </Panel>
            )}
          </>
        ) : null}
      </div>
    </div>
  );
}

function EndpointList({
  title,
  items,
  tone,
}: {
  title: string;
  items: string[];
  tone: "info" | "bad" | "ok";
}) {
  return (
    <div>
      <p className="mb-1">
        <Badge tone={tone}>
          {title} ({items.length})
        </Badge>
      </p>
      <ul className="space-y-0.5 font-mono text-2xs text-text-muted">
        {items.length === 0 ? (
          <li className="text-text-faint">none</li>
        ) : (
          items.map((item) => <li key={item}>{item}</li>)
        )}
      </ul>
    </div>
  );
}

export { GitCompare };