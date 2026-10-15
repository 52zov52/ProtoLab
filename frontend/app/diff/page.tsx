"use client";

import { useRouter, useSearchParams } from "next/navigation";
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
import { heatCells, maxAbs, similarityColor } from "@/lib/diff-heatmap";
import { useI18n } from "@/lib/i18n";

export default function DiffPage() {
  const workspace = useWorkspace();
  const params = useSearchParams();
  const { t } = useI18n();
  const projectId = params.get("project") ?? workspace.projectId;
  const [base, setBase] = useState("");
  const [compare, setCompare] = useState("");
  const [focus, setFocus] = useState("all");
  const [selectedRow, setSelectedRow] = useState<number | null>(null);
  const action = useAction();
  const router = useRouter();

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
        <EmptyState title={t("No project selected")} />
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

  // Shared magnitude scales, so a cell's shade is comparable across the table.
  const maxByte = maxAbs(sessions.map((row) => row.byte_delta ?? 0));
  const maxPacket = maxAbs(sessions.map((row) => row.packet_delta ?? 0));
  const selected = selectedRow != null ? sessions[selectedRow] : undefined;

  return (
    <div className="flex h-full flex-col">
      <div className="border-b border-line px-4 py-3">
        <h1 className="text-sm font-semibold tracking-tight text-text">{t("Capture Diff")}</h1>
        <p className="mt-0.5 max-w-3xl text-2xs leading-relaxed text-text-muted">
          {t(
            "Sessions are matched on endpoints, direction, sizes and message-length shape — not on packet numbers, which stop corresponding as soon as behaviour changes.",
          )}
        </p>
      </div>

      <div className="space-y-3 overflow-auto p-3">
        <Panel title={t("Comparison setup")}>
          <div className="grid gap-3 p-3 md:grid-cols-4">
            <label className="block">
              <span className="mb-1 block text-2xs uppercase tracking-wider text-text-faint">
                {t("Baseline")}
              </span>
              <select
                className="input"
                value={base}
                onChange={(event) => setBase(event.target.value)}
              >
                <option value="">{t("select a capture")}</option>
                {(captures.data ?? []).map((capture) => (
                  <option key={capture.id} value={capture.id}>
                    {capture.name}
                  </option>
                ))}
              </select>
            </label>
            <label className="block">
              <span className="mb-1 block text-2xs uppercase tracking-wider text-text-faint">
                {t("Compare with")}
              </span>
              <select
                className="input"
                value={compare}
                onChange={(event) => setCompare(event.target.value)}
              >
                <option value="">{t("select a capture")}</option>
                {(captures.data ?? []).map((capture) => (
                  <option key={capture.id} value={capture.id}>
                    {capture.name}
                  </option>
                ))}
              </select>
            </label>
            <label className="block">
              <span className="mb-1 block text-2xs uppercase tracking-wider text-text-faint">
                {t("Focus")}
              </span>
              <select
                className="input"
                value={focus}
                onChange={(event) => setFocus(event.target.value)}
              >
                {["all", "endpoints", "sessions", "messages", "bytes", "diagnostics"].map(
                  (option) => (
                    <option key={option} value={option}>
                      {t(option)}
                    </option>
                  ),
                )}
              </select>
            </label>
            <div className="flex items-end">
              <Badge tone={base && compare && base !== compare ? "info" : "warn"}>
                {base && compare && base !== compare
                  ? t("ready")
                  : t("choose two different captures")}
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
              title={t("Select a baseline and a comparison capture")}
              description={t(
                "The result is a heat map of differences. A difference is not an anomaly: it only means this recording differs from that one.",
              )}
            />
          </Panel>
        ) : result.state === "loading" ? (
          <Panel>
            <Skeleton rows={10} />
          </Panel>
        ) : result.data ? (
          <>
            <Panel title={t("Session heat map")}>
              <div className="flex flex-wrap items-center gap-3 border-b border-line px-3 py-2 text-2xs text-text-faint">
                <span className="uppercase tracking-wider">{t("similarity")}</span>
                {[0, 0.25, 0.5, 0.75, 1].map((value) => (
                  <span key={value} className="flex items-center gap-1">
                    <span
                      className="inline-block h-3 w-5 rounded-sm"
                      style={{ background: similarityColor(value) }}
                    />
                    {value.toFixed(2)}
                  </span>
                ))}
                <span className="ml-auto">
                  {t("Δ shade = magnitude · blue growth · amber shrink · empty = no change")}
                </span>
              </div>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>{t("Status")}</th>
                    <th>{t("Endpoints")}</th>
                    <th>{t("Similarity")}</th>
                    <th>{t("Byte Δ")}</th>
                    <th>{t("Packet Δ")}</th>
                    <th>{t("Why")}</th>
                  </tr>
                </thead>
                <tbody>
                  {sessions.map((row, index) => {
                    const cells = heatCells(row, maxByte, maxPacket);
                    return (
                      <tr
                        key={index}
                        className={
                          selectedRow === index
                            ? "cursor-pointer bg-accent-faint"
                            : "cursor-pointer"
                        }
                        onClick={() =>
                          setSelectedRow(selectedRow === index ? null : index)
                        }
                      >
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
                        <td
                          className="text-center font-mono text-[#0b0d10]"
                          style={{ background: cells[0].color }}
                          title={cells[0].title}
                        >
                          {row.similarity.toFixed(3)}
                        </td>
                        <td
                          className="text-center font-mono"
                          style={{ background: cells[1].color }}
                          title={cells[1].title}
                        >
                          {row.byte_delta ?? 0}
                        </td>
                        <td
                          className="text-center font-mono"
                          style={{ background: cells[2].color }}
                          title={cells[2].title}
                        >
                          {row.packet_delta ?? 0}
                        </td>
                        <td className="whitespace-normal text-text-muted">
                          {row.reasons.join("; ") || "—"}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
              {selected ? (
                <div className="space-y-2 border-t border-line px-3 py-2">
                  <p className="text-2xs text-text-muted">
                    {selected.endpoints}
                    {selected.reasons.length > 0
                      ? ` — ${selected.reasons.join("; ")}`
                      : ""}
                  </p>
                  <div className="flex flex-wrap gap-2">
                    {selected.base_session_id ? (
                      <button
                        type="button"
                        className="btn"
                        onClick={() => {
                          workspace.selectSession(selected.base_session_id);
                          router.push("/sessions");
                        }}
                      >
                        {t("Open baseline session")}
                      </button>
                    ) : (
                      <span className="text-2xs text-text-faint">
                        {t("no baseline session")}
                      </span>
                    )}
                    {selected.compare_session_id ? (
                      <button
                        type="button"
                        className="btn"
                        onClick={() => {
                          workspace.selectSession(selected.compare_session_id);
                          router.push("/sessions");
                        }}
                      >
                        {t("Open comparison session")}
                      </button>
                    ) : (
                      <span className="text-2xs text-text-faint">
                        {t("no comparison session")}
                      </span>
                    )}
                  </div>
                </div>
              ) : null}
              <div className="p-3">
                <Caveat tone="warn">
                  {t(String(result.data.interpretation_note))}
                </Caveat>
              </div>
            </Panel>

            {typeof result.data.endpoints === "object" &&
              result.data.endpoints !== null && (
                <Panel title={t("Endpoints")}>
                  <div className="grid gap-3 p-3 md:grid-cols-3">
                    <EndpointList
                      title={t("added")}
                      items={(result.data.endpoints as { added: string[] }).added}
                      tone="info"
                    />
                    <EndpointList
                      title={t("removed")}
                      items={(result.data.endpoints as { removed: string[] }).removed}
                      tone="bad"
                    />
                    <EndpointList
                      title={t("common")}
                      items={(result.data.endpoints as { common: string[] }).common}
                      tone="ok"
                    />
                  </div>
                </Panel>
              )}

            {Array.isArray(result.data.diagnostics) && (
              <Panel title={t("Message-level differences")}>
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>{t("Dir")}</th>
                      <th>#</th>
                      <th>{t("Status")}</th>
                      <th>{t("Base len")}</th>
                      <th>{t("Compare len")}</th>
                      <th>{t("Bytes changed")}</th>
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
  const { t } = useI18n();

  return (
    <div>
      <p className="mb-1">
        <Badge tone={tone}>
          {title} ({items.length})
        </Badge>
      </p>
      <ul className="space-y-0.5 font-mono text-2xs text-text-muted">
        {items.length === 0 ? (
          <li className="text-text-faint">{t("none")}</li>
        ) : (
          items.map((item) => <li key={item}>{item}</li>)
        )}
      </ul>
    </div>
  );
}

export { GitCompare };