"use client";

import { useSearchParams } from "next/navigation";
import { useMemo, useState } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

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
import { cn } from "@/lib/format";
import { useI18n } from "@/lib/i18n";

const ACCENT = "#3fb6c8";
const GRID = "#23282f";
const AXIS_TEXT = "#8d97a3";

/** Bars kept readable: the list below carries every row. */
const CHART_ROWS = 12;

interface AnomalyRow {
  entity_id: string;
  entity_type: string;
  score: number;
  explanation?: { feature: string; value: number; baseline_mean: number }[];
  navigate_to?: {
    message_id: string | null;
    stream_id: string | null;
    capture_id: string | null;
  } | null;
}

export default function AnomaliesPage() {
  const workspace = useWorkspace();
  const { t } = useI18n();
  const params = useSearchParams();
  const projectId = params.get("project") ?? workspace.projectId;
  const [scope, setScope] = useState<"messages" | "sessions">("messages");

  const status = useAsync(() => api.anomaliesStatus(), []);
  const action = useAction();
  const score = useAction();
  /** The most recently trained model, shown verbatim so the operator can audit it. */
  const [latest, setLatest] = useState<Record<string, unknown> | null>(null);
  /** The most recent scoring run, for the ranked chart and its explanation. */
  const [scoreResult, setScoreResult] = useState<Record<string, unknown> | null>(null);

  if (!projectId) {
    return (
      <div className="p-4">
        <EmptyState title={t("No project selected")} />
      </div>
    );
  }

  const available = status.data?.available === true;

  return (
    <div className="flex h-full flex-col">
      <div className="border-b border-line px-4 py-3">
        <h1 className="text-sm font-semibold tracking-tight text-text">
          {t("Anomaly Detection")}
        </h1>
        <p className="mt-0.5 max-w-3xl text-2xs leading-relaxed text-text-muted">
          {t(
            "Isolation Forest over a baseline corpus. Scores rank how unusual an entity is relative to that corpus; they are not probabilities and carry no severity.",
          )}
        </p>
      </div>

      <div className="space-y-3 overflow-auto p-3">
        {status.state === "loading" ? (
          <Skeleton rows={4} />
        ) : !available ? (
          <Panel title={t("Unavailable")}>
            <div className="space-y-2 p-3">
              <Badge tone="warn">{t("scikit-learn is not installed")}</Badge>
              <p className="text-2xs text-text-muted">
                {String(status.data?.availability_note ?? "")}
              </p>
              <pre className="overflow-x-auto rounded-sm border border-line bg-surface-sunken p-2 font-mono text-2xs">
{`python -m pip install "madrigal-protocol-lab-backend[analytics]"`}
              </pre>
              <Caveat>
                {t(
                  "The product is fully usable without this module. Nothing else degrades when anomaly detection is unavailable.",
                )}
              </Caveat>
            </div>
          </Panel>
        ) : (
          <>
            <Panel title={t("Train a baseline")}>
              <TrainForm
                projectId={projectId}
                scope={scope}
                onScopeChange={setScope}
                pending={action.pending}
                onTrain={async (body) => {
                  const result = await action.run(() => api.anomaliesTrain(body));
                  if (result) setLatest(result as Record<string, unknown>);
                  return result;
                }}
              />
              {action.notice && <p className="px-3 pb-3 text-2xs text-status-ok">{action.notice}</p>}
              {action.error && (
                <p className="px-3 pb-3 font-mono text-2xs text-status-bad">{action.error}</p>
              )}
            </Panel>

            {latest && (
              <Panel title={t("Latest model")}>
                <div className="space-y-2 p-3 font-mono text-2xs">
                  <pre className="max-h-96 overflow-auto rounded-sm border border-line bg-surface-sunken p-2">
                    {JSON.stringify(latest, null, 2)}
                  </pre>
                  <Caveat>
                    {String(
                      (latest.training_summary as { interpretation?: string })?.interpretation ??
                        "",
                    )}
                  </Caveat>
                </div>
              </Panel>
            )}

            <Panel title={t("Score a capture against the baseline")}>
              <ScoreForm
                projectId={projectId}
                scope={scope}
                pending={score.pending}
                onScore={async (body) => {
                  const result = await score.run(() => api.anomaliesScore(body));
                  setScoreResult(result as Record<string, unknown> | null);
                  return result;
                }}
              />
              {score.error && (
                <p className="px-3 pb-3 font-mono text-2xs text-status-bad">{score.error}</p>
              )}
            </Panel>

            {scoreResult && <ScoreResult result={scoreResult} />}
          </>
        )}
      </div>
    </div>
  );
}

function TrainForm({
  projectId,
  scope,
  onScopeChange,
  pending,
  onTrain,
}: {
  projectId: string;
  scope: "messages" | "sessions";
  onScopeChange: (scope: "messages" | "sessions") => void;
  pending: boolean;
  onTrain: (body: Record<string, unknown>) => Promise<unknown>;
}) {
  const { t } = useI18n();
  const captures = useAsync(() => api.projectCaptures(projectId), [projectId]);
  const [selected, setSelected] = useState<string[]>([]);
  const [name, setName] = useState(t("Baseline model"));

  return (
    <div className="grid gap-3 p-3 md:grid-cols-3">
      <label className="block">
        <span className="mb-1 block text-2xs uppercase tracking-wider text-text-faint">
          {t("Model name")}
        </span>
        <input
          className="input"
          value={name}
          maxLength={200}
          onChange={(event) => setName(event.target.value)}
        />
      </label>
      <label className="block">
        <span className="mb-1 block text-2xs uppercase tracking-wider text-text-faint">
          {t("Scope")}
        </span>
        <select
          className="input"
          value={scope}
          onChange={(event) => onScopeChange(event.target.value as "messages" | "sessions")}
        >
          <option value="messages">{t("messages")}</option>
          <option value="sessions">{t("sessions")}</option>
        </select>
      </label>
      <div className="flex items-end">
        <button
          type="button"
          className="btn btn-primary"
          disabled={pending || selected.length === 0}
          onClick={() =>
            void onTrain({
              name,
              capture_ids: selected,
              scope,
              contamination: 0.05,
              n_estimators: 100,
              seed: 42,
            })
          }
        >
          {pending ? t("Training…") : t("Train baseline")}
        </button>
      </div>

      <div className="md:col-span-3">
        <p className="mb-1 text-2xs uppercase tracking-wider text-text-faint">
          {t("Baseline corpus")}
        </p>
        {captures.state === "loading" ? (
          <Skeleton rows={2} />
        ) : (
          <ul className="max-h-40 space-y-0.5 overflow-auto">
            {(captures.data ?? []).map((capture) => (
              <li key={capture.id}>
                <label className="flex items-center gap-2 py-0.5 text-2xs">
                  <input
                    type="checkbox"
                    checked={selected.includes(capture.id)}
                    onChange={(event) =>
                      setSelected(
                        event.target.checked
                          ? [...selected, capture.id]
                          : selected.filter((id) => id !== capture.id),
                      )
                    }
                  />
                  <span className="truncate text-text">{capture.name}</span>
                  <span
                    className={cn(
                      "text-text-faint",
                      capture.analysis_status === "completed" && "text-status-ok",
                    )}
                  >
                    {capture.analysis_status}
                  </span>
                </label>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

/** Scoring against a trained model: model, corpus and how many to report. */
function ScoreForm({
  projectId,
  scope,
  pending,
  onScore,
}: {
  projectId: string;
  scope: "messages" | "sessions";
  pending: boolean;
  onScore: (body: Record<string, unknown>) => Promise<unknown>;
}) {
  const { t } = useI18n();
  const captures = useAsync(() => api.projectCaptures(projectId), [projectId]);
  const models = useAsync(() => api.anomaliesModels(projectId), [projectId]);
  const [modelId, setModelId] = useState("");
  const [selected, setSelected] = useState<string[]>([]);
  const [limit, setLimit] = useState("25");

  const usable = ((models.data ?? []) as Record<string, unknown>[]);

  return (
    <div className="grid gap-3 p-3 md:grid-cols-4">
      <label className="block">
        <span className="mb-1 block text-2xs uppercase tracking-wider text-text-faint">
          {t("Model")}
        </span>
        <select
          className="input"
          value={modelId}
          onChange={(event) => setModelId(event.target.value)}
        >
          <option value="">{t("Select a model")}</option>
          {usable.map((model) => (
            <option key={String(model.id)} value={String(model.id)}>
              {String(model.name)}
            </option>
          ))}
        </select>
      </label>
      <label className="block">
        <span className="mb-1 block text-2xs uppercase tracking-wider text-text-faint">
          {t("Report at most")}
        </span>
        <input
          className="input"
          inputMode="numeric"
          value={limit}
          onChange={(event) => setLimit(event.target.value)}
        />
      </label>
      <div className="flex items-end">
        <button
          type="button"
          className="btn btn-primary"
          disabled={pending || !modelId || selected.length === 0}
          onClick={() =>
            void onScore({
              model_id: modelId,
              capture_ids: selected,
              scope,
              limit: Math.max(1, Number.parseInt(limit, 10) || 25),
            })
          }
        >
          {pending ? t("Scoring…") : t("Score captures")}
        </button>
      </div>

      <div className="md:col-span-4">
        <p className="mb-1 text-2xs uppercase tracking-wider text-text-faint">
          {t("Captures to score")}
        </p>
        {usable.length === 0 ? (
          <p className="text-2xs text-text-muted">
            {t("Train a baseline first; the server refuses a capture that cannot supply every feature the model was trained on.")}
          </p>
        ) : captures.state === "loading" ? (
          <Skeleton rows={2} />
        ) : (
          <ul className="max-h-40 space-y-0.5 overflow-auto">
            {(captures.data ?? []).map((capture) => (
              <li key={capture.id}>
                <label className="flex items-center gap-2 py-0.5 text-2xs">
                  <input
                    type="checkbox"
                    checked={selected.includes(capture.id)}
                    onChange={(event) =>
                      setSelected(
                        event.target.checked
                          ? [...selected, capture.id]
                          : selected.filter((id) => id !== capture.id),
                      )
                    }
                  />
                  <span className="truncate text-text">{capture.name}</span>
                </label>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

/** Ranked scores plus the features that put each entity away from the mean. */
function ScoreResult({ result }: { result: Record<string, unknown> }) {
  const { t } = useI18n();
  const rows: AnomalyRow[] = useMemo(
    () => ((result.anomalies ?? []) as AnomalyRow[]) ?? [],
    [result],
  );
  const chartData = useMemo(
    () =>
      rows.slice(0, CHART_ROWS).map((row) => ({
        label: `${row.entity_type} ${row.entity_id.slice(0, 8)}`,
        score: row.score,
      })),
    [rows],
  );

  return (
    <Panel title={t("Scored result")}>
      <div className="space-y-3">
        <div className="flex flex-wrap items-center gap-2 p-3">
          <Badge tone="info">{String(result.model_name ?? "")}</Badge>
          <span className="text-2xs text-text-faint">
            {t("{count} entity(ies) reported · scope {scope}", {
              count: rows.length,
              scope: String(result.scope ?? ""),
            })}
          </span>
        </div>

        {rows.length === 0 ? (
          <EmptyState
            title={t("Nothing scored")}
            description={t("No entity was reported for this scope.")}
          />
        ) : (
          <>
            <div className="px-3">
              <p className="mb-1 text-2xs uppercase tracking-wider text-text-faint">
                {t("Outlier score per entity")}
              </p>
              {/* The chart shows the shape of the ranking; the table below keeps
                  the exact values, the explanation and the reference. */}
              <div className="h-[300px] w-full">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart
                    data={chartData}
                    layout="vertical"
                    margin={{ top: 4, right: 16, bottom: 4, left: 4 }}
                  >
                    <CartesianGrid stroke={GRID} horizontal={false} />
                    <XAxis type="number" stroke={GRID} tick={{ fill: AXIS_TEXT, fontSize: 10 }} />
                    <YAxis
                      type="category"
                      dataKey="label"
                      width={170}
                      stroke={GRID}
                      tick={{ fill: AXIS_TEXT, fontSize: 10 }}
                    />
                    <Tooltip
                      cursor={{ fill: "#171b21" }}
                      contentStyle={{
                        background: "#171b21",
                        border: "1px solid #313842",
                        borderRadius: 2,
                        fontSize: 11,
                      }}
                      labelStyle={{ color: "#d6dbe1" }}
                    />
                    <Bar dataKey="score" fill={ACCENT} radius={[0, 2, 2, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>{t("Entity")}</th>
                    <th className="w-24">{t("Score")}</th>
                    <th>{t("What pushed the score")}</th>
                    <th>{t("Stream")}</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((row) => (
                    <tr key={row.entity_id}>
                      <td className="font-mono text-2xs text-text">
                        {row.entity_type} {row.entity_id}
                      </td>
                      <td className="font-mono text-2xs text-accent">
                        {row.score.toFixed(4)}
                      </td>
                      <td>
                        <ul className="space-y-0.5">
                          {(row.explanation ?? []).slice(0, 3).map((item) => (
                            <li
                              key={item.feature}
                              className="font-mono text-2xs text-text-muted"
                            >
                              {item.feature}: {item.value.toFixed(3)} ·{" "}
                              {t("mean {value}", { value: item.baseline_mean.toFixed(3) })}
                            </li>
                          ))}
                        </ul>
                      </td>
                      <td className="font-mono text-2xs text-text-faint">
                        {row.navigate_to?.stream_id ?? "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}

        <div className="px-3 pb-3">
          <Caveat>{String(result.interpretation ?? "")}</Caveat>
        </div>
      </div>
    </Panel>
  );
}