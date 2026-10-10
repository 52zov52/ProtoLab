"use client";

import { useSearchParams } from "next/navigation";
import { useState } from "react";

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

export default function AnomaliesPage() {
  const workspace = useWorkspace();
  const params = useSearchParams();
  const projectId = params.get("project") ?? workspace.projectId;
  const [scope, setScope] = useState<"messages" | "sessions">("messages");

  const status = useAsync(() => api.anomaliesStatus(), []);
  const action = useAction();

  if (!projectId) {
    return (
      <div className="p-4">
        <EmptyState title="No project selected" />
      </div>
    );
  }

  const available = status.data?.available === true;

  return (
    <div className="flex h-full flex-col">
      <div className="border-b border-line px-4 py-3">
        <h1 className="text-sm font-semibold tracking-tight text-text">
          Anomaly Detection
        </h1>
        <p className="mt-0.5 max-w-3xl text-2xs leading-relaxed text-text-muted">
          Isolation Forest over a baseline corpus. Scores rank how unusual an entity is
          relative to that corpus; they are not probabilities and carry no severity.
        </p>
      </div>

      <div className="space-y-3 overflow-auto p-3">
        {status.state === "loading" ? (
          <Skeleton rows={4} />
        ) : !available ? (
          <Panel title="Unavailable">
            <div className="space-y-2 p-3">
              <Badge tone="warn">scikit-learn is not installed</Badge>
              <p className="text-2xs text-text-muted">
                {String(status.data?.availability_note ?? "")}
              </p>
              <pre className="overflow-x-auto rounded-sm border border-line bg-surface-sunken p-2 font-mono text-2xs">
{`python -m pip install "madrigal-protocol-lab-backend[analytics]"`}
              </pre>
              <Caveat>
                The product is fully usable without this module. Nothing else degrades
                when anomaly detection is unavailable.
              </Caveat>
            </div>
          </Panel>
        ) : (
          <>
            <Panel title="Train a baseline">
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
              <Panel title="Latest model">
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
  const captures = useAsync(() => api.projectCaptures(projectId), [projectId]);
  const [selected, setSelected] = useState<string[]>([]);
  const [name, setName] = useState("Baseline model");

  return (
    <div className="grid gap-3 p-3 md:grid-cols-3">
      <label className="block">
        <span className="mb-1 block text-2xs uppercase tracking-wider text-text-faint">
          Model name
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
          Scope
        </span>
        <select
          className="input"
          value={scope}
          onChange={(event) => onScopeChange(event.target.value as "messages" | "sessions")}
        >
          <option value="messages">messages</option>
          <option value="sessions">sessions</option>
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
          {pending ? "Training…" : "Train baseline"}
        </button>
      </div>

      <div className="md:col-span-3">
        <p className="mb-1 text-2xs uppercase tracking-wider text-text-faint">
          Baseline corpus
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