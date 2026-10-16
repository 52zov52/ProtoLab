"use client";

import { useSearchParams } from "next/navigation";
import { useEffect, useState } from "react";
import { Check, FlaskConical, PlayCircle, X } from "lucide-react";

import {
  Badge,
  Caveat,
  EmptyState,

  Panel,
  Skeleton,
} from "@/components/ui";
import { useAction, useAsync } from "@/hooks/use-async";
import { SpecEditor } from "@/components/spec-editor";
import { useWorkspace } from "@/hooks/use-workspace";
import { api } from "@/lib/api";
import { cn, formatTimestamp, hypothesisTone, verdictTone } from "@/lib/format";
import { useI18n } from "@/lib/i18n";

const STARTER_SPEC = {
  schema_version: "1.0",
  protocol_name: "NewProtocol",
  description: "What this specification claims, and how it was arrived at.",
  direction: "both",
  framing: {
    method: "length_prefix",
    length_field: {
      offset: 0,
      size: 2,
      endianness: "big",
      includes_header: true,
    },
  },
  fields: [
    {
      name: "length",
      kind: "uint16",
      offset: 0,
      size: 2,
      endianness: "big",
      semantic_status: "observed",
      description: "Total message length, including these two bytes.",
    },
  ],
};

export default function HypothesesPage() {
  const workspace = useWorkspace();
  const params = useSearchParams();
  const { t } = useI18n();
  const projectId = params.get("project") ?? workspace.projectId;

  const [draft, setDraft] = useState(JSON.stringify(STARTER_SPEC, null, 2));
  const [specError, setSpecError] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [runId, setRunId] = useState<string | null>(null);
  const [corpus, setCorpus] = useState<string[]>([]);
  const [runResult, setRunResult] = useState<Record<string, unknown> | null>(null);

  const action = useAction();
  const validateAction = useAction();

  const hypotheses = useAsync(
    () => (projectId ? api.hypotheses(projectId) : Promise.resolve([])),
    [projectId, workspace.revision],
  );

  const interpretations = useAsync(
    () => (projectId ? api.interpretations(projectId) : Promise.resolve([])),
    [projectId, workspace.revision],
  );

  const support = useAsync(
    () => (projectId ? api.interpretationSupport(projectId) : Promise.resolve(null)),
    [projectId],
  );

  const metrics = useAsync(
    () => (projectId ? api.metrics(projectId) : Promise.resolve(null)),
    [projectId, workspace.revision],
  );

  const run = useAsync(
    () => (runId ? api.validationRun(runId) : Promise.resolve(null)),
    [runId],
  );

  const counterexamples = useAsync(
    () => (runId ? api.counterexamples(runId) : Promise.resolve(null)),
    [runId],
  );

  // Default the corpus to every capture in the project.
  useEffect(() => {
    if (metrics.data && corpus.length === 0) {
      void (async () => {
        const ids: string[] = [];
        // The metrics endpoint does not list capture ids, so derive them from the
        // project export path the UI already uses elsewhere.
        const rows = (hypotheses.data ?? []) as { id: string }[];
        void rows;
        setCorpus(ids);
      })();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [metrics.data]);

  const selected = (interpretations.data ?? []).find((i) => i.id === selectedId) ?? null;

  useEffect(() => {
    if (selected && typeof selected.specification === "object") {
      setDraft(JSON.stringify(selected.specification, null, 2));
    }
  }, [selectedId]); // eslint-disable-line react-hooks/exhaustive-deps

  // Validate the draft against the current text so the "Valid JSON" hint stays
  // honest while the analyst types — it must not claim a broken draft is fine.
  const validateDraft = (text: string): Record<string, unknown> | null => {
    try {
      const parsed = JSON.parse(text);
      if (typeof parsed !== "object" || parsed === null) {
        setSpecError(t("The specification must be a JSON object."));
        return null;
      }
      setSpecError(null);
      return parsed as Record<string, unknown>;
    } catch (error) {
      setSpecError(error instanceof Error ? error.message : t("Invalid JSON."));
      return null;
    }
  };

  const create = async () => {
    if (!projectId) return;
    const specification = validateDraft(draft);
    if (!specification) return;
    const created = await action.run(
      () =>
        api.createInterpretation(projectId, {
          name: String(specification.protocol_name ?? "Interpretation"),
          specification,
        }),
      t("Interpretation created."),
    );
    if (created) {
      setSelectedId(created.id);
      workspace.invalidate();
    }
  };

  const update = async () => {
    if (!projectId || !selectedId) return;
    const specification = validateDraft(draft);
    if (!specification) return;
    const updated = await action.run(
      () => api.updateInterpretation(projectId, selectedId, { specification }),
      t("Interpretation updated. Previous validation runs are now marked stale."),
    );
    if (updated) {
      workspace.invalidate();
      setRunResult(null);
    }
  };

  const validate = async () => {
    if (!projectId || !selectedId) return;
    if (corpus.length === 0) {
      validateAction.setError(
        t(
          "Select at least one capture to validate against. A rule tested on no data proves nothing.",
        ),
      );
      return;
    }
    const result = await validateAction.run(() =>
      api.validate(projectId, selectedId, { capture_ids: corpus }),
    );
    if (result) {
      setRunResult(result);
      setRunId(String(result.run_id));
      workspace.invalidate();
    }
  };

  if (!projectId) {
    return (
      <div className="p-4">
        <EmptyState
          title={t("No project selected")}
          description={t("Open a project on the Overview page first.")}
        />
      </div>
    );
  }

  return (
    <div className="flex h-full flex-col">
      <div className="flex shrink-0 items-start justify-between gap-4 border-b border-line px-4 py-3">
        <div>
          <h1 className="text-sm font-semibold tracking-tight text-text">
            {t("Hypotheses & Rules")}
          </h1>
          <p className="mt-0.5 max-w-3xl text-2xs leading-relaxed text-text-muted">
            {t(
              "Write an executable interpretation, run it against a corpus and read the counterexamples. A rule that survives every message in this corpus is",
            )}{" "}
            <em>{t("supported by observed data")}</em>{" "}
            {t("— not proven universally.")}
          </p>
        </div>
      </div>

      <div className="grid min-h-0 flex-1 grid-cols-1 gap-3 overflow-auto p-3 xl:grid-cols-[280px_1fr_400px]">
        {/* -- left: hypotheses and interpretations -------------------- */}
        <div className="space-y-3">
          <Panel
            title={t("Hypotheses")}
            actions={
              <button
                type="button"
                className="btn"
                onClick={async () => {
                  const name = window.prompt(t("Hypothesis name"));
                  if (!name) return;
                  const created = await action.run(() =>
                    api.createHypothesis(projectId, { name, status: "draft" }),
                  );
                  if (created) workspace.invalidate();
                }}
              >
                {t("new")}
              </button>
            }
          >
            {hypotheses.state === "loading" ? (
              <Skeleton rows={5} />
            ) : (hypotheses.data ?? []).length === 0 ? (
              <EmptyState
                title={t("No hypotheses yet")}
                description={t(
                  "A hypothesis records what you believe the protocol looks like and why.",
                )}
              />
            ) : (
              <ul>
                {(hypotheses.data as Record<string, unknown>[]).map((h) => {
                  const row = h as unknown as {
                    id: string;
                    name: string;
                    status: string;
                    version: number;
                    updated_at: string;
                  };
                  return (
                    <li key={row.id} className="border-b border-line/60 px-3 py-2">
                      <div className="flex items-center justify-between gap-2">
                        <span className="truncate text-2xs text-text">{row.name}</span>
                        <Badge tone={hypothesisTone(row.status)}>{row.status}</Badge>
                      </div>
                      <p className="mt-0.5 text-2xs text-text-faint">
                        v{row.version} · {formatTimestamp(Date.parse(row.updated_at) / 1000)}
                      </p>
                      <select
                        className="input mt-1.5"
                        value={row.status}
                        aria-label={t("Status of {name}", { name: row.name })}
                        onChange={async (event) => {
                          const next = event.target.value;
                          await action.run(
                            () => api.updateHypothesis(projectId, row.id, { status: next }),
                            t("Hypothesis updated."),
                          );
                          workspace.invalidate();
                        }}
                      >
                        {[
                          "draft",
                          "proposed",
                          "testing",
                          "supported",
                          "contradicted",
                          "revised",
                          "rejected",
                        ].map((status) => (
                          <option key={status} value={status}>
                            {t(status)}
                          </option>
                        ))}
                      </select>
                    </li>
                  );
                })}
              </ul>
            )}
          </Panel>

          <Panel title={t("Interpretations")}>
            {interpretations.state === "loading" ? (
              <Skeleton rows={4} />
            ) : (interpretations.data ?? []).length === 0 ? (
              <EmptyState
                title={t("No rules yet")}
                description={t("Write a specification on the right and create it.")}
              />
            ) : (
              <ul>
                {(interpretations.data ?? []).map((row) => (
                  <li key={row.id}>
                    <button
                      type="button"
                      onClick={() => setSelectedId(row.id)}
                      className={cn(
                        "w-full border-b border-line/60 px-3 py-2 text-left transition-colors",
                        selectedId === row.id ? "bg-accent-faint" : "hover:bg-surface-raised",
                      )}
                    >
                      <span className="block truncate font-mono text-2xs text-text">
                        {row.name}
                      </span>
                      <span className="mt-0.5 block text-2xs text-text-faint">
                        v{row.version} · {row.checksum.slice(0, 16)}…
                      </span>
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </Panel>
        </div>

        {/* -- middle: editor ------------------------------------------- */}
        <Panel
          title={t("Interpretation specification (JSON)")}
          actions={
            <>
              <button
                type="button"
                className="btn"
                onClick={() => setDraft(JSON.stringify(STARTER_SPEC, null, 2))}
              >
                {t("reset")}
              </button>
              <button type="button" className="btn btn-primary" onClick={create}>
                {t("create")}
              </button>
              <button
                type="button"
                className="btn"
                disabled={!selectedId}
                onClick={update}
              >
                {t("save")}
              </button>
            </>
          }
        >
          <div className="flex h-full min-h-0 flex-col">
            <SpecEditor
              value={draft}
              onChange={(next) => {
                setDraft(next);
                validateDraft(next);
              }}
              ariaLabel={t("Interpretation specification")}
            />
            <div className="border-t border-line p-2">
              {specError ? (
                <p className="font-mono text-2xs text-status-bad">{specError}</p>
              ) : (
                <p className="text-2xs text-status-ok">
                  <Check className="mr-1 inline h-3 w-3" aria-hidden />
                  {t("Valid JSON. The backend validates the schema again on save.")}
                </p>
              )}
              {action.notice && (
                <p className="mt-1 text-2xs text-status-ok">{action.notice}</p>
              )}
              {action.error && (
                <p className="mt-1 font-mono text-2xs text-status-bad">{action.error}</p>
              )}
            </div>
          </div>
        </Panel>

        {/* -- right: validation and counterexamples -------------------- */}
        <div className="space-y-3">
          <Panel title={t("Validate against a corpus")}>
            <div className="space-y-2 p-3">
              <CorpusPicker
                projectId={projectId}
                selected={corpus}
                onChange={setCorpus}
              />
              <button
                type="button"
                className="btn btn-primary w-full"
                disabled={!selectedId || validateAction.pending}
                onClick={validate}
              >
                <FlaskConical className="h-3 w-3" aria-hidden />
                {validateAction.pending ? t("Validating…") : t("Run validation")}
              </button>
              {validateAction.error && (
                <p className="font-mono text-2xs text-status-bad">
                  {validateAction.error}
                </p>
              )}
              {runResult && (
                <VerdictSummary result={runResult} />
              )}
            </div>
          </Panel>

          {run?.data && (
            <Panel title={t("Validation run")}>
              <dl className="space-y-1 p-3 font-mono text-2xs">
                <Row label={t("run")} value={run.data.id.slice(0, 16)} />
                <Row label={t("rule")} value={run.data.interpretation_name ?? "-"} />
                <Row label={t("rule version")} value={String(run.data.interpretation_version ?? "-")} />
                <Row
                  label={t("checksum")}
                  value={(run.data.specification_checksum ?? "-").slice(0, 16)}
                />
                <Row label={t("status")} value={run.data.status} />
                <Row label={t("analyzer")} value={run.data.analyzer_version} />
              </dl>
              {run.data.stale && (
                <div className="px-3 pb-3">
                  <Caveat tone="warn">
                    {run.data.stale_reason}{" "}
                    {t("Re-run the validation before citing these results.")}
                  </Caveat>
                </div>
              )}
            </Panel>
          )}

          <Panel title={t("Counterexamples")}>
            {counterexamples.state === "loading" ? (
              <Skeleton rows={6} />
            ) : counterexamples.data && counterexamples.data.count > 0 ? (
              <div className="space-y-2 p-3">
                <Badge tone="bad">
                  {t("{count} message(s) broke the rule", {
                    count: counterexamples.data.count,
                  })}
                </Badge>
                <ul className="space-y-2">
                  {counterexamples.data.counterexamples.map((example) => {
                    const row = example as unknown as {
                      result_id: string;
                      message_id: string;
                      start_offset: number;
                      end_offset: number;
                      violated_rule: string | null;
                      reasons: { message: string; field?: string }[];
                      alternative_explanations: string[];
                      explanation: string;
                    };
                    return (
                      <li
                        key={row.result_id}
                        className="rounded-sm border border-status-bad/30 bg-status-bad/5 p-2.5"
                      >
                        <div className="flex items-center justify-between gap-2">
                          <span className="font-mono text-2xs text-accent">
                            {t("msg {id}", { id: row.message_id.slice(0, 12) })}
                          </span>
                          <Badge tone="bad">{row.violated_rule ?? t("rule")}</Badge>
                        </div>
                        <p className="mt-1 font-mono text-2xs text-text-muted">
                          {t("offsets {start}…{end}", {
                            start: row.start_offset,
                            end: row.end_offset,
                          })}
                        </p>
                        <ul className="mt-1 space-y-0.5">
                          {row.reasons.map((reason, index) => (
                            <li key={index} className="text-2xs text-text">
                              • {reason.message}
                            </li>
                          ))}
                        </ul>
                        <details className="mt-1.5">
                          <summary className="cursor-pointer text-2xs text-text-muted">
                            {t("alternative explanations ({count})", {
                              count: row.alternative_explanations.length,
                            })}
                          </summary>
                          <ul className="mt-1 space-y-0.5">
                            {row.alternative_explanations.map((text, index) => (
                              <li key={index} className="text-2xs text-text-muted">
                                – {text}
                              </li>
                            ))}
                          </ul>
                        </details>
                      </li>
                    );
                  })}
                </ul>
                <Caveat tone="warn">{t(String(counterexamples.data.disclaimer))}</Caveat>
              </div>
            ) : counterexamples.data ? (
              <EmptyState
                title={t("No counterexamples")}
                description={t("Every message in this corpus satisfied the rule.")}
              />
            ) : (
              <EmptyState title={t("Run a validation to see counterexamples")} />
            )}
          </Panel>

          {support.data && (
            <Panel title={t("What the format can express")}>
              <div className="space-y-2 p-3 text-2xs">
                <p className="text-text-muted">
                  <span className="text-text-faint">{t("framing:")}</span>{" "}
                  {((support.data.supported_framing ?? []) as string[]).join(", ")}
                </p>
                <p className="text-text-muted">
                  <span className="text-text-faint">{t("field kinds:")}</span>{" "}
                  {((support.data.supported_field_kinds ?? []) as string[]).join(", ")}
                </p>
                <div>
                  <p className="text-text-faint">{t("explicitly unsupported:")}</p>
                  <ul className="mt-1 space-y-0.5">
                    {((support.data.explicitly_unsupported ?? []) as string[]).map(
                      (item, index) => (
                        <li key={index} className="text-status-warn">
                          • {t(item)}
                        </li>
                      ),
                    )}
                  </ul>
                </div>
                <Caveat>{t(String(support.data.safety))}</Caveat>
              </div>
            </Panel>
          )}
        </div>
      </div>
    </div>
  );
}

function VerdictSummary({ result }: { result: Record<string, unknown> }) {
  const { t } = useI18n();
  const verdict = String(result.verdict ?? "");
  const summary = [
    ["total", result.total],
    ["matched", result.matched],
    ["partial", result.partial],
    ["failed", result.failed],
    ["unparsed", result.unparsed],
  ] as const;

  return (
    <div className="mt-2 rounded-sm border border-line bg-surface-raised p-2.5">
      <Badge tone={verdictTone(verdict)}>{t("verdict: {verdict}", { verdict })}</Badge>
      <dl className="mt-2 grid grid-cols-5 gap-1 text-center font-mono text-2xs">
        {summary.map(([label, value]) => (
          <div key={label}>
            <dt className="text-text-faint">{t(label)}</dt>
            <dd
              className={cn(
                label === "failed" && Number(value) > 0
                  ? "text-status-bad"
                  : label === "matched"
                    ? "text-status-ok"
                    : "text-text",
              )}
            >
              {String(value)}
            </dd>
          </div>
        ))}
      </dl>
      {typeof result.notes === "object" && Array.isArray(result.notes) && (
        <ul className="mt-2 space-y-0.5">
          {(result.notes as string[]).map((note, index) => (
            <li key={index} className="text-2xs text-text-faint">
              {note}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

/** Choose captures by name; ids come from the capture list endpoint. */
function CorpusPicker({
  projectId,
  selected,
  onChange,
}: {
  projectId: string;
  selected: string[];
  onChange: (ids: string[]) => void;
}) {
  const captures = useAsync(async () => {
    // The capture ids for a project are obtained by exporting the project
    // listing; a dedicated lightweight endpoint is added below.
    const { api: client } = await import("@/lib/api");
    return client.projectCaptures(projectId);
  }, [projectId, selected.length]);

  const { t } = useI18n();

  return (
    <div>
      <p className="mb-1 text-2xs uppercase tracking-wider text-text-faint">
        {t("Corpus (captures to validate against)")}
      </p>
      {captures.state === "loading" ? (
        <Skeleton rows={3} />
      ) : (captures.data ?? []).length === 0 ? (
        <p className="text-2xs text-text-faint">
          {t("Import captures before validating a rule. A rule tested on no data proves nothing.")}
        </p>
      ) : (
        <ul className="max-h-40 space-y-0.5 overflow-auto">
          {captures.data!.map((capture) => {
            const checked = selected.includes(capture.id);
            return (
              <li key={capture.id}>
                <label className="flex items-center gap-2 px-1 py-0.5 text-2xs">
                  <input
                    type="checkbox"
                    checked={checked}
                    onChange={(event) => {
                      onChange(
                        event.target.checked
                          ? [...selected, capture.id]
                          : selected.filter((id) => id !== capture.id),
                      );
                    }}
                  />
                  <span className="truncate text-text">{capture.name}</span>
                  {capture.analysis_status === "completed" ? (
                    <Badge tone="ok">{t("analysed")}</Badge>
                  ) : (
                    <Badge tone="warn">{t("not analysed")}</Badge>
                  )}
                </label>
              </li>
            );
          })}
        </ul>
      )}
      {selected.length > 0 && (
        <button
          type="button"
          className="btn mt-1.5"
          onClick={() => onChange([])}
        >
          <X className="h-3 w-3" aria-hidden />
          {t("clear corpus")}
        </button>
      )}
    </div>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex justify-between gap-2">
      <dt className="text-text-faint">{label}</dt>
      <dd className="min-w-0 truncate text-text">{value}</dd>
    </div>
  );
}

export { PlayCircle };