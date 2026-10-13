"use client";

import { useRouter, useSearchParams } from "next/navigation";
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
import { API_BASE, api } from "@/lib/api";
import {
  evidenceTarget,
  shortId,
  type EvidenceItem,
} from "@/lib/evidence-links";
import { useI18n } from "@/lib/i18n";

type Section = {
  number: number;
  title: string;
  body: string;
  evidence: EvidenceItem[];
  notes: string[];
};

export default function ReportsPage() {
  const workspace = useWorkspace();
  const { t } = useI18n();
  const params = useSearchParams();
  const projectId = params.get("project") ?? workspace.projectId;
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [useLlm, setUseLlm] = useState(false);
  const action = useAction();

  const reports = useAsync(
    () => (projectId ? api.reports(projectId) : Promise.resolve([])),
    [projectId, workspace.revision],
  );

  const aiInfo = useAsync(() => api.assistantCapabilities(), []);

  const current = useAsync(
    () => (selectedId ? api.getReport(selectedId) : Promise.resolve(null)),
    [selectedId],
  );

  if (!projectId) {
    return (
      <div className="p-4">
        <EmptyState title={t("No project selected")} />
      </div>
    );
  }

  return (
    <div className="flex h-full flex-col">
      <div className="flex shrink-0 items-start justify-between gap-4 border-b border-line px-4 py-3">
        <div>
          <h1 className="text-sm font-semibold tracking-tight text-text">{t("Reports")}</h1>
          <p className="mt-0.5 max-w-3xl text-2xs leading-relaxed text-text-muted">
            {t(
              "Every section is assembled from stored facts and lists the evidence it came from. A report can be produced entirely offline, without any language model.",
            )}
          </p>
        </div>
        <div className="flex shrink-0 flex-col items-end gap-1.5">
          <div className="flex items-center gap-3">
            <label className="flex cursor-pointer items-center gap-1.5 text-2xs text-text-muted">
              <input
                type="checkbox"
                checked={useLlm}
                onChange={(event) => setUseLlm(event.target.checked)}
              />
              {t("narrate with local model")}
            </label>
            <button
              type="button"
              className="btn btn-primary"
              disabled={action.pending}
              onClick={async () => {
                const created = await action.run(() =>
                  api.report(projectId, {
                    title: t("Investigation report"),
                    use_llm: useLlm,
                  }),
                );
                if (created) {
                  setSelectedId(String(created.report_id));
                  workspace.invalidate();
                }
              }}
            >
              {action.pending ? t("Generating…") : t("Generate report")}
            </button>
          </div>
          {useLlm && aiInfo.data ? (
            (() => {
              const enabled = Boolean(
                ((aiInfo.data as Record<string, unknown>).external_ai as
                  | { enabled?: boolean }
                  | undefined)?.enabled,
              );
              return enabled ? (
                <p className="text-2xs text-text-faint">
                  {t(
                    "Server switch is on; the report will still be produced if the model cannot narrate in time.",
                  )}
                </p>
              ) : (
                <p className="text-2xs text-status-warn">
                  {t("External AI is disabled on this server, so the checkbox has no effect.")}
                </p>
              );
            })()
          ) : null}
        </div>
      </div>

      <div className="grid min-h-0 flex-1 grid-cols-1 gap-3 overflow-hidden p-3 lg:grid-cols-[280px_1fr]">
        <Panel title={t("Generated reports")}>
          {reports.state === "loading" ? (
            <Skeleton rows={5} />
          ) : (reports.data ?? []).length === 0 ? (
            <EmptyState title={t("No reports yet")} />
          ) : (
            <ul>
              {(reports.data as Record<string, unknown>[]).map((report) => {
                const row = report as unknown as {
                  id: string;
                  title: string;
                  created_at: string;
                  ai_used: boolean;
                };
                return (
                  <li key={row.id}>
                    <button
                      type="button"
                      onClick={() => setSelectedId(row.id)}
                      className={`w-full border-b border-line/60 px-3 py-2 text-left ${
                        selectedId === row.id ? "bg-accent-faint" : "hover:bg-surface-raised"
                      }`}
                    >
                      <span className="block truncate text-2xs text-text">{row.title}</span>
                      <span className="mt-0.5 flex items-center gap-2 text-2xs text-text-faint">
                        {new Date(row.created_at).toISOString().slice(0, 19)}
                        {row.ai_used && <Badge tone="warn">{t("AI used")}</Badge>}
                      </span>
                    </button>
                  </li>
                );
              })}
            </ul>
          )}
          {action.error && (
            <p className="p-3 font-mono text-2xs text-status-bad">{action.error}</p>
          )}
        </Panel>

        <Panel
          title={t("Report")}
          actions={
            selectedId && (
              <div className="flex gap-2">
                <a
                  className="btn"
                  href={`${API_BASE}/api/reports/${selectedId}/markdown`}
                  target="_blank"
                  rel="noreferrer"
                >
                  {t("Markdown")}
                </a>
                <a
                  className="btn"
                  href={`${API_BASE}/api/reports/${selectedId}/json`}
                  target="_blank"
                  rel="noreferrer"
                >
                  {t("JSON")}
                </a>
              </div>
            )
          }
        >
          {!selectedId ? (
            <EmptyState
              title={t("No report selected")}
              description={t(
                "Generate a report to see the investigation written out with its evidence.",
              )}
            />
          ) : current.state === "loading" ? (
            <Skeleton rows={14} />
          ) : current.data ? (
            <ReportView
              report={current.data as Record<string, unknown>}
              projectId={projectId}
            />
          ) : null}
        </Panel>
      </div>
    </div>
  );
}

function ReportView({
  report,
  projectId,
}: {
  report: Record<string, unknown>;
  projectId: string;
}) {
  const workspace = useWorkspace();
  const router = useRouter();
  const { t } = useI18n();
  const sections = (report.sections ?? []) as Section[];
  const warnings = (report.ai_warnings ?? []) as string[];

  const openEvidence = (item: EvidenceItem) => {
    const target = evidenceTarget(item, projectId);
    if (!target.href) return;
    if (target.select === "session") workspace.selectSession(item.id);
    if (target.select === "capture") workspace.selectCapture(item.id);
    router.push(target.href);
  };

  return (
    <div className="space-y-4 p-4">
      <div>
        <h2 className="text-sm font-semibold text-text">{String(report.title)}</h2>
        <p className="mt-0.5 text-2xs text-text-faint">
          {t("generator: {generator} · created {created}", {
            generator: String(report.generator),
            created: new Date(String(report.created_at)).toISOString().slice(0, 19),
          })}
        </p>
      </div>

      {report.ai_used === true && (
        <div className="rounded-sm border border-status-warn/30 bg-status-warn/5 p-2.5">
          <Badge tone="warn">{t("a language model contributed to this report")}</Badge>
          {warnings.map((warning, index) => (
            <Caveat key={index} tone="warn">
              {warning}
            </Caveat>
          ))}
        </div>
      )}
      {report.ai_used === false && warnings.length > 0 && (
        <div className="space-y-1">
          {warnings.map((warning, index) => (
            <Caveat key={index}>{warning}</Caveat>
          ))}
        </div>
      )}

      {sections.map((section) => (
        <section key={section.number}>
          <h3 className="text-xs font-semibold text-accent">
            {section.number}. {section.title}
          </h3>
          <div className="sanitized-markdown mt-1 text-2xs text-text">
            {section.body.split("\n").map((line, index) => (
              <p key={index}>{line || " "}</p>
            ))}
          </div>
          {section.evidence.length > 0 && (
            <div className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-1 font-mono text-2xs text-text-faint">
              <span>{t("evidence:")}</span>
              {section.evidence.slice(0, 8).map((item) => {
                const target = evidenceTarget(item, projectId);
                const text = `${target.label}:${shortId(item.id)}`;
                const key = `${item.kind}:${item.id}`;
                return target.href ? (
                  <button
                    key={key}
                    type="button"
                    className="cursor-pointer underline decoration-dotted underline-offset-2 hover:text-accent"
                    title={t("open {label} {id}", { label: target.label, id: item.id })}
                    onClick={() => openEvidence(item)}
                  >
                    {text}
                  </button>
                ) : (
                  <span key={key} title={`${item.kind} ${item.id}`}>
                    {text}
                  </span>
                );
              })}
              {section.evidence.length > 8 ? (
                <span>+{section.evidence.length - 8}</span>
              ) : null}
            </div>
          )}
          {section.notes.map((note, index) => (
            <Caveat key={index}>{note}</Caveat>
          ))}
        </section>
      ))}
    </div>
  );
}