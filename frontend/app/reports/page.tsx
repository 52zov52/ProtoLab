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

type Section = {
  number: number;
  title: string;
  body: string;
  evidence: { kind: string; id: string }[];
  notes: string[];
};

export default function ReportsPage() {
  const workspace = useWorkspace();
  const params = useSearchParams();
  const projectId = params.get("project") ?? workspace.projectId;
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const action = useAction();

  const reports = useAsync(
    () => (projectId ? api.reports(projectId) : Promise.resolve([])),
    [projectId, workspace.revision],
  );

  const current = useAsync(
    () => (selectedId ? api.getReport(selectedId) : Promise.resolve(null)),
    [selectedId],
  );

  if (!projectId) {
    return (
      <div className="p-4">
        <EmptyState title="No project selected" />
      </div>
    );
  }

  return (
    <div className="flex h-full flex-col">
      <div className="flex shrink-0 items-start justify-between gap-4 border-b border-line px-4 py-3">
        <div>
          <h1 className="text-sm font-semibold tracking-tight text-text">Reports</h1>
          <p className="mt-0.5 max-w-3xl text-2xs leading-relaxed text-text-muted">
            Every section is assembled from stored facts and lists the evidence it came
            from. A report can be produced entirely offline, without any language model.
          </p>
        </div>
        <button
          type="button"
          className="btn btn-primary"
          disabled={action.pending}
          onClick={async () => {
            const created = await action.run(() =>
              api.report(projectId, { title: "Investigation report" }),
            );
            if (created) {
              setSelectedId(String(created.report_id));
              workspace.invalidate();
            }
          }}
        >
          {action.pending ? "Generating…" : "Generate report"}
        </button>
      </div>

      <div className="grid min-h-0 flex-1 grid-cols-1 gap-3 overflow-hidden p-3 lg:grid-cols-[280px_1fr]">
        <Panel title="Generated reports">
          {reports.state === "loading" ? (
            <Skeleton rows={5} />
          ) : (reports.data ?? []).length === 0 ? (
            <EmptyState title="No reports yet" />
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
                        {row.ai_used && <Badge tone="warn">AI used</Badge>}
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
          title="Report"
          actions={
            selectedId && (
              <div className="flex gap-2">
                <a
                  className="btn"
                  href={`${api.constructor === Object ? "" : ""}`}
                  onClick={(event) => {
                    event.preventDefault();
                    window.open(
                      `${location.origin}/api/reports/${selectedId}/markdown`,
                      "_blank",
                    );
                  }}
                >
                  Markdown
                </a>
                <a
                  className="btn"
                  href="#json"
                  onClick={(event) => {
                    event.preventDefault();
                    window.open(`${location.origin}/api/reports/${selectedId}/json`, "_blank");
                  }}
                >
                  JSON
                </a>
              </div>
            )
          }
        >
          {!selectedId ? (
            <EmptyState
              title="No report selected"
              description="Generate a report to see the investigation written out with its evidence."
            />
          ) : current.state === "loading" ? (
            <Skeleton rows={14} />
          ) : current.data ? (
            <ReportView report={current.data as Record<string, unknown>} />
          ) : null}
        </Panel>
      </div>
    </div>
  );
}

function ReportView({ report }: { report: Record<string, unknown> }) {
  const sections = (report.sections ?? []) as Section[];
  const warnings = (report.ai_warnings ?? []) as string[];

  return (
    <div className="space-y-4 p-4">
      <div>
        <h2 className="text-sm font-semibold text-text">{String(report.title)}</h2>
        <p className="mt-0.5 text-2xs text-text-faint">
          generator: {String(report.generator)} · created{" "}
          {new Date(String(report.created_at)).toISOString().slice(0, 19)}
        </p>
      </div>

      {report.ai_used === true && (
        <div className="rounded-sm border border-status-warn/30 bg-status-warn/5 p-2.5">
          <Badge tone="warn">a language model contributed to this report</Badge>
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
            <p className="mt-1 font-mono text-2xs text-text-faint">
              evidence:{" "}
              {section.evidence
                .slice(0, 8)
                .map((item) => `${item.kind}:${item.id.slice(0, 10)}`)
                .join("  ")}
              {section.evidence.length > 8 ? `  (+${section.evidence.length - 8})` : ""}
            </p>
          )}
          {section.notes.map((note, index) => (
            <Caveat key={index}>{note}</Caveat>
          ))}
        </section>
      ))}
    </div>
  );
}