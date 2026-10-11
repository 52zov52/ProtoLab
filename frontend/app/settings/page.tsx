"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

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

export default function ProjectSettingsPage() {
  const workspace = useWorkspace();
  const projectId = workspace.projectId;

  const project = useAsync(
    () => (projectId ? api.getProject(projectId) : Promise.resolve(null)),
    [projectId, workspace.revision],
  );
  const capabilities = useAsync(() => api.assistantCapabilities(), []);
  const integrity = useAsync(
    () => (projectId ? api.integrity(projectId) : Promise.resolve(null)),
    [projectId, workspace.revision],
  );

  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const save = useAction();
  const consent = useAction();

  useEffect(() => {
    if (project.data) {
      setName(project.data.name);
      setDescription(project.data.description);
    }
  }, [project.data]);

  if (!projectId) {
    return (
      <div className="p-4">
        <EmptyState
          title="No project selected"
          description="Project Settings apply to one project. Create or select a project first."
          action={
            <Link href="/" className="btn btn-primary">
              Go to Overview
            </Link>
          }
        />
      </div>
    );
  }

  const externalAi = (capabilities.data?.external_ai ?? {}) as {
    enabled?: boolean;
    provider?: string | null;
  };
  const projectConsent = Boolean(
    (project.data?.settings as Record<string, unknown> | undefined)?.allow_external_ai,
  );
  const integrityBody = (integrity.data ?? {}) as Record<string, unknown>;
  const integrityOk = integrityBody.ok === true || integrityBody.intact === true;

  return (
    <div className="flex h-full flex-col">
      <div className="border-b border-line px-4 py-3">
        <h1 className="text-sm font-semibold tracking-tight text-text">Project Settings</h1>
        <p className="mt-0.5 max-w-3xl text-2xs leading-relaxed text-text-muted">
          Identity, integrity and the per-project consent that governs optional external
          AI. Nothing here changes how packets are analysed.
        </p>
      </div>

      <div className="min-h-0 flex-1 overflow-auto p-3">
        {project.state === "error" ? (
          <Panel>
            <ErrorState message={project.error ?? ""} onRetry={project.reload} />
          </Panel>
        ) : project.state === "loading" ? (
          <Panel>
            <Skeleton rows={6} />
          </Panel>
        ) : project.data ? (
          <div className="flex flex-col gap-3">
            <Panel title="Identity">
              <form
                className="space-y-3 p-3"
                onSubmit={(event) => {
                  event.preventDefault();
                  void save
                    .run(
                      () =>
                        api.updateProject(projectId, { name, description }),
                      "Project saved.",
                    )
                    .then(() => {
                      project.reload();
                      workspace.invalidate();
                    });
                }}
              >
                <label className="block">
                  <span className="text-2xs uppercase tracking-wider text-text-faint">Name</span>
                  <input
                    className="input mt-1 w-full"
                    value={name}
                    maxLength={200}
                    onChange={(event) => setName(event.target.value)}
                  />
                </label>
                <label className="block">
                  <span className="text-2xs uppercase tracking-wider text-text-faint">
                    Description
                  </span>
                  <textarea
                    className="input mt-1 w-full font-mono text-2xs"
                    rows={3}
                    value={description}
                    onChange={(event) => setDescription(event.target.value)}
                  />
                </label>
                <div className="flex flex-wrap items-center gap-2">
                  <button
                    type="submit"
                    className="btn btn-primary"
                    disabled={save.pending || name.trim().length === 0}
                  >
                    {save.pending ? "Saving…" : "Save"}
                  </button>
                  <span className="font-mono text-2xs text-text-faint">id: {project.data.id}</span>
                  <Badge tone="neutral">schema v{project.data.schema_version}</Badge>
                  <span className="text-2xs text-text-faint">
                    updated {new Date(project.data.updated_at).toLocaleString()}
                  </span>
                </div>
                {save.error ? <p className="text-2xs text-status-bad">{save.error}</p> : null}
                {save.notice ? <p className="text-2xs text-status-ok">{save.notice}</p> : null}
              </form>
            </Panel>

            <Panel title="External AI">
              <div className="space-y-2 p-3">
                <div className="flex flex-wrap items-center gap-2">
                  <Badge tone={externalAi.enabled ? "warn" : "ok"}>
                    server: {externalAi.enabled ? "external AI enabled" : "external AI disabled"}
                  </Badge>
                  <Badge tone={projectConsent ? "warn" : "neutral"}>
                    this project: consent {projectConsent ? "given" : "not given"}
                  </Badge>
                  {externalAi.provider ? (
                    <Badge tone="info">provider: {externalAi.provider}</Badge>
                  ) : null}
                </div>
                <p className="max-w-3xl text-2xs leading-relaxed text-text-muted">
                  External AI is off by default. Report generation can only use a model when
                  the server operator has enabled it <em>and</em> this project records consent.
                  Even then the model only narrates already-validated findings; it never runs
                  queries, reads files, or sees raw packet bytes or secrets.
                </p>
                <label className="flex cursor-pointer items-center gap-2 text-xs text-text">
                  <input
                    type="checkbox"
                    checked={projectConsent}
                    disabled={consent.pending}
                    onChange={(event) => {
                      const value = event.target.checked;
                      void consent
                        .run(
                          () => api.updateProject(projectId, { settings: { allow_external_ai: value } }),
                          value
                            ? "Consent recorded for this project."
                            : "Consent withdrawn for this project.",
                        )
                        .then(() => {
                          project.reload();
                          workspace.invalidate();
                        });
                    }}
                  />
                  Allow external AI for this project
                </label>
                {consent.error ? <p className="text-2xs text-status-bad">{consent.error}</p> : null}
                {consent.notice ? <p className="text-2xs text-status-ok">{consent.notice}</p> : null}
                {!externalAi.enabled ? (
                  <Caveat>
                    The server-level switch is off, so this consent alone cannot send anything
                    anywhere. Set <code className="font-mono">MPLAB_ALLOW_EXTERNAL_AI=true</code>{" "}
                    (and run a local Ollama) to make the consent effective.
                  </Caveat>
                ) : null}
              </div>
            </Panel>

            <Panel
              title="Capture integrity"
              actions={
                <button type="button" className="btn" onClick={integrity.reload}>
                  Re-verify
                </button>
              }
            >
              <div className="space-y-2 p-3">
                {integrity.state === "loading" ? (
                  <Skeleton rows={3} />
                ) : integrity.data ? (
                  <>
                    <Badge tone={integrityOk ? "ok" : "warn"}>
                      {integrityOk ? "hashes verified" : "needs attention"}
                    </Badge>
                    <pre className="max-h-64 overflow-auto rounded-sm border border-line bg-surface-sunken p-2 font-mono text-2xs text-text-muted">
                      {JSON.stringify(integrity.data, null, 2)}
                    </pre>
                  </>
                ) : (
                  <EmptyState title="No integrity result" />
                )}
              </div>
            </Panel>
          </div>
        ) : null}
      </div>
    </div>
  );
}
