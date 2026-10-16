"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";

import {
  Badge,
  Caveat,
  ConfirmButton,
  EmptyState,
  ErrorState,
  Panel,
  Skeleton,
} from "@/components/ui";
import { useAction, useAsync } from "@/hooks/use-async";
import { useProtocolFilter } from "@/hooks/use-protocol-filter";
import { useWorkspace } from "@/hooks/use-workspace";
import { api } from "@/lib/api";
import { useI18n, useStreamingBoundary } from "@/lib/i18n";

/** ISO timestamps are shown in the active locale, never as a raw string. */
function formatIsoDate(value: string, locale: "en" | "ru"): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat(locale === "ru" ? "ru-RU" : "en-US", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  }).format(date);
}

export default function ProjectSettingsPage() {
  const workspace = useWorkspace();
  const router = useRouter();
  const { t, locale } = useI18n();
  // Joins the shell's streaming boundary: a page that never suspends would
  // otherwise render into the fallback and the client would never replace it.
  useStreamingBoundary();
  const projectId = workspace.projectId;
  const protocolFilter = useProtocolFilter();

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
  const remove = useAction();

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
          title={t("No project selected")}
          description={t(
            "Project Settings apply to one project. Create or select a project first.",
          )}
          action={
            <Link href="/" className="btn btn-primary">
              {t("Go to Overview")}
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
  const hiddenProtocols = Array.from(protocolFilter.hidden).sort((a, b) => a.localeCompare(b));

  const deleteProject = async () => {
    const ok = await remove.run(
      async () => {
        await api.deleteProject(projectId);
        return true;
      },
      t("Project deleted."),
    );
    if (!ok) return;
    workspace.clearProject();
    workspace.invalidate();
    router.push("/");
  };

  return (
    <div className="flex h-full flex-col">
      <div className="border-b border-line px-4 py-3">
        <h1 className="text-sm font-semibold tracking-tight text-text">
          {t("Project Settings")}
        </h1>
        <p className="mt-0.5 max-w-3xl text-2xs leading-relaxed text-text-muted">
          {t(
            "Identity, integrity and the per-project consent that governs optional external AI. Nothing here changes how packets are analysed.",
          )}
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
            <Panel title={t("Identity")}>
              <form
                className="space-y-3 p-3"
                onSubmit={(event) => {
                  event.preventDefault();
                  void save
                    .run(
                      () => api.updateProject(projectId, { name, description }),
                      t("Project saved."),
                    )
                    .then(() => {
                      project.reload();
                      workspace.invalidate();
                    });
                }}
              >
                <label className="block">
                  <span className="text-2xs uppercase tracking-wider text-text-faint">
                    {t("Name")}
                  </span>
                  <input
                    className="input mt-1 w-full"
                    value={name}
                    maxLength={200}
                    onChange={(event) => setName(event.target.value)}
                  />
                </label>
                <label className="block">
                  <span className="text-2xs uppercase tracking-wider text-text-faint">
                    {t("Description")}
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
                    {save.pending ? t("Saving…") : t("Save")}
                  </button>
                  <span className="font-mono text-2xs text-text-faint">
                    {t("id: {id}", { id: project.data.id })}
                  </span>
                  <Badge tone="neutral">
                    {t("schema v{version}", { version: project.data.schema_version })}
                  </Badge>
                  <span className="text-2xs text-text-faint">
                    {t("updated {time}", {
                      time: formatIsoDate(project.data.updated_at, locale),
                    })}
                  </span>
                </div>
                {save.error ? <p className="text-2xs text-status-bad">{save.error}</p> : null}
                {save.notice ? <p className="text-2xs text-status-ok">{save.notice}</p> : null}
              </form>
            </Panel>

            <Panel
              title={t("Protocols")}
              actions={
                hiddenProtocols.length > 0 ? (
                  <button type="button" className="btn" onClick={protocolFilter.showAll}>
                    {t("Show all")}
                  </button>
                ) : undefined
              }
            >
              <div className="space-y-2 p-3">
                <p className="max-w-3xl text-2xs leading-relaxed text-text-muted">
                  {t(
                    "Detected protocol labels you have hidden. They are removed from the network graph and the stream list. Hiding changes what is shown, not what was analysed — the data stays available by showing the label again.",
                  )}
                </p>
                {hiddenProtocols.length === 0 ? (
                  <p className="text-2xs text-text-faint">{t("No protocols hidden.")}</p>
                ) : (
                  <ul className="flex flex-wrap gap-1.5">
                    {hiddenProtocols.map((label) => (
                      <li key={label}>
                        <button
                          type="button"
                          className="tag border-line-strong bg-surface-raised text-text-muted hover:border-line-strong"
                          onClick={() => protocolFilter.toggle(label)}
                          title={t("Show this protocol again")}
                        >
                          <span className="font-mono">{label}</span>
                          <span aria-hidden>×</span>
                        </button>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </Panel>

            <Panel title={t("External AI")}>
              <div className="space-y-2 p-3">
                <div className="flex flex-wrap items-center gap-2">
                  <Badge tone={externalAi.enabled ? "warn" : "ok"}>
                    {t("server: {state}", {
                      state: externalAi.enabled
                        ? t("external AI enabled")
                        : t("external AI disabled"),
                    })}
                  </Badge>
                  <Badge tone={projectConsent ? "warn" : "neutral"}>
                    {t("this project: consent {state}", {
                      state: projectConsent ? t("given") : t("not given"),
                    })}
                  </Badge>
                  {externalAi.provider ? (
                    <Badge tone="info">
                      {t("provider: {provider}", { provider: externalAi.provider })}
                    </Badge>
                  ) : null}
                </div>
                <p className="max-w-3xl text-2xs leading-relaxed text-text-muted">
                  {t(
                    "External AI is off by default. Report generation can only use a model when the server operator has enabled it and this project records consent. Even then the model only narrates already-validated findings; it never runs queries, reads files, or sees raw packet bytes or secrets.",
                  )}
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
                          () =>
                            api.updateProject(projectId, {
                              settings: { allow_external_ai: value },
                            }),
                          value
                            ? t("Consent recorded for this project.")
                            : t("Consent withdrawn for this project."),
                        )
                        .then(() => {
                          project.reload();
                          workspace.invalidate();
                        });
                    }}
                  />
                  {t("Allow external AI for this project")}
                </label>
                {consent.error ? <p className="text-2xs text-status-bad">{consent.error}</p> : null}
                {consent.notice ? <p className="text-2xs text-status-ok">{consent.notice}</p> : null}
                {!externalAi.enabled ? (
                  <Caveat>
                    {t(
                      "The server-level switch is off, so this consent alone cannot send anything anywhere. Set MPLAB_ALLOW_EXTERNAL_AI=true (and run a local Ollama) to make the consent effective.",
                    )}
                  </Caveat>
                ) : null}
              </div>
            </Panel>

            <Panel
              title={t("Capture integrity")}
              actions={
                <button type="button" className="btn" onClick={integrity.reload}>
                  {t("Re-verify")}
                </button>
              }
            >
              <div className="space-y-2 p-3">
                {integrity.state === "loading" ? (
                  <Skeleton rows={3} />
                ) : integrity.data ? (
                  <>
                    <Badge tone={integrityOk ? "ok" : "warn"}>
                      {integrityOk ? t("hashes verified") : t("needs attention")}
                    </Badge>
                    <pre className="max-h-64 overflow-auto rounded-sm border border-line bg-surface-sunken p-2 font-mono text-2xs text-text-muted">
                      {JSON.stringify(integrity.data, null, 2)}
                    </pre>
                  </>
                ) : (
                  <EmptyState title={t("No integrity result")} />
                )}
              </div>
            </Panel>

            <Panel
              title={
                <span className="text-status-bad">{t("Danger zone")}</span>
              }
            >
              <div className="space-y-2 p-3">
                <p className="max-w-3xl text-2xs leading-relaxed text-text-muted">
                  {t(
                    "Deleting a project removes its captures, packets, sessions, hypotheses and reports from this workspace. This cannot be undone.",
                  )}
                </p>
                <div className="flex flex-wrap items-center gap-2">
                  <ConfirmButton
                    label={t("Delete project")}
                    confirmLabel={t("Delete project permanently?")}
                    onConfirm={deleteProject}
                    disabled={remove.pending}
                  />
                  {remove.pending ? (
                    <span className="text-2xs text-text-faint">{t("Deleting…")}</span>
                  ) : null}
                </div>
                {remove.error ? <p className="text-2xs text-status-bad">{remove.error}</p> : null}
              </div>
            </Panel>
          </div>
        ) : null}
      </div>
    </div>
  );
}
