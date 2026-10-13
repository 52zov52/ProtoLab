"use client";

import { useRef, useState } from "react";

import { Badge, ConfirmButton, EmptyState, Panel } from "@/components/ui";
import { useAsync, useAction } from "@/hooks/use-async";
import { useWorkspace } from "@/hooks/use-workspace";
import { api } from "@/lib/api";
import { cn, formatBytes, formatTimestamp } from "@/lib/format";
import { useI18n } from "@/lib/i18n";

/** Project selector + creation form. Persisted in the workspace context. */
export function ProjectPicker() {
  const workspace = useWorkspace();
  const { t } = useI18n();
  const projects = useAsync(() => api.listProjects(), [workspace.revision]);
  const action = useAction();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");

  const create = async () => {
    if (!name.trim()) return;
    const created = await action.run(
      () => api.createProject(name.trim(), description.trim()),
      t('Project "{name}" created.', { name: name.trim() }),
    );
    if (created) {
      workspace.selectProject(created.id, created.name);
      workspace.invalidate();
      setName("");
      setDescription("");
      projects.reload();
    }
  };

  const adopt = (id: string) => {
    const project = projects.data?.find((p) => p.id === id);
    if (project) {
      workspace.selectProject(project.id, project.name);
      workspace.invalidate();
    }
  };

  const remove = useAction();
  const deleteProject = async (id: string, displayName: string) => {
    const ok = await remove.run(
      async () => {
        await api.deleteProject(id);
        return true;
      },
      t('Project "{name}" deleted.', { name: displayName }),
    );
    // `run` resolves to null only when the request failed.
    if (!ok) return;
    if (workspace.projectId === id) workspace.clearProject();
    workspace.invalidate();
    projects.reload();
  };

  return (
    <Panel
      title={t("Investigation project")}
      actions={
        projects.state === "loading" ? (
          <span className="text-2xs text-text-faint">{t("loading…")}</span>
        ) : (
          <button type="button" className="btn" onClick={projects.reload}>
            {t("Refresh")}
          </button>
        )
      }
    >
      <div className="p-3">
        {projects.state === "error" && (
          <p className="mb-3 rounded-sm border border-status-bad/40 bg-status-bad/5 p-2 font-mono text-2xs text-status-bad">
            {projects.error}
          </p>
        )}

        {projects.data && projects.data.length === 0 && (
          <EmptyState
            title={t("No projects yet")}
            description={t(
              "Create an investigation project, then import a PCAP capture to begin.",
            )}
          />
        )}

        <ul className="space-y-1">
          {(projects.data ?? []).map((project) => {
            const active = project.id === workspace.projectId;
            return (
              <li
                key={project.id}
                className={cn(
                  "flex items-stretch gap-1 rounded-sm border transition-colors",
                  active
                    ? "border-accent-dim bg-accent-faint"
                    : "border-line bg-surface-raised hover:border-line-strong",
                )}
              >
                <button
                  type="button"
                  onClick={() => adopt(project.id)}
                  aria-current={active ? "true" : undefined}
                  className="flex min-w-0 flex-1 items-center justify-between gap-3 px-2.5 py-2 text-left"
                >
                  <span className="min-w-0">
                    <span
                      className={cn(
                        "block truncate text-xs font-medium",
                        active ? "text-accent" : "text-text",
                      )}
                    >
                      {project.name}
                    </span>
                    <span className="mt-0.5 block font-mono text-2xs text-text-faint">
                      {t("{captures} capture(s) · {messages} message(s) · {hypotheses} hypothesis/hypotheses", {
                        captures: project.capture_count,
                        messages: project.message_count,
                        hypotheses: project.hypothesis_count,
                      })}
                    </span>
                  </span>
                  {active && <Badge tone="info">{t("current")}</Badge>}
                </button>
                <div className="flex shrink-0 items-center pr-1.5">
                  <ConfirmButton
                    label={t("Delete")}
                    confirmLabel={t("Delete project?")}
                    onConfirm={() => deleteProject(project.id, project.name)}
                    disabled={remove.pending}
                  />
                </div>
              </li>
            );
          })}
        </ul>

        <div className="mt-4 border-t border-line pt-3">
          <p className="mb-2 text-2xs uppercase tracking-wider text-text-faint">
            {t("New project")}
          </p>
          <input
            className="input"
            placeholder={t("Project name")}
            value={name}
            maxLength={200}
            onChange={(event) => setName(event.target.value)}
          />
          <textarea
            className="input mt-1.5 h-16 resize-y"
            placeholder={t("What is the investigation trying to establish?")}
            value={description}
            maxLength={20000}
            onChange={(event) => setDescription(event.target.value)}
          />
          <button
            type="button"
            className="btn btn-primary mt-2"
            disabled={!name.trim() || action.pending}
            onClick={create}
          >
            {action.pending ? t("Creating…") : t("Create project")}
          </button>
          {action.notice && (
            <p className="mt-2 text-2xs text-status-ok">{action.notice}</p>
          )}
          {action.error && <p className="mt-2 text-2xs text-status-bad">{action.error}</p>}
          {remove.notice && (
            <p className="mt-2 text-2xs text-status-ok" role="status">
              {remove.notice}
            </p>
          )}
          {remove.error && (
            <p className="mt-2 text-2xs text-status-bad" role="alert">
              {remove.error}
            </p>
          )}
        </div>
      </div>
    </Panel>
  );
}

/** Capture selector, scoped to the current project. */
export function CapturePicker({ onSelect }: { onSelect?: (id: string) => void }) {
  const workspace = useWorkspace();
  const { t } = useI18n();
  const [busy, setBusy] = useState(false);
  const fileInput = useRef<HTMLInputElement>(null);

  const sessions = useAsync(
    async () => {
      if (!workspace.captureId) return null;
      return api.listSessions(workspace.captureId);
    },
    [workspace.captureId, workspace.revision],
  );

  const capture = useAsync(
    async () => {
      if (!workspace.captureId) return null;
      return api.getCapture(workspace.captureId);
    },
    [workspace.captureId, workspace.revision],
  );

  const importFile = async (file: File) => {
    if (!workspace.projectId) return;
    setBusy(true);
    try {
      const imported = await api.importCapture(workspace.projectId, file, file.name);
      workspace.selectCapture(imported.id);
      workspace.invalidate();
      onSelect?.(imported.id);
    } catch (error) {
      window.alert(
        error instanceof Error
          ? error.message
          : t(
              "The capture could not be imported. See the Security Center for the active limits.",
            ),
      );
    } finally {
      setBusy(false);
    }
  };

  return (
    <Panel title={t("Selected capture")}>
      <div className="space-y-2 p-3">
        {!workspace.captureId && (
          <EmptyState
            title={t("No capture selected")}
            description={t(
              "Import a PCAP or PCAPNG file to start. The original bytes are stored immutably and hashed.",
            )}
            action={
              <button
                type="button"
                className="btn btn-primary"
                disabled={!workspace.projectId || busy}
                onClick={() => fileInput.current?.click()}
              >
                {busy ? t("Importing…") : t("Import PCAP")}
              </button>
            }
          />
        )}

        <input
          ref={fileInput}
          type="file"
          accept=".pcap,.pcapng,.cap"
          className="hidden"
          onChange={(event) => {
            const file = event.target.files?.[0];
            if (file) void importFile(file);
            event.target.value = "";
          }}
        />

        {workspace.captureId && capture.data && (
          <div className="space-y-1.5 font-mono text-2xs">
            <Row label={t("name")} value={capture.data.name} />
            <Row label={t("format")} value={capture.data.format} />
            <Row label={t("size")} value={formatBytes(capture.data.file_size)} />
            <Row label={t("sha256")} value={`${capture.data.sha256.slice(0, 32)}…`} />
            <Row
              label={t("imported")}
              value={formatTimestamp(Date.parse(capture.data.imported_at) / 1000)}
            />
            <Row label={t("analysis")} value={capture.data.analysis_status} />
          </div>
        )}

        {sessions.data && (
          <p className="border-t border-line pt-2 text-2xs text-text-muted">
            {t("{count} TCP session(s) in this capture.", { count: sessions.data.total })}
          </p>
        )}

        {workspace.captureId && (
          <button
            type="button"
            className="btn w-full"
            disabled={!workspace.projectId || busy}
            onClick={() => fileInput.current?.click()}
          >
            {t("Import another capture")}
          </button>
        )}
      </div>
    </Panel>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex gap-2">
      <span className="w-20 shrink-0 text-text-faint">{label}</span>
      <span className="min-w-0 break-all text-text">{value}</span>
    </div>
  );
}