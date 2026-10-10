"use client";

import { useEffect, useRef, useState } from "react";

import { Badge, EmptyState, Panel } from "@/components/ui";
import { useAsync, useAction } from "@/hooks/use-async";
import { useWorkspace } from "@/hooks/use-workspace";
import { api } from "@/lib/api";
import { cn, formatBytes, formatTimestamp } from "@/lib/format";

/** Project selector + creation form. Persisted in the workspace context. */
export function ProjectPicker() {
  const workspace = useWorkspace();
  const projects = useAsync(() => api.listProjects(), [workspace.revision]);
  const action = useAction();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");

  const create = async () => {
    if (!name.trim()) return;
    const created = await action.run(
      () => api.createProject(name.trim(), description.trim()),
      `Project "${name.trim()}" created.`,
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

  return (
    <Panel
      title="Investigation project"
      actions={
        projects.state === "loading" ? (
          <span className="text-2xs text-text-faint">loading…</span>
        ) : (
          <button type="button" className="btn" onClick={projects.reload}>
            Refresh
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
            title="No projects yet"
            description="Create an investigation project, then import a PCAP capture to begin."
          />
        )}

        <ul className="space-y-1">
          {(projects.data ?? []).map((project) => {
            const active = project.id === workspace.projectId;
            return (
              <li key={project.id}>
                <button
                  type="button"
                  onClick={() => adopt(project.id)}
                  aria-current={active ? "true" : undefined}
                  className={cn(
                    "flex w-full items-center justify-between gap-3 rounded-sm border px-2.5 py-2 text-left transition-colors",
                    active
                      ? "border-accent-dim bg-accent-faint"
                      : "border-line bg-surface-raised hover:border-line-strong",
                  )}
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
                      {project.capture_count} capture(s) · {project.message_count} message(s) ·{" "}
                      {project.hypothesis_count} hypothesis/hypotheses
                    </span>
                  </span>
                  {active && <Badge tone="info">current</Badge>}
                </button>
              </li>
            );
          })}
        </ul>

        <div className="mt-4 border-t border-line pt-3">
          <p className="mb-2 text-2xs uppercase tracking-wider text-text-faint">
            New project
          </p>
          <input
            className="input"
            placeholder="Project name"
            value={name}
            maxLength={200}
            onChange={(event) => setName(event.target.value)}
          />
          <textarea
            className="input mt-1.5 h-16 resize-y"
            placeholder="What is the investigation trying to establish?"
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
            {action.pending ? "Creating…" : "Create project"}
          </button>
          {action.notice && (
            <p className="mt-2 text-2xs text-status-ok">{action.notice}</p>
          )}
          {action.error && <p className="mt-2 text-2xs text-status-bad">{action.error}</p>}
        </div>
      </div>
    </Panel>
  );
}

/** Capture selector, scoped to the current project. */
export function CapturePicker({ onSelect }: { onSelect?: (id: string) => void }) {
  const workspace = useWorkspace();
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
          : "The capture could not be imported. See the Security Center for the active limits.",
      );
    } finally {
      setBusy(false);
    }
  };

  return (
    <Panel title="Selected capture">
      <div className="space-y-2 p-3">
        {!workspace.captureId && (
          <EmptyState
            title="No capture selected"
            description="Import a PCAP or PCAPNG file to start. The original bytes are stored immutably and hashed."
            action={
              <button
                type="button"
                className="btn btn-primary"
                disabled={!workspace.projectId || busy}
                onClick={() => fileInput.current?.click()}
              >
                {busy ? "Importing…" : "Import PCAP"}
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
            <Row label="name" value={capture.data.name} />
            <Row label="format" value={capture.data.format} />
            <Row label="size" value={formatBytes(capture.data.file_size)} />
            <Row label="sha256" value={`${capture.data.sha256.slice(0, 32)}…`} />
            <Row label="imported" value={formatTimestamp(Date.parse(capture.data.imported_at) / 1000)} />
            <Row label="analysis" value={capture.data.analysis_status} />
          </div>
        )}

        {sessions.data && (
          <p className="border-t border-line pt-2 text-2xs text-text-muted">
            {sessions.data.total} TCP session(s) in this capture.
          </p>
        )}

        {workspace.captureId && (
          <button
            type="button"
            className="btn w-full"
            disabled={!workspace.projectId || busy}
            onClick={() => fileInput.current?.click()}
          >
            Import another capture
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