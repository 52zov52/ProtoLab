"use client";


import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { Download, HardDrive, Loader2, Upload, Wifi, WifiOff } from "lucide-react";

import { Badge } from "@/components/ui";
import { useAction, useAsync } from "@/hooks/use-async";
import { useWorkspace } from "@/hooks/use-workspace";
import { api } from "@/lib/api";
import { cn } from "@/lib/format";
import { useI18n } from "@/lib/i18n";


export function TopBar() {
  const router = useRouter();
  const workspace = useWorkspace();
  const { t } = useI18n();
  const [query, setQuery] = useState("");

  const jobs = useAsync(() => (workspace.projectId ? api.jobs(`?project_id=${workspace.projectId}`) : Promise.resolve([])), [
    workspace.projectId,
    workspace.revision,
  ]);

  const running = (jobs.data ?? []).filter((job) =>
    ["queued", "running", "canceling"].includes(String(job.status)),
  );

  const exportAction = useAction();
  const importAction = useAction();
  const [importMessage, setImportMessage] = useState<string | null>(null);

  // The import/export notice is a transient toast, not a permanent overlay.
  useEffect(() => {
    if (!importMessage) return;
    const timer = window.setTimeout(() => setImportMessage(null), 8000);
    return () => window.clearTimeout(timer);
  }, [importMessage]);

  const runExport = async () => {
    const projectId = workspace.projectId;
    if (!projectId) return;
    const result = await exportAction.run(() => api.exportProject(projectId));
    if (result) {
      setImportMessage(
        t("Archive written: {archive} ({bytes} bytes)", {
          archive: String(result.archive),
          bytes: String(result.bytes),
        }),
      );
    }
  };

  const runImport = async (file: File) => {
    const result = await importAction.run(() => api.importProject(file));
    if (result) {
      const newId = String(result.project_id ?? "");
      if (newId) {
        workspace.selectProject(newId, String(result.name ?? "Imported project"));
        workspace.invalidate();
        router.push(`/?project=${newId}`);
      }
      setImportMessage(
        t("Imported {summary}; {count} hash mismatch(es)", {
          summary: JSON.stringify(result.imported ?? {}),
          count: Array.isArray(result.hash_mismatches) ? result.hash_mismatches.length : 0,
        }),
      );
    }
  };

  return (
    <header className="flex h-11 shrink-0 items-center gap-2 overflow-x-auto border-b border-line bg-surface px-3">
      <div className="flex min-w-0 items-center gap-2">
        <Badge tone="info" title={t("Current project")}>
          <span className="block max-w-[14rem] truncate">
            {workspace.projectName ?? t("no project")}
          </span>
        </Badge>
        <span className="hidden text-2xs text-text-faint md:inline">
          {workspace.captureId
            ? t("capture {id}", { id: workspace.captureId.slice(0, 8) })
            : t("no capture selected")}
        </span>
      </div>

      <form
        className="ml-auto flex min-w-0 items-center gap-2"
        onSubmit={(event) => {
          event.preventDefault();
          if (workspace.projectId && query.trim()) {
            router.push(`/assistant?project=${workspace.projectId}&q=${encodeURIComponent(query)}`);
          }
        }}
        role="search"
      >
        <label htmlFor="global-search" className="sr-only">
          {t("Search the investigation")}
        </label>
        <input
          id="global-search"
          className="input w-40 sm:w-56 lg:w-64"
          placeholder={t("Search: responses longer than 1000 bytes")}
          value={query}
          onChange={(event) => setQuery(event.target.value)}
        />
      </form>

      <div className="flex shrink-0 items-center gap-2">
        <span
          className="flex items-center gap-1 text-2xs"
          title={workspace.backendError ?? t("Backend reachable")}
        >
          {workspace.backendOnline ? (
            <Wifi className="h-3 w-3 text-status-ok" aria-hidden />
          ) : (
            <WifiOff className="h-3 w-3 text-status-bad" aria-hidden />
          )}
          <span
            className={cn(
              "hidden md:inline",
              workspace.backendOnline ? "text-status-ok" : "text-status-bad",
            )}
          >
            {workspace.backendOnline ? t("backend up") : t("backend down")}
          </span>
        </span>

        {running.length > 0 && (
          <Badge tone="info" title={t("Background jobs in flight")}>
            <Loader2 className="h-3 w-3 animate-spin" aria-hidden />
            {t("{count} job(s)", { count: running.length })}
          </Badge>
        )}

        <LocaleSwitcher />

        <label className="btn cursor-pointer">
          <Upload className="h-3 w-3" aria-hidden />
          {t("Import .mplab")}
          <input
            type="file"
            accept=".mplab"
            className="hidden"
            onChange={(event) => {
              const file = event.target.files?.[0];
              if (file) void runImport(file);
              event.target.value = "";
            }}
          />
        </label>

        <button
          type="button"
          className="btn btn-primary"
          disabled={!workspace.projectId || exportAction.pending}
          onClick={runExport}
          title={t("Export the project as a portable .mplab archive")}
        >
          <Download className="h-3 w-3" aria-hidden />
          {exportAction.pending ? t("Exporting") : t("Export")}
        </button>
      </div>

      {(importMessage || exportAction.error || importAction.error) && (
        <div
          role="status"
          className="fixed bottom-4 right-4 z-50 flex max-w-sm items-start gap-2 rounded-sm border border-line-strong bg-surface-raised p-2.5 text-2xs shadow-lg"
        >
          <div className="min-w-0 space-y-1">
            {importMessage && <p className="text-status-ok">{importMessage}</p>}
            {exportAction.error && (
              <p className="text-status-bad">
                <HardDrive className="mr-1 inline h-3 w-3" aria-hidden />
                {exportAction.error}
              </p>
            )}
            {importAction.error && <p className="text-status-bad">{importAction.error}</p>}
          </div>
          <button
            type="button"
            className="btn shrink-0 px-1.5"
            title={t("Dismiss")}
            aria-label={t("Dismiss")}
            onClick={() => {
              setImportMessage(null);
              exportAction.clear();
              importAction.clear();
            }}
          >
            ×
          </button>
        </div>
      )}
    </header>
  );
}

/** RU/EN language switch. The choice is remembered in `mplab.locale`. */
function LocaleSwitcher() {
  const { locale, setLocale, t } = useI18n();
  return (
    <div className="flex items-center gap-0.5" role="group" aria-label={t("Language")}>
      {(["en", "ru"] as const).map((code) => (
        <button
          key={code}
          type="button"
          className={cn("btn px-1.5", locale === code && "btn-primary")}
          aria-pressed={locale === code}
          title={t("Language")}
          onClick={() => setLocale(code)}
        >
          {code.toUpperCase()}
        </button>
      ))}
    </div>
  );
}

/** Breadcrumb of the current tool, shown above the working area. */
export function PageHeader({
  title,
  description,
  actions,
}: {
  title: string;
  description?: string;
  actions?: React.ReactNode;
}) {
  return (
    <div className="flex shrink-0 items-start justify-between gap-4 border-b border-line px-4 py-3">
      <div className="min-w-0">
        <h1 className="text-sm font-semibold tracking-tight text-text">{title}</h1>
        {description && (
          <p className="mt-0.5 max-w-3xl text-2xs leading-relaxed text-text-muted">
            {description}
          </p>
        )}
      </div>
      {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
    </div>
  );
}