"use client";

import Link from "next/link";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useEffect, useState } from "react";
import { Download, HardDrive, Loader2, Upload, Wifi, WifiOff } from "lucide-react";

import { Sidebar, NAV } from "@/components/sidebar";
import { Badge } from "@/components/ui";
import { useAction, useAsync } from "@/hooks/use-async";
import { useWorkspace } from "@/hooks/use-workspace";
import { api } from "@/lib/api";
import { cn } from "@/lib/format";

export function TopBar() {
  const router = useRouter();
  const pathname = usePathname();
  const params = useSearchParams();
  const workspace = useWorkspace();
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

  // Re-evaluate the active nav entry when the query string changes.
  const [active, setActive] = useState(pathname);
  useEffect(() => setActive(pathname), [pathname]);

  const runExport = async () => {
    if (!workspace.projectId) return;
    const result = await exportAction.run(() =>
      api.exportProject(workspace.projectId),
    );
    if (result) {
      setImportMessage(
        `Archive written: ${String(result.archive)} (${String(result.bytes)} bytes)`,
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
        `Imported ${JSON.stringify(result.imported ?? {})}; ` +
          `${Array.isArray(result.hash_mismatches) ? result.hash_mismatches.length : 0} hash mismatch(es)`,
      );
    }
  };

  return (
    <header className="flex h-11 shrink-0 items-center gap-3 border-b border-line bg-surface px-3">
      <div className="flex min-w-0 items-center gap-2">
        <Badge tone="info" title="Current project">
          {workspace.projectName ?? "no project"}
        </Badge>
        <span className="hidden text-2xs text-text-faint sm:inline">
          {workspace.captureId ? `capture ${workspace.captureId.slice(0, 8)}` : "no capture selected"}
        </span>
      </div>

      <form
        className="ml-auto flex items-center gap-2"
        onSubmit={(event) => {
          event.preventDefault();
          if (workspace.projectId && query.trim()) {
            router.push(`/assistant?project=${workspace.projectId}&q=${encodeURIComponent(query)}`);
          }
        }}
        role="search"
      >
        <label htmlFor="global-search" className="sr-only">
          Search the investigation
        </label>
        <input
          id="global-search"
          className="input w-64"
          placeholder="Search: responses longer than 1000 bytes"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
        />
      </form>

      <div className="flex items-center gap-2">
        <span
          className="flex items-center gap-1 text-2xs"
          title={workspace.backendError ?? "Backend reachable"}
        >
          {workspace.backendOnline ? (
            <Wifi className="h-3 w-3 text-status-ok" aria-hidden />
          ) : (
            <WifiOff className="h-3 w-3 text-status-bad" aria-hidden />
          )}
          <span className={workspace.backendOnline ? "text-status-ok" : "text-status-bad"}>
            {workspace.backendOnline ? "backend up" : "backend down"}
          </span>
        </span>

        {running.length > 0 && (
          <Badge tone="info" title="Background jobs in flight">
            <Loader2 className="h-3 w-3 animate-spin" aria-hidden />
            {running.length} job{running.length === 1 ? "" : "s"}
          </Badge>
        )}

        <label className="btn cursor-pointer">
          <Upload className="h-3 w-3" aria-hidden />
          Import .mplab
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
          title="Export the project as a portable .mplab archive"
        >
          <Download className="h-3 w-3" aria-hidden />
          {exportAction.pending ? "Exporting" : "Export"}
        </button>
      </div>

      {(importMessage || exportAction.error || importAction.error) && (
        <div className="absolute right-3 top-12 z-50 max-w-md rounded-sm border border-line-strong bg-surface-raised p-2 text-2xs shadow-lg">
          {importMessage && <p className="text-status-ok">{importMessage}</p>}
          {exportAction.error && (
            <p className="text-status-bad">
              <HardDrive className="mr-1 inline h-3 w-3" aria-hidden />
              {exportAction.error}
            </p>
          )}
          {importAction.error && <p className="text-status-bad">{importAction.error}</p>}
        </div>
      )}
    </header>
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

export { NAV, cn, usePathname, useSearchParams, Link };