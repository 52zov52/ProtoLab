"use client";

import Link from "next/link";
import { useMemo, useRef, useState } from "react";

import {
  Badge,
  Caveat,
  EmptyState,
  ErrorState,
  Panel,
  Skeleton,
} from "@/components/ui";
import { useAsync, useAction } from "@/hooks/use-async";
import { useWorkspace } from "@/hooks/use-workspace";
import { api } from "@/lib/api";
import { formatNumber } from "@/lib/format";
import type { StatusTone } from "@/lib/format";
import { useI18n, useStreamingBoundary } from "@/lib/i18n";

const CATEGORY_TONE: Record<string, StatusTone> = {
  browser: "ok",
  library: "info",
  bot: "info",
  server: "neutral",
  unknown: "unknown",
};

const CATEGORY_LABEL: Record<string, string> = {
  browser: "browser",
  library: "library / script",
  bot: "bot / automation",
  server: "server",
  unknown: "unmatched",
};

const DECRYPT_TONE: Record<string, StatusTone> = {
  decrypted: "ok",
  auth_failed: "bad",
  unsupported: "warn",
  truncated: "warn",
  not_encrypted: "neutral",
};

/** How much of a decrypted record is shown before the rest moves to a scroll. */
const PREVIEW_BYTES = 96;

function KeyLogPanel({ projectId }: { projectId: string }) {
  const { t } = useI18n();
  const keylogs = useAsync(() => api.keylogs(projectId), [projectId, projectId]);
  const action = useAction();
  const inputRef = useRef<HTMLInputElement | null>(null);

  return (
    <Panel title={t("TLS key log")}>
      <div className="space-y-2 p-3">
        <p className="max-w-3xl text-2xs leading-relaxed text-text-muted">
          {t(
            "Upload the key log (SSLKEYLOGFILE) of one side of the conversation to decrypt its application records. The file is hashed, stored with owner-only permissions and never returned by the API; nothing here derives keys from observed traffic.",
          )}
        </p>
        <div className="flex flex-wrap items-center gap-2">
          <label className="btn cursor-pointer">
            {action.pending ? t("Uploading…") : t("Upload key log")}
            <input
              ref={inputRef}
              type="file"
              accept=".log,.txt,.keylog"
              className="hidden"
              onChange={(event) => {
                const file = event.target.files?.[0];
                event.target.value = "";
                if (!file) return;
                void action
                  .run(() => api.uploadKeylog(projectId, file))
                  .then(() => keylogs.reload());
              }}
            />
          </label>
          <button type="button" className="btn" onClick={keylogs.reload}>
            {t("Refresh")}
          </button>
          {action.error ? (
            <span className="font-mono text-2xs text-status-bad">{action.error}</span>
          ) : null}
        </div>

        {keylogs.state === "loading" ? (
          <Skeleton rows={2} />
        ) : (keylogs.data ?? []).length === 0 ? (
          <p className="text-2xs text-text-faint">{t("No key log uploaded yet.")}</p>
        ) : (
          <ul className="space-y-1">
            {(keylogs.data ?? []).map((row) => (
              <li
                key={String(row.id)}
                className="flex flex-wrap items-center gap-2 rounded-sm border border-line bg-surface-raised px-2 py-1.5"
              >
                <span className="truncate text-2xs text-text">{String(row.name)}</span>
                <span className="font-mono text-2xs text-text-faint">
                  {String(row.sha256).slice(0, 16)}…
                </span>
                {Object.entries((row.labels ?? {}) as Record<string, number>).map(
                  ([label, count]) => (
                    <Badge key={label} tone="neutral">
                      {t("{label}: {count}", { label, count })}
                    </Badge>
                  ),
                )}
                <button
                  type="button"
                  className="btn btn-danger ml-auto"
                  onClick={() => {
                    void action.run(async () => {
                      await api.deleteKeylog(projectId, String(row.id));
                      keylogs.reload();
                      return null;
                    });
                  }}
                >
                  {t("Delete")}
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>
    </Panel>
  );
}

function DecryptPanel({
  projectId,
  streamIds,
}: {
  projectId: string;
  streamIds: string[];
}) {
  const { t } = useI18n();
  const keylogs = useAsync(() => api.keylogs(projectId), [projectId]);
  const [streamId, setStreamId] = useState("");
  const [keylogId, setKeylogId] = useState("");
  const action = useAction();
  const [result, setResult] = useState<Record<string, unknown> | null>(null);

  const records = ((result?.records ?? []) as Record<string, unknown>[]) ?? [];
  const summary = (result?.summary ?? {}) as Record<string, unknown>;

  return (
    <Panel title={t("Decrypt a stream")}>
      <div className="space-y-3 p-3">
        <p className="max-w-3xl text-2xs leading-relaxed text-text-muted">
          {t(
            "Decryption is only possible for the direction the key log belongs to, and only for cipher suites this build implements (TLS 1.2 AES-CBC/GCM, TLS 1.3 AES-GCM and ChaCha20-Poly1305). Everything else is reported as unsupported, never approximated.",
          )}
        </p>

        <div className="flex flex-wrap items-end gap-2">
          <label className="block">
            <span className="mb-1 block text-2xs uppercase tracking-wider text-text-faint">
              {t("Stream")}
            </span>
            <select
              className="input"
              value={streamId}
              onChange={(event) => setStreamId(event.target.value)}
            >
              <option value="">{t("Select a stream")}</option>
              {streamIds.map((id) => (
                <option key={id} value={id}>
                  {id.slice(0, 12)}
                </option>
              ))}
            </select>
          </label>
          <label className="block">
            <span className="mb-1 block text-2xs uppercase tracking-wider text-text-faint">
              {t("Key log")}
            </span>
            <select
              className="input"
              value={keylogId}
              onChange={(event) => setKeylogId(event.target.value)}
            >
              <option value="">{t("Select a key log")}</option>
              {(keylogs.data ?? []).map((row) => (
                <option key={String(row.id)} value={String(row.id)}>
                  {String(row.name)}
                </option>
              ))}
            </select>
          </label>
          <button
            type="button"
            className="btn btn-primary"
            disabled={action.pending || !streamId || !keylogId}
            onClick={() => {
              void action
                .run(async () => {
                  const value = await api.decryptStream(streamId, keylogId);
                  setResult(value as Record<string, unknown>);
                  return value;
                })
                .catch(() => setResult(null));
            }}
          >
            {action.pending ? t("Decrypting…") : t("Decrypt")}
          </button>
        </div>

        {action.error ? (
          <p className="font-mono text-2xs text-status-bad">{action.error}</p>
        ) : null}

        {result ? (
          <div className="space-y-2">
            <div className="flex flex-wrap items-center gap-2">
              {Object.entries((summary.by_status ?? {}) as Record<string, number>).map(
                ([status, count]) => (
                  <Badge key={status} tone={DECRYPT_TONE[status] ?? "unknown"}>
                    {t("{status}: {count}", { status, count })}
                  </Badge>
                ),
              )}
              <span className="text-2xs text-text-faint">
                {t("{bytes} byte(s) decrypted", {
                  bytes: formatNumber(Number(summary.plaintext_bytes ?? 0)),
                })}
              </span>
            </div>

            {records.length === 0 ? (
              <p className="text-2xs text-text-faint">
                {t("No application records were found in this direction.")}
              </p>
            ) : (
              <table className="data-table">
                <thead>
                  <tr>
                    <th>{t("#")}</th>
                    <th>{t("Record")}</th>
                    <th>{t("Status")}</th>
                    <th>{t("Plaintext")}</th>
                    <th>{t("Detail")}</th>
                  </tr>
                </thead>
                <tbody>
                  {records.map((record, index) => {
                    const hex = String(record.plaintext_hex ?? "");
                    const preview =
                      hex.slice(0, PREVIEW_BYTES) + (hex.length > PREVIEW_BYTES ? "…" : "");
                    return (
                      <tr key={index}>
                        <td className="text-text-faint">{Number(record.sequence)}</td>
                        <td className="font-mono text-2xs text-text-muted">
                          {String(record.content_type)}
                        </td>
                        <td>
                          <Badge
                            tone={DECRYPT_TONE[String(record.status)] ?? "unknown"}
                          >
                            {String(record.status)}
                          </Badge>
                        </td>
                        <td className="font-mono text-2xs text-text">
                          {preview || <span className="text-text-faint">—</span>}
                        </td>
                        <td className="text-2xs text-text-muted">
                          {String(record.reason ?? "")}
                          {record.cipher_suite_name ? (
                            <span className="block text-text-faint">
                              {String(record.cipher_suite_name)}
                            </span>
                          ) : null}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}

            <Caveat>{t(String(result.interpretation ?? ""))}</Caveat>
          </div>
        ) : null}
      </div>
    </Panel>
  );
}

export default function TlsPage() {
  const workspace = useWorkspace();
  const { t } = useI18n();
  // This page takes no ?project= parameter, but it still has to join the shell's
  // streaming boundary: without this it renders into the fallback and the client
  // never replaces it, leaving the application on "Loading…" on a hard load.
  useStreamingBoundary();
  const captureId = workspace.captureId;
  const [nonBrowserOnly, setNonBrowserOnly] = useState(false);

  const tls = useAsync(
    () => (captureId ? api.captureTls(captureId) : Promise.resolve(null)),
    [captureId, workspace.revision],
  );

  /**
   * Captures elsewhere in the project that *do* carry a handshake.
   *
   * The page reports on the selected capture, which is right - but "no
   * fingerprints here" reads as "the feature found nothing" when the truth is
   * often "this particular file has no ClientHello and another one does". Saying
   * so turns a dead end into one click.
   */
  const withHandshakes = useAsync(
    async () => {
      const pid = workspace.projectId;
      if (!pid) return [];
      const captures = await api.projectCaptures(pid);
      const found: { id: string; name: string; count: number }[] = [];
      for (const capture of captures) {
        if (capture.id === captureId) continue;
        try {
          const report = await api.captureTls(capture.id);
          const count = (report?.fingerprints ?? []).length;
          if (count > 0) found.push({ id: capture.id, name: capture.name, count });
        } catch {
          /* a capture that cannot be read simply has nothing to offer here */
        }
      }
      return found;
    },
    [captureId, workspace.projectId, workspace.revision],
  );

  const fingerprints = useMemo(() => {
    const items = tls.data?.fingerprints ?? [];
    return nonBrowserOnly
      ? items.filter((item) => item.category !== "browser" && item.category !== "unknown")
      : items;
  }, [tls.data, nonBrowserOnly]);

  // Streams a fingerprint was seen in are the ones a key log can be tried on.
  const streamIds = useMemo(() => {
    const ids = new Set<string>();
    for (const item of fingerprints) {
      for (const id of item.stream_ids ?? []) ids.add(id);
    }
    return [...ids].sort();
  }, [fingerprints]);

  if (!captureId) {
    return (
      <div className="p-4">
        <EmptyState
          title={t("No capture selected")}
          description={t(
            "TLS Analysis fingerprints the handshakes inside one capture. Pick a capture first; fingerprinting reads the plaintext handshake, so it works on encrypted sessions and needs no keys.",
          )}
          action={
            <Link href="/captures" className="btn btn-primary">
              {t("Go to Captures")}
            </Link>
          }
        />
      </div>
    );
  }

  return (
    <div className="flex h-full flex-col">
      <div className="border-b border-line px-4 py-3">
        <h1 className="text-sm font-semibold tracking-tight text-text">{t("TLS Analysis")}</h1>
        <p className="mt-0.5 max-w-3xl text-2xs leading-relaxed text-text-muted">
          {t(
            "JA3 and JA3S fingerprints of the handshakes in this capture, matched against a small, locally maintained table. A match identifies a known client family — it is not proof of the implementation language and never an indication of maliciousness.",
          )}
        </p>
      </div>

      <div className="min-h-0 flex-1 overflow-auto p-3">
        {tls.state === "error" ? (
          <Panel>
            <ErrorState message={tls.error ?? ""} onRetry={tls.reload} />
          </Panel>
        ) : tls.state === "loading" ? (
          <Panel>
            <Skeleton rows={8} />
          </Panel>
        ) : tls.data ? (
          <div className="flex flex-col gap-3">
            {(withHandshakes.data?.length ?? 0) > 0 && (
              <Panel title={t("Handshakes are in another capture")}>
                <div className="space-y-2 p-3 text-2xs">
                  <p className="text-text-muted">
                    {t(
                      "This capture has no ClientHello, which is a fact about this file and not about the traffic. These captures in the same project do have one:",
                    )}
                  </p>
                  <ul className="space-y-1">
                    {(withHandshakes.data ?? []).map((item) => (
                      <li key={item.id}>
                        <button
                          type="button"
                          className="link text-left"
                          onClick={() => workspace.selectCapture(item.id)}
                        >
                          {item.name}
                        </button>
                        <span className="ml-2 font-mono text-text-faint">
                          {t("{count} fingerprints", { count: item.count })}
                        </span>
                      </li>
                    ))}
                  </ul>
                </div>
              </Panel>
            )}
            <Panel title={t("Verdict")}>
              <div className="space-y-2 p-3">
                <p className="text-xs text-text">{t(String(tls.data.verdict.statement))}</p>
                <div className="flex flex-wrap items-center gap-2">
                  <Badge tone="info">
                    {t("client fingerprints: {count}", {
                      count: tls.data.verdict.client_fingerprints,
                    })}
                  </Badge>
                  <Badge tone={tls.data.verdict.non_browser_matches ? "info" : "neutral"}>
                    {t("non-browser matches: {count}", {
                      count: tls.data.verdict.non_browser_matches,
                    })}
                  </Badge>
                  <Badge tone={tls.data.unreliable_handshakes ? "warn" : "neutral"}>
                    {t("unreliable handshakes: {count}", {
                      count: tls.data.unreliable_handshakes,
                    })}
                  </Badge>
                  <Badge tone="neutral">
                    {t("streams scanned: {scanned}/{total}", {
                      scanned: formatNumber(tls.data.streams_scanned),
                      total: formatNumber(tls.data.streams_total),
                    })}
                  </Badge>
                  {Object.entries(tls.data.categories).map(([category, count]) => (
                    <Badge key={category} tone={CATEGORY_TONE[category] ?? "unknown"}>
                      {t("{label}: {count}", { label: t(CATEGORY_LABEL[category] ?? category), count })}
                    </Badge>
                  ))}
                </div>
                <Caveat>{t(String(tls.data.interpretation_note))}</Caveat>
                <p className="text-2xs text-text-faint">
                  {t("fingerprint database: {database}", {
                    database: tls.data.fingerprint_database,
                  })}
                </p>
              </div>
            </Panel>

            <Panel
              title={t("Fingerprints")}
              actions={
                <label className="flex cursor-pointer items-center gap-1.5 text-2xs text-text-muted">
                  <input
                    type="checkbox"
                    checked={nonBrowserOnly}
                    onChange={(event) => setNonBrowserOnly(event.target.checked)}
                  />
                  {t("only non-browser clients")}
                </label>
              }
            >
              {fingerprints.length === 0 ? (
                <EmptyState
                  title={t("No fingerprints")}
                  description={
                    tls.data.count === 0
                      ? t("No TLS handshake was found at the head of any stream. That means this capture has no TLS handshake, not that the traffic was not encrypted.")
                      : t("No fingerprint matches the current filter.")
                  }
                />
              ) : (
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>{t("Kind")}</th>
                      <th>{t("Fingerprint")}</th>
                      <th>{t("Client family")}</th>
                      <th>{t("Class")}</th>
                      <th>{t("Confidence")}</th>
                      <th>{t("Seen")}</th>
                      <th>{t("SNI / ALPN")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {fingerprints.map((item) => (
                      <tr key={`${item.kind}-${item.md5}`}>
                        <td>
                          <Badge tone="info">{item.kind}</Badge>
                        </td>
                        <td className="font-mono text-2xs text-text">{item.md5}</td>
                        <td className="text-text">
                          {item.family ?? (
                            <span className="text-text-faint">{t("no local match")}</span>
                          )}
                          {item.source ? (
                            <span className="block text-2xs text-text-faint">
                              {t("source: {source}", { source: item.source })}
                            </span>
                          ) : null}
                        </td>
                        <td>
                          <Badge tone={CATEGORY_TONE[item.category] ?? "unknown"}>
                            {t(CATEGORY_LABEL[item.category] ?? item.category)}
                          </Badge>
                        </td>
                        <td className="text-text-muted">{item.confidence}</td>
                        <td className="text-text-muted">
                          {item.occurrences}
                          <span className="block text-2xs text-text-faint">
                            {t("{count} stream(s)", { count: item.stream_ids.length })}
                          </span>
                        </td>
                        <td className="font-mono text-2xs text-text-muted">
                          {item.sni.length ? (
                            <div>{t("sni: {value}", { value: item.sni.join(", ") })}</div>
                          ) : null}
                          {item.alpn.length ? (
                            <div>{t("alpn: {value}", { value: item.alpn.join(", ") })}</div>
                          ) : null}
                          {item.versions.length ? (
                            <div className="text-text-faint">
                              {t("tls: {value}", { value: item.versions.join(", ") })}
                            </div>
                          ) : null}
                          {!item.sni.length && !item.alpn.length && !item.versions.length ? (
                            <span className="text-text-faint">—</span>
                          ) : null}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </Panel>

            <Caveat tone="warn">
              {t(
                "A fingerprint names a client library or family, not a human or a piece of malware. The same library produces the same hash for legitimate and abusive traffic alike, so this table is a lead to investigate, never a verdict on its own.",
              )}
            </Caveat>

            <KeyLogPanel projectId={workspace.projectId ?? ""} />

            <DecryptPanel
              projectId={workspace.projectId ?? ""}
              streamIds={streamIds}
            />
          </div>
        ) : null}
      </div>
    </div>
  );
}
