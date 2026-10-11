"use client";

import Link from "next/link";
import { useMemo, useState } from "react";

import {
  Badge,
  Caveat,
  EmptyState,
  ErrorState,
  Panel,
  Skeleton,
} from "@/components/ui";
import { useAsync } from "@/hooks/use-async";
import { useWorkspace } from "@/hooks/use-workspace";
import { api } from "@/lib/api";
import { formatNumber } from "@/lib/format";
import type { StatusTone } from "@/lib/format";

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

export default function TlsPage() {
  const workspace = useWorkspace();
  const captureId = workspace.captureId;
  const [nonBrowserOnly, setNonBrowserOnly] = useState(false);

  const tls = useAsync(
    () => (captureId ? api.captureTls(captureId) : Promise.resolve(null)),
    [captureId, workspace.revision],
  );

  const fingerprints = useMemo(() => {
    const items = tls.data?.fingerprints ?? [];
    return nonBrowserOnly
      ? items.filter((item) => item.category !== "browser" && item.category !== "unknown")
      : items;
  }, [tls.data, nonBrowserOnly]);

  if (!captureId) {
    return (
      <div className="p-4">
        <EmptyState
          title="No capture selected"
          description="TLS Analysis fingerprints the handshakes inside one capture. Pick a capture first; fingerprinting reads the plaintext handshake, so it works on encrypted sessions and needs no keys."
          action={
            <Link href="/captures" className="btn btn-primary">
              Go to Captures
            </Link>
          }
        />
      </div>
    );
  }

  return (
    <div className="flex h-full flex-col">
      <div className="border-b border-line px-4 py-3">
        <h1 className="text-sm font-semibold tracking-tight text-text">TLS Analysis</h1>
        <p className="mt-0.5 max-w-3xl text-2xs leading-relaxed text-text-muted">
          JA3 and JA3S fingerprints of the handshakes in this capture, matched against a
          small, locally maintained table. A match identifies a known client family — it is
          not proof of the implementation language and never an indication of maliciousness.
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
            <Panel title="Verdict">
              <div className="space-y-2 p-3">
                <p className="text-xs text-text">{tls.data.verdict.statement}</p>
                <div className="flex flex-wrap items-center gap-2">
                  <Badge tone="info">
                    client fingerprints: {tls.data.verdict.client_fingerprints}
                  </Badge>
                  <Badge tone={tls.data.verdict.non_browser_matches ? "info" : "neutral"}>
                    non-browser matches: {tls.data.verdict.non_browser_matches}
                  </Badge>
                  <Badge tone={tls.data.unreliable_handshakes ? "warn" : "neutral"}>
                    unreliable handshakes: {tls.data.unreliable_handshakes}
                  </Badge>
                  <Badge tone="neutral">
                    streams scanned: {formatNumber(tls.data.streams_scanned)}/
                    {formatNumber(tls.data.streams_total)}
                  </Badge>
                  {Object.entries(tls.data.categories).map(([category, count]) => (
                    <Badge key={category} tone={CATEGORY_TONE[category] ?? "unknown"}>
                      {CATEGORY_LABEL[category] ?? category}: {count}
                    </Badge>
                  ))}
                </div>
                <Caveat>{tls.data.interpretation_note}</Caveat>
                <p className="text-2xs text-text-faint">
                  fingerprint database: {tls.data.fingerprint_database}
                </p>
              </div>
            </Panel>

            <Panel
              title="Fingerprints"
              actions={
                <label className="flex cursor-pointer items-center gap-1.5 text-2xs text-text-muted">
                  <input
                    type="checkbox"
                    checked={nonBrowserOnly}
                    onChange={(event) => setNonBrowserOnly(event.target.checked)}
                  />
                  only non-browser clients
                </label>
              }
            >
              {fingerprints.length === 0 ? (
                <EmptyState
                  title="No fingerprints"
                  description={
                    tls.data.count === 0
                      ? "No TLS handshake was found at the head of any stream. That means this capture has no TLS handshake, not that the traffic was not encrypted."
                      : "No fingerprint matches the current filter."
                  }
                />
              ) : (
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Kind</th>
                      <th>Fingerprint</th>
                      <th>Client family</th>
                      <th>Class</th>
                      <th>Confidence</th>
                      <th>Seen</th>
                      <th>SNI / ALPN</th>
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
                            <span className="text-text-faint">no local match</span>
                          )}
                          {item.source ? (
                            <span className="block text-2xs text-text-faint">
                              source: {item.source}
                            </span>
                          ) : null}
                        </td>
                        <td>
                          <Badge tone={CATEGORY_TONE[item.category] ?? "unknown"}>
                            {CATEGORY_LABEL[item.category] ?? item.category}
                          </Badge>
                        </td>
                        <td className="text-text-muted">{item.confidence}</td>
                        <td className="text-text-muted">
                          {item.occurrences}
                          <span className="block text-2xs text-text-faint">
                            {item.stream_ids.length} stream(s)
                          </span>
                        </td>
                        <td className="font-mono text-2xs text-text-muted">
                          {item.sni.length ? <div>sni: {item.sni.join(", ")}</div> : null}
                          {item.alpn.length ? <div>alpn: {item.alpn.join(", ")}</div> : null}
                          {item.versions.length ? (
                            <div className="text-text-faint">tls: {item.versions.join(", ")}</div>
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
              A fingerprint names a client library or family, not a human or a piece of
              malware. The same library produces the same hash for legitimate and abusive
              traffic alike, so this table is a lead to investigate, never a verdict on its own.
            </Caveat>
          </div>
        ) : null}
      </div>
    </div>
  );
}
