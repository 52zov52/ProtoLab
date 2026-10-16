"use client";

import { useState } from "react";
import { ShieldCheck } from "lucide-react";

import {
  Badge,
  Caveat,
  EmptyState,
  Panel,
  Skeleton,
} from "@/components/ui";
import { useAction, useAsync } from "@/hooks/use-async";
import { checkTone, cn } from "@/lib/format";
import { useI18n, useStreamingBoundary } from "@/lib/i18n";

type Check = {
  id: string;
  title: string;
  verdict: "pass" | "fail" | "unknown" | "na";
  detail: string;
  evidence: Record<string, unknown>;
  remediation: string | null;
};

export default function SecurityPage() {
  const report = useAsync(() => api_securityReport(), []);
  const { t } = useI18n();
  // Joins the shell's streaming boundary: a page that never suspends would
  // otherwise render into the fallback and the client would never replace it.
  useStreamingBoundary();
  const action = useAction();
  const [tab, setTab] = useState<"checks" | "audit">("checks");

  const audit = useAsync(() => api_auditEvents(), [tab === "audit"]);
  const chain = useAsync(() => api_verifyAudit(), [tab === "audit"]);

  const data = report.data as Record<string, unknown> | null;
  const checks = ((data?.security_checks as { checks?: Check[] })?.checks ?? []) as Check[];
  const summary =
    (data?.security_checks as { summary?: Record<string, number> })?.summary ?? {};

  return (
    <div className="flex h-full flex-col">
      <div className="flex shrink-0 items-start justify-between gap-4 border-b border-line px-4 py-3">
        <div>
          <h1 className="text-sm font-semibold tracking-tight text-text">{t("Security Center")}</h1>
          <p className="mt-0.5 max-w-3xl text-2xs leading-relaxed text-text-muted">
            {t(
              "Real local checks with honest verdicts. A check that could not be performed says so; nothing here is a penetration test or a certification.",
            )}
          </p>
        </div>
        <button
          type="button"
          className="btn btn-primary"
          disabled={action.pending}
          onClick={async () => {
            const result = await action.run(() => api_securityCheck());
            if (result) report.setData(result);
          }}
        >
          <ShieldCheck className="h-3 w-3" aria-hidden />
          {action.pending ? t("Checking…") : t("Run configuration check")}
        </button>
      </div>

      <div className="flex shrink-0 gap-1 border-b border-line px-3 py-1.5">
        {(["checks", "audit"] as const).map((name) => (
          <button
            key={name}
            type="button"
            className={cn("btn", tab === name && "btn-primary")}
            onClick={() => setTab(name)}
          >
            {name === "checks" ? t("Configuration checks") : t("Audit log")}
          </button>
        ))}
      </div>

      <div className="min-h-0 flex-1 overflow-auto p-3">
        {action.error && (
          <p className="mb-3 rounded-sm border border-status-bad/40 bg-status-bad/5 p-2 font-mono text-2xs text-status-bad">
            {action.error}
          </p>
        )}

        {tab === "checks" ? (
          report.state === "loading" ? (
            <Skeleton rows={10} />
          ) : checks.length === 0 ? (
            <EmptyState title={t("No checks available")} />
          ) : (
            <div className="space-y-3">
              <div className="flex flex-wrap gap-2">
                {(["pass", "fail", "unknown", "na"] as const).map((verdict) => (
                  <Badge key={verdict} tone={checkTone(verdict)}>
                    {verdict}: {summary[verdict] ?? 0}
                  </Badge>
                ))}
              </div>

              <Panel title={t("Runtime")}>
                <dl className="grid gap-2 p-3 font-mono text-2xs sm:grid-cols-3">
                  <Field label={t("mode")} value={String(data?.mode ?? "-")} />
                  <Field
                    label={t("bind")}
                    value={
                      ((data?.bind ?? {}) as { host: string; port: number }).host +
                      ":" +
                      ((data?.bind ?? {}) as { host: string; port: number }).port
                    }
                  />
                  <Field
                    label={t("platform")}
                    value={String(
                      (data?.platform as { system?: string; release?: string } | undefined)
                        ?.system ?? "-",
                    )}
                  />
                </dl>
              </Panel>

              <Panel title={t("Checks")}>
                <ul className="divide-y divide-line/60">
                  {checks.map((check) => (
                    <li key={check.id} className="px-3 py-2">
                      <div className="flex flex-wrap items-center gap-2">
                        <Badge tone={checkTone(check.verdict)}>{check.verdict}</Badge>
                        <span className="text-2xs font-medium text-text">{check.title}</span>
                        <span className="ml-auto font-mono text-2xs text-text-faint">
                          {check.id}
                        </span>
                      </div>
                      <p className="mt-1 text-2xs leading-relaxed text-text-muted">
                        {check.detail}
                      </p>
                      {check.remediation && (
                        <p className="mt-1 text-2xs text-status-warn">
                          → {check.remediation}
                        </p>
                      )}
                    </li>
                  ))}
                </ul>
              </Panel>

              <Panel title={t("Integrations")}>
                <ul className="space-y-2 p-3 text-2xs">
                  {Object.entries(
                    (data?.integrations ?? {}) as Record<string, Record<string, unknown>>,
                  ).map(([name, value]) => (
                    <li key={name} className="flex flex-wrap items-center gap-2">
                      <span className="w-40 font-mono text-text-faint">{name}</span>
                      <Badge
                        tone={
                          value.available === true
                            ? "ok"
                            : value.available === false
                              ? "unknown"
                              : "neutral"
                        }
                      >
                        {String(value.available)}
                      </Badge>
                      <span className="text-text-muted">{String(value.note ?? "")}</span>
                    </li>
                  ))}
                </ul>
              </Panel>

              <Panel title={t("Documented limits")}>
                <ul className="space-y-1 p-3">
                  {((data?.documented_limits ?? []) as string[]).map((limit, index) => (
                    <li key={index} className="text-2xs text-text-muted">
                      • {limit}
                    </li>
                  ))}
                  <Caveat tone="warn">
                    {String(
                      (data?.security_checks as { scope?: string })?.scope ?? "",
                    )}
                  </Caveat>
                </ul>
              </Panel>
            </div>
          )
        ) : (
          <div className="space-y-3">
            <Panel title={t("Audit chain integrity")}>
              {chain.state === "loading" ? (
                <Skeleton rows={2} />
              ) : chain.data ? (
                <div className="space-y-1 p-3">
                  <Badge tone={chain.data.valid ? "ok" : "bad"}>
                    {chain.data.valid ? t("chain verified") : t("chain broken")}
                  </Badge>
                  <p className="text-2xs text-text-muted">
                    {String(chain.data.explanation ?? "")}
                  </p>
                </div>
              ) : null}
            </Panel>

            <Panel title={t("Security events")}>
              {audit.state === "loading" ? (
                <Skeleton rows={10} />
              ) : audit.data ? (
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>{t("Time")}</th>
                      <th>{t("Action")}</th>
                      <th>{t("Outcome")}</th>
                      <th>{t("Risk")}</th>
                      <th>{t("Object")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(audit.data.items as Record<string, unknown>[]).map((item) => (
                      <tr key={String(item.id)}>
                        <td className="text-text-faint">
                          {String(item.timestamp).slice(0, 19)}
                        </td>
                        <td className="text-accent">{String(item.action)}</td>
                        <td>{String(item.outcome)}</td>
                        <td>
                          <Badge
                            tone={
                              item.risk === "error"
                                ? "bad"
                                : item.risk === "warning"
                                  ? "warn"
                                  : "neutral"
                            }
                          >
                            {String(item.risk)}
                          </Badge>
                        </td>
                        <td className="text-text-muted">
                          {item.object_type ? `${item.object_type}:${String(item.object_id).slice(0, 10)}` : "—"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <EmptyState title={t("No audit events")} />
              )}
            </Panel>
          </div>
        )}
      </div>
    </div>
  );
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="text-text-faint">{label}</dt>
      <dd className="text-text">{value}</dd>
    </div>
  );
}

function api_securityReport() {
  return import("@/lib/api").then((m) => m.api.securityReport());
}

function api_securityCheck() {
  return import("@/lib/api").then((m) => m.api.securityCheck());
}

function api_auditEvents() {
  return import("@/lib/api").then((m) => m.api.auditEvents("?limit=200"));
}

function api_verifyAudit() {
  return import("@/lib/api").then((m) => m.api.verifyAudit());
}