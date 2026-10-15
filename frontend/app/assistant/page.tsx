"use client";

import { useSearchParams } from "next/navigation";
import { useEffect, useState } from "react";
import { Search } from "lucide-react";

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
import { useI18n } from "@/lib/i18n";

const SUGGESTIONS = [
  "Find all TCP responses longer than 1000 bytes",
  "Show messages whose first two bytes match",
  "Find requests answered within 100 milliseconds",
  "Show streams with holes in the reconstructed bytes",
  "Find POST requests where HTTP content is visible",
];

export default function AssistantPage() {
  const workspace = useWorkspace();
  const { t } = useI18n();
  const params = useSearchParams();
  const projectId = params.get("project") ?? workspace.projectId;
  const [query, setQuery] = useState(params.get("q") ?? "");
  const [dryRun, setDryRun] = useState(true);
  const [useLlm, setUseLlm] = useState(false);
  const action = useAction();

  const capabilities = useAsync(() => api.assistantCapabilities(), []);
  const captures = useAsync(
    () => (projectId ? api.projectCaptures(projectId) : Promise.resolve([])),
    [projectId, workspace.revision],
  );
  const [corpus, setCorpus] = useState<string[]>([]);

  useEffect(() => {
    const fromUrl = params.get("q");
    if (fromUrl) setQuery(fromUrl);
  }, [params]);

  const result = action.pending ? null : (action as unknown as { result?: unknown }).result ?? null;

  return (
    <div className="flex h-full flex-col">
      <div className="border-b border-line px-4 py-3">
        <h1 className="text-sm font-semibold tracking-tight text-text">
          {t("Investigation Assistant")}
        </h1>
        <p className="mt-0.5 max-w-3xl text-2xs leading-relaxed text-text-muted">
          {t(
            "Your question is compiled into a typed query plan, validated against a field allowlist, and executed through a fixed analytics API. No SQL, shell command or Python is ever generated from text — yours or a model's.",
          )}
        </p>
      </div>

      <div className="grid min-h-0 flex-1 grid-cols-1 gap-3 overflow-auto p-3 lg:grid-cols-[1fr_360px]">
        <div className="space-y-3">
          <Panel title={t("Ask about the traffic")}>
            <div className="space-y-2 p-3">
              <textarea
                className="input h-20 resize-y"
                maxLength={1000}
                placeholder={t(SUGGESTIONS[0])}
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                aria-label={t("Search request")}
              />
              <div className="flex flex-wrap items-center gap-3">
                <label className="flex items-center gap-1.5 text-2xs text-text-muted">
                  <input
                    type="checkbox"
                    checked={dryRun}
                    onChange={(event) => setDryRun(event.target.checked)}
                  />
                  {t("dry run (show the plan without executing)")}
                </label>
                <label className="flex items-center gap-1.5 text-2xs text-text-muted">
                  <input
                    type="checkbox"
                    checked={useLlm}
                    onChange={(event) => setUseLlm(event.target.checked)}
                  />
                  {t("allow optional local model narration")}
                </label>
                <button
                  type="button"
                  className="btn btn-primary ml-auto"
                  disabled={!query.trim() || action.pending}
                  onClick={() =>
                    void action.run(() =>
                      api.assistantQuery({
                        query: query.trim(),
                        capture_ids: corpus,
                        dry_run: dryRun,
                        use_llm: useLlm,
                      }),
                    )
                  }
                >
                  <Search className="h-3 w-3" aria-hidden />
                  {action.pending ? t("Working…") : t("Run")}
                </button>
              </div>

              {(action.error || action.notice) && (
                <p
                  className={`font-mono text-2xs ${action.error ? "text-status-bad" : "text-status-ok"}`}
                >
                  {action.error ?? action.notice}
                </p>
              )}
            </div>
          </Panel>

          {result ? <ResultView result={result as Record<string, unknown>} /> : (
            <Panel>
              <EmptyState
                title={t("No result yet")}
                description={t(
                  "Start with a dry run: you will see exactly how the request was interpreted before anything is executed.",
                )}
              />
            </Panel>
          )}
        </div>

        <div className="space-y-3">
          <Panel title={t("Corpus")}>
            {captures.state === "loading" ? (
              <Skeleton rows={4} />
            ) : (
              <ul className="max-h-48 space-y-0.5 overflow-auto p-3">
                {(captures.data ?? []).map((capture) => (
                  <li key={capture.id}>
                    <label className="flex items-center gap-2 py-0.5 text-2xs">
                      <input
                        type="checkbox"
                        checked={corpus.includes(capture.id)}
                        onChange={(event) =>
                          setCorpus(
                            event.target.checked
                              ? [...corpus, capture.id]
                              : corpus.filter((id) => id !== capture.id),
                          )
                        }
                      />
                      <span className="truncate text-text">{capture.name}</span>
                    </label>
                  </li>
                ))}
                {(captures.data ?? []).length === 0 && (
                  <li className="text-2xs text-text-faint">
                    {t("No captures imported; the search will cover the whole index.")}
                  </li>
                )}
              </ul>
            )}
          </Panel>

          <Panel title={t("What this can and cannot do")}>
            {capabilities.state === "loading" ? (
              <Skeleton rows={6} />
            ) : capabilities.data ? (
              <div className="space-y-2 p-3 text-2xs">
                <p className="text-text-muted">
                  {String(capabilities.data.execution_model)}
                </p>
                <div>
                  <p className="text-text-faint">{t("queryable entities:")}</p>
                  <p className="font-mono text-text">
                    {((capabilities.data.entities ?? []) as string[]).join(", ")}
                  </p>
                </div>
                <div>
                  <p className="text-text-faint">{t("external AI:")}</p>
                  <Badge
                    tone={
                      (capabilities.data.external_ai as { enabled?: boolean })?.enabled
                        ? "warn"
                        : "ok"
                    }
                  >
                    {String((capabilities.data.external_ai as { default?: string })?.default ?? "")}
                  </Badge>
                  {/* Named, so an analyst knows *what* would be contacted - never
                      the key, which the API does not return. */}
                  {(() => {
                    const external = capabilities.data.external_ai as {
                      enabled?: boolean;
                      provider?: string | null;
                      model?: string | null;
                      configured?: boolean;
                    };
                    if (!external?.enabled) return null;
                    return (
                      <p className="mt-1 font-mono text-2xs text-text-faint">
                        {external.configured
                          ? t("Narration endpoint: {provider}", {
                              provider: String(external.provider ?? "?"),
                            })
                          : t(
                              "External AI is allowed, but no endpoint is configured; narration stays off.",
                            )}
                      </p>
                    );
                  })()}
                </div>
                <ul className="space-y-1">
                  {((capabilities.data.limitations ?? []) as string[]).map((item, index) => (
                    <li key={index} className="text-status-warn">
                      • {item}
                    </li>
                  ))}
                </ul>
              </div>
            ) : null}
          </Panel>

          <Panel title={t("Try one of these")}>
            <ul className="space-y-1 p-3">
              {SUGGESTIONS.map((suggestion) => (
                <li key={suggestion}>
                  <button
                    type="button"
                    className="link text-left text-2xs"
                    onClick={() => setQuery(suggestion)}
                  >
                    {t(suggestion)}
                  </button>
                </li>
              ))}
            </ul>
          </Panel>
        </div>
      </div>
    </div>
  );
}

function ResultView({ result }: { result: Record<string, unknown> }) {
  const { t } = useI18n();
  const status = String(result.status ?? "");

  if (status === "needs_clarification") {
    return (
      <Panel title={t("The assistant refused to guess")}>
        <div className="space-y-2 p-3">
          <Badge tone="warn">{t("needs clarification")}</Badge>
          <p className="text-2xs text-text">{String(result.question ?? "")}</p>
          <Caveat tone="warn">{String(result.note ?? "")}</Caveat>
          <ul className="space-y-1">
            {((result.suggestions ?? []) as string[]).map((item) => (
              <li key={item} className="font-mono text-2xs text-text-muted">
                {item}
              </li>
            ))}
          </ul>
        </div>
      </Panel>
    );
  }

  const plan = result.plan as Record<string, unknown> | undefined;
  const queryResult = result.result as Record<string, unknown> | undefined;

  return (
    <Panel title={t("Result")}>
      <div className="space-y-2 p-3">
        <div className="flex flex-wrap items-center gap-2">
          <Badge tone={result.executed ? "ok" : "info"}>
            {result.executed ? t("executed") : t("planned (dry run)")}
          </Badge>
          <span className="text-2xs text-text-muted">{String(result.interpretation ?? "")}</span>
        </div>

        {plan && (
          <div>
            <p className="mb-1 text-2xs uppercase tracking-wider text-text-faint">
              {t("Compiled query plan")}
            </p>
            <pre className="overflow-x-auto rounded-sm border border-line bg-surface-sunken p-2 font-mono text-2xs">
              {JSON.stringify(plan, null, 2)}
            </pre>
          </div>
        )}

        {Array.isArray(result.warnings) && (result.warnings as string[]).length > 0 && (
          <ul className="space-y-1">
            {(result.warnings as string[]).map((warning, index) => (
              <li key={index} className="text-2xs text-status-warn">
                ! {warning}
              </li>
            ))}
          </ul>
        )}

        {queryResult && (
          <div>
            <p className="mb-1 text-2xs uppercase tracking-wider text-text-faint">
              {t("{count} matching {entity}", {
                count: String(queryResult.count ?? 0),
                entity: String(queryResult.entity ?? t("records")),
              })}
            </p>
            <table className="data-table">
              <thead>
                <tr>
                  <th>{t("id")}</th>
                  <th>{t("stream")}</th>
                  <th>{t("direction")}</th>
                  <th>{t("range")}</th>
                  <th>{t("length")}</th>
                  <th>{t("entropy")}</th>
                </tr>
              </thead>
              <tbody>
                {((queryResult.items ?? []) as Record<string, unknown>[]).slice(0, 200).map(
                  (item, index) => (
                    <tr key={index}>
                      <td className="text-accent">{String(item.id ?? "").slice(0, 12)}</td>
                      <td className="text-text-faint">
                        {String(item.stream_id ?? "—").slice(0, 12)}
                      </td>
                      <td>{String(item.direction ?? "—")}</td>
                      <td className="text-text-muted">
                        {item.start_offset !== undefined
                          ? `${item.start_offset}…${item.end_offset}`
                          : "—"}
                      </td>
                      <td>{String(item.length ?? "—")}</td>
                      <td>
                        {item.entropy !== undefined
                          ? Number(item.entropy).toFixed(2)
                          : "—"}
                      </td>
                    </tr>
                  ),
                )}
              </tbody>
            </table>
          </div>
        )}

        {typeof result.llm === "object" && result.llm !== null && (
          <div className="rounded-sm border border-status-warn/30 bg-status-warn/5 p-2.5">
            <Badge tone="warn">{t("model narration")}</Badge>
            <p className="mt-1 whitespace-pre-wrap text-2xs text-text">
              {String((result.llm as { text?: string }).text ?? "")}
            </p>
            <Caveat tone="warn">
              {String(
                (result.llm as { disclaimer?: string }).disclaimer ??
                  t("Model-generated narration, not evidence."),
              )}
            </Caveat>
          </div>
        )}
      </div>
    </Panel>
  );
}