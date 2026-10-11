/**
 * Typed API client.
 *
 * Two rules this module exists to enforce:
 *   1. No request is ever sent with a server-controlled path segment. Callers
 *      pass identifiers, and they are validated before interpolation.
 *   2. No response body is trusted. Every payload is checked against a Zod
 *      schema before it reaches a component, so a malformed response becomes a
 *      visible error instead of a blank panel.
 */

import { z } from "zod";

export const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE ?? "http://127.0.0.1:8010";

const ID_PATTERN = /^[A-Za-z0-9]{1,64}$/;

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly details: unknown = null,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export function assertId(value: string, field: string): string {
  if (!ID_PATTERN.test(value)) {
    throw new ApiError(
      400,
      "invalid_identifier",
      `${field} is not a valid object identifier.`,
    );
  }
  return value;
}

// --------------------------------------------------------------------------
// Schemas
// --------------------------------------------------------------------------

export const PageSchema = z.object({
  items: z.array(z.record(z.string(), z.unknown())),
  total: z.number(),
  offset: z.number(),
  limit: z.number(),
  has_more: z.boolean(),
});
export type Page = z.infer<typeof PageSchema>;

export const ProjectSchema = z.object({
  id: z.string(),
  name: z.string(),
  description: z.string(),
  schema_version: z.number(),
  created_at: z.string(),
  updated_at: z.string(),
  settings: z.record(z.string(), z.unknown()),
});

export const ProjectSummarySchema = z.object({
  id: z.string(),
  name: z.string(),
  created_at: z.string(),
  updated_at: z.string(),
  capture_count: z.number(),
  hypothesis_count: z.number(),
  interpretation_count: z.number(),
  message_count: z.number(),
});

export const CaptureSchema = z.object({
  id: z.string(),
  project_id: z.string(),
  name: z.string(),
  sha256: z.string(),
  file_size: z.number(),
  format: z.string(),
  imported_at: z.string(),
  analysis_status: z.string(),
  diagnostics: z.record(z.string(), z.unknown()),
  stats: z.record(z.string(), z.unknown()),
  source_kind: z.string(),
  relative_path: z.string(),
});

export const ProjectMetricsSchema = z.object({
  project_id: z.string(),
  captures: z.number(),
  packets: z.number(),
  tcp_sessions: z.number(),
  streams: z.number(),
  messages: z.number(),
  hypotheses: z.number(),
  interpretations: z.number(),
  validation_runs: z.number(),
  counterexamples: z.number(),
  sessions_with_reconstruction_problems: z.number(),
  bytes_stored: z.number(),
  analyst_versions: z.record(z.string(), z.string()),
});

export const SessionSchema = z.object({
  id: z.string(),
  capture_id: z.string(),
  session_identity: z.string(),
  endpoint_a: z.string(),
  endpoint_b: z.string(),
  client_endpoint: z.string().nullable(),
  server_endpoint: z.string().nullable(),
  role_confidence: z.string(),
  start_time: z.number(),
  end_time: z.number(),
  completeness_status: z.string(),
  diagnostics: z.record(z.string(), z.unknown()),
  analyzer_version: z.string(),
});

export const StreamSchema = z.object({
  id: z.string(),
  session_id: z.string(),
  direction: z.string(),
  local_endpoint: z.string(),
  remote_endpoint: z.string(),
  stream_length: z.number(),
  present_bytes: z.number(),
  holes: z.array(z.record(z.string(), z.unknown())),
  coverage_map: z.array(z.record(z.string(), z.unknown())),
  diagnostics: z.record(z.string(), z.unknown()),
  conflicts: z.array(z.record(z.string(), z.unknown())),
  protocol_label: z.string(),
  protocol_confidence: z.number(),
  analyzer_version: z.string(),
});

export const MessageSchema = z.object({
  id: z.string(),
  stream_id: z.string(),
  index_in_stream: z.number(),
  start_offset: z.number(),
  end_offset: z.number(),
  present_length: z.number(),
  declared_length: z.number().nullable(),
  timestamp: z.number(),
  framing_method: z.string(),
  framing_rule_version: z.string(),
  confidence: z.number(),
  complete: z.boolean(),
  packet_references: z.array(z.record(z.string(), z.unknown())),
  diagnostics: z.record(z.string(), z.unknown()),
  features: z.record(z.string(), z.unknown()),
});

export const HexLineSchema = z.object({
  offset: z.number(),
  hex: z.array(z.string()),
  ascii: z.array(z.string()),
  length: z.number(),
});

export const InterpretationSchema = z.object({
  id: z.string(),
  project_id: z.string(),
  hypothesis_id: z.string().nullable(),
  name: z.string(),
  specification: z.record(z.string(), z.unknown()),
  version: z.number(),
  checksum: z.string(),
  created_at: z.string(),
  notes: z.string(),
});

export const ValidationRunSchema = z.object({
  id: z.string(),
  interpretation_id: z.string(),
  interpretation_name: z.string().nullable(),
  interpretation_version: z.number().nullable(),
  specification_checksum: z.string().nullable(),
  project_id: z.string(),
  corpus: z.record(z.string(), z.unknown()),
  settings: z.record(z.string(), z.unknown()),
  started_at: z.string(),
  completed_at: z.string().nullable(),
  status: z.string(),
  summary: z.record(z.string(), z.unknown()),
  stale: z.boolean(),
  stale_reason: z.string().nullable(),
  analyzer_version: z.string(),
});

// --------------------------------------------------------------------------
// Transport
// --------------------------------------------------------------------------

async function request<T>(
  path: string,
  schema: z.ZodType<T>,
  init?: RequestInit,
): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${API_BASE}${path}`, {
      ...init,
      cache: "no-store",
      headers: {
        Accept: "application/json",
        ...(init?.body && !(init.body instanceof FormData)
          ? { "Content-Type": "application/json" }
          : {}),
        ...init?.headers,
      },
    });
  } catch (cause) {
    throw new ApiError(
      0,
      "backend_unreachable",
      `The backend at ${API_BASE} did not respond. Is it running?`,
      String(cause),
    );
  }

  const text = await response.text();
  let payload: unknown = null;
  if (text) {
    try {
      payload = JSON.parse(text);
    } catch {
      payload = null;
    }
  }

  if (!response.ok) {
    const errorBody = (payload ?? {}) as {
      error?: { code?: string; message?: string; details?: unknown };
      detail?: unknown;
    };
    throw new ApiError(
      response.status,
      errorBody.error?.code ?? "http_error",
      errorBody.error?.message ??
        (typeof errorBody.detail === "string"
          ? errorBody.detail
          : `Request failed with status ${response.status}.`),
      errorBody.error?.details ?? errorBody.detail ?? null,
    );
  }

  const parsed = schema.safeParse(payload);
  if (!parsed.success) {
    throw new ApiError(
      response.status,
      "schema_mismatch",
      "The backend returned data that does not match the expected shape.",
      parsed.error.issues.slice(0, 6),
    );
  }
  return parsed.data;
}

const json = (body: unknown): RequestInit => ({
  method: "POST",
  body: JSON.stringify(body),
});

/**
 * Fetch a plain-text endpoint (Markdown/JSON exports).
 *
 * Errors are unwrapped the same way `request` does, so a failed export shows
 * the backend's message rather than a raw response body.
 */
async function fetchText(path: string): Promise<string> {
  let response: Response;
  try {
    response = await fetch(`${API_BASE}${path}`, {
      cache: "no-store",
      headers: { Accept: "text/plain" },
    });
  } catch (cause) {
    throw new ApiError(
      0,
      "backend_unreachable",
      `The backend at ${API_BASE} did not respond. Is it running?`,
      String(cause),
    );
  }
  const text = await response.text();
  if (!response.ok) {
    let message = `Request failed with status ${response.status}.`;
    try {
      const body = JSON.parse(text) as {
        error?: { message?: string };
        detail?: string;
      };
      message = body.error?.message ?? body.detail ?? message;
    } catch {
      /* keep the generic message for a non-JSON error body */
    }
    throw new ApiError(response.status, "http_error", message, null);
  }
  return text;
}

export const api = {
  health: () => request("/api/health", z.record(z.string(), z.unknown())),

  // -- projects ---------------------------------------------------------
  listProjects: () =>
    request("/api/projects", z.array(ProjectSummarySchema)),
  createProject: (name: string, description = "") =>
    request("/api/projects", ProjectSchema, {
      method: "POST",
      body: JSON.stringify({ name, description }),
    }),
  getProject: (id: string) =>
    request(`/api/projects/${assertId(id, "project_id")}`, ProjectSchema),
  updateProject: (id: string, body: Record<string, unknown>) =>
    request(`/api/projects/${assertId(id, "project_id")}`, ProjectSchema, {
      method: "PATCH",
      body: JSON.stringify(body),
    }),
  deleteProject: (id: string) =>
    request(`/api/projects/${assertId(id, "project_id")}`, z.never().or(z.null()), {
      method: "DELETE",
    }),
  metrics: (id: string) =>
    request(
      `/api/projects/${assertId(id, "project_id")}/metrics`,
      ProjectMetricsSchema,
    ),
  integrity: (id: string) =>
    request(
      `/api/projects/${assertId(id, "project_id")}/integrity`,
      z.record(z.string(), z.unknown()),
    ),

  // -- captures ---------------------------------------------------------
  importCapture: (projectId: string, file: File, name?: string) => {
    const form = new FormData();
    form.append("project_id", projectId);
    form.append("name", name ?? file.name);
    form.append("file", file);
    return request("/api/captures", CaptureSchema, {
      method: "POST",
      body: form,
    });
  },
  getCapture: (id: string) =>
    request(`/api/captures/${assertId(id, "capture_id")}`, CaptureSchema),
  projectCaptures: (projectId: string) =>
    request(
      `/api/projects/${assertId(projectId, "project_id")}/captures`,
      z.array(CaptureSchema),
    ),
  analyze: (id: string, options: Record<string, unknown> = {}) =>
    request(
      `/api/captures/${assertId(id, "capture_id")}/analyze`,
      z.record(z.string(), z.unknown()),
      json(options),
    ),
  analyzeAsync: (id: string) =>
    request(
      `/api/captures/${assertId(id, "capture_id")}/analyze-async`,
      z.object({ job_id: z.string(), status: z.string() }),
      { method: "POST" },
    ),
  listSessions: (captureId: string) =>
    request(
      `/api/captures/${assertId(captureId, "capture_id")}/sessions`,
      PageSchema,
    ),
  listMessages: (captureId: string, query = "") =>
    request(
      `/api/captures/${assertId(captureId, "capture_id")}/messages${query}`,
      PageSchema,
    ),
  listPackets: (captureId: string, query = "") =>
    request(
      `/api/captures/${assertId(captureId, "capture_id")}/packets${query}`,
      PageSchema,
    ),
  /** Original on-disk bytes of one packet, served from the immutable file. */
  async packetBytes(captureId: string, packetIndex: number): Promise<Uint8Array> {
    let response: Response;
    try {
      response = await fetch(
        `${API_BASE}/api/captures/${assertId(captureId, "capture_id")}/packets/${packetIndex}/raw`,
        { cache: "no-store", headers: { Accept: "application/octet-stream" } },
      );
    } catch (cause) {
      throw new ApiError(
        0,
        "backend_unreachable",
        `The backend at ${API_BASE} did not respond. Is it running?`,
        String(cause),
      );
    }
    if (!response.ok) {
      let message = `Request failed with status ${response.status}.`;
      try {
        const body = (await response.json()) as {
          error?: { message?: string };
          detail?: string;
        };
        message = body.error?.message ?? body.detail ?? message;
      } catch {
        /* keep the generic message for a non-JSON error body */
      }
      throw new ApiError(response.status, "http_error", message, null);
    }
    return new Uint8Array(await response.arrayBuffer());
  },
  deleteCapture: (id: string) =>
    request(`/api/captures/${assertId(id, "capture_id")}`, z.unknown(), {
      method: "DELETE",
    }),
  exportPcapng: (id: string) =>
    request(
      `/api/captures/${assertId(id, "capture_id")}/export-pcapng`,
      z.record(z.string(), z.unknown()),
      { method: "POST" },
    ),
  /** JA3/JA3S aggregated across every stream of a capture. */
  captureTls: (captureId: string) =>
    request(
      `/api/captures/${assertId(captureId, "capture_id")}/tls`,
      z.object({
        capture_id: z.string(),
        streams_scanned: z.number(),
        streams_total: z.number(),
        count: z.number(),
        unreliable_handshakes: z.number(),
        categories: z.record(z.string(), z.number()),
        verdict: z.object({
          client_fingerprints: z.number(),
          non_browser_matches: z.number(),
          statement: z.string(),
        }),
        fingerprints: z.array(
          z.object({
            kind: z.string(),
            md5: z.string(),
            raw: z.string(),
            family: z.string().nullable(),
            category: z.string(),
            confidence: z.string(),
            source: z.string().nullable(),
            interpretation: z.string().nullable(),
            versions: z.array(z.string()),
            sni: z.array(z.string()),
            alpn: z.array(z.string()),
            occurrences: z.number(),
            stream_ids: z.array(z.string()),
            example_offset: z.number().nullable(),
          }),
        ),
        fingerprint_database: z.string(),
        database: z.record(z.string(), z.unknown()),
        interpretation_note: z.string(),
      }),
    ),

  // -- sessions / streams ----------------------------------------------
  /** One TCP session. Also resolves which capture a ?session= link belongs to. */
  getSession: (sessionId: string) =>
    request(
      `/api/sessions/${assertId(sessionId, "session_id")}`,
      SessionSchema,
    ),
  timeline: (sessionId: string) =>
    request(
      `/api/sessions/${assertId(sessionId, "session_id")}/timeline`,
      z.record(z.string(), z.unknown()),
    ),
  diagnostics: (sessionId: string) =>
    request(
      `/api/sessions/${assertId(sessionId, "session_id")}/diagnostics`,
      z.record(z.string(), z.unknown()),
    ),
  sessionStreams: (sessionId: string) =>
    request(
      `/api/sessions/${assertId(sessionId, "session_id")}/streams`,
      z.array(StreamSchema),
    ),
  streamBytes: (streamId: string, offset: number, length: number) =>
    request(
      `/api/streams/${assertId(streamId, "stream_id")}/bytes?offset=${offset}&length=${length}`,
      z.object({
        stream_id: z.string(),
        offset: z.number(),
        stream_length: z.number(),
        present_bytes: z.number(),
        holes: z.array(
          z.object({
            start: z.number(),
            end: z.number(),
            length: z.number(),
            reason: z.string(),
          }),
        ),
        coverage: z.array(z.record(z.string(), z.number())),
        lines: z.array(HexLineSchema),
        packet_references: z.array(z.record(z.string(), z.unknown())),
      }),
    ),
  framingSuggestions: (streamId: string) =>
    request(
      `/api/streams/${assertId(streamId, "stream_id")}/framing-suggestions`,
      z.object({
        suggestions: z.array(
          z.object({
            method: z.string(),
            config: z.record(z.string(), z.unknown()),
            score: z.number(),
            evidence: z.record(z.string(), z.unknown()),
          }),
        ),
        disclaimer: z.string(),
      }),
    ),
  messageHex: (streamId: string, messageId: string) =>
    request(
      `/api/streams/${assertId(streamId, "stream_id")}/messages/${assertId(messageId, "message_id")}/hex`,
      z.object({
        message_id: z.string(),
        start_offset: z.number(),
        end_offset: z.number(),
        declared_length: z.number().nullable(),
        present_length: z.number(),
        complete: z.boolean(),
        hex: z.string(),
        lines: z.array(HexLineSchema),
        packet_references: z.array(z.record(z.string(), z.unknown())),
        features: z.record(z.string(), z.unknown()),
        diagnostics: z.record(z.string(), z.unknown()),
      }),
    ),
  compareMessages: (streamId: string, messageIds: string[]) =>
    request(
      `/api/streams/${assertId(streamId, "stream_id")}/compare`,
      z.record(z.string(), z.unknown()),
      json({ message_ids: messageIds }),
    ),
  fieldStatistics: (streamId: string) =>
    request(
      `/api/streams/${assertId(streamId, "stream_id")}/field-statistics`,
      z.record(z.string(), z.unknown()),
    ),
  /** JA3/JA3S observed in a stream. Works on encrypted sessions; needs no keys. */
  tlsFingerprints: (streamId: string) =>
    request(
      `/api/streams/${assertId(streamId, "stream_id")}/tls`,
      z.record(z.string(), z.unknown()),
    ),

  // -- research ---------------------------------------------------------
  hypotheses: (projectId: string) =>
    request(
      `/api/projects/${assertId(projectId, "project_id")}/hypotheses`,
      z.array(z.record(z.string(), z.unknown())),
    ),
  createHypothesis: (projectId: string, body: Record<string, unknown>) =>
    request(
      `/api/projects/${assertId(projectId, "project_id")}/hypotheses`,
      z.record(z.string(), z.unknown()),
      json(body),
    ),
  updateHypothesis: (
    projectId: string,
    hypothesisId: string,
    body: Record<string, unknown>,
  ) =>
    request(
      `/api/projects/${assertId(projectId, "project_id")}/hypotheses/${assertId(hypothesisId, "hypothesis_id")}`,
      z.record(z.string(), z.unknown()),
      { method: "PUT", body: JSON.stringify(body) },
    ),
  interpretations: (projectId: string) =>
    request(
      `/api/projects/${assertId(projectId, "project_id")}/interpreters`,
      z.array(InterpretationSchema),
    ),
  createInterpretation: (projectId: string, body: Record<string, unknown>) =>
    request(
      `/api/projects/${assertId(projectId, "project_id")}/interpreters`,
      InterpretationSchema,
      json(body),
    ),
  updateInterpretation: (
    projectId: string,
    interpretationId: string,
    body: Record<string, unknown>,
  ) =>
    request(
      `/api/projects/${assertId(projectId, "project_id")}/interpreters/${assertId(interpretationId, "interpretation_id")}`,
      InterpretationSchema,
      { method: "PUT", body: JSON.stringify(body) },
    ),
  interpretationSupport: (projectId: string) =>
    request(
      `/api/projects/${assertId(projectId, "project_id")}/interpretation-support`,
      z.record(z.string(), z.unknown()),
    ),
  validate: (
    projectId: string,
    interpretationId: string,
    body: Record<string, unknown>,
  ) =>
    request(
      `/api/projects/${assertId(projectId, "project_id")}/interpreters/${assertId(interpretationId, "interpretation_id")}/validate`,
      z.record(z.string(), z.unknown()),
      json(body),
    ),
  validationRun: (runId: string) =>
    request(
      `/api/validation-runs/${assertId(runId, "run_id")}`,
      ValidationRunSchema,
    ),
  counterexamples: (runId: string) =>
    request(
      `/api/validation-runs/${assertId(runId, "run_id")}/counterexamples`,
      z.object({
        run_id: z.string(),
        count: z.number(),
        counterexamples: z.array(z.record(z.string(), z.unknown())),
        disclaimer: z.string(),
      }),
    ),

  // -- experiments ------------------------------------------------------
  importExperiments: (projectId: string, events: unknown[]) =>
    request(
      `/api/projects/${assertId(projectId, "project_id")}/experiments`,
      z.object({ imported: z.number(), project_id: z.string() }),
      json({ events }),
    ),
  experiments: (projectId: string) =>
    request(
      `/api/projects/${assertId(projectId, "project_id")}/experiments`,
      z.array(z.record(z.string(), z.unknown())),
    ),

  // -- analytics --------------------------------------------------------
  diff: (body: Record<string, unknown>) =>
    request("/api/captures/diff", z.record(z.string(), z.unknown()), json(body)),
  graph: (captureIds: string[]) =>
    request(
      "/api/network/graph",
      z.record(z.string(), z.unknown()),
      json({ capture_ids: captureIds }),
    ),
  anomaliesStatus: () =>
    request("/api/anomalies/status", z.record(z.string(), z.unknown())),
  anomaliesModels: (projectId: string) =>
    request(
      `/api/anomalies/models?project_id=${assertId(projectId, "project_id")}`,
      z.array(z.record(z.string(), z.unknown())),
    ),
  anomaliesTrain: (body: Record<string, unknown>) =>
    request("/api/anomalies/train", z.record(z.string(), z.unknown()), json(body)),
  anomaliesScore: (body: Record<string, unknown>) =>
    request("/api/anomalies/score", z.record(z.string(), z.unknown()), json(body)),
  assistantCapabilities: () =>
    request("/api/assistant/capabilities", z.record(z.string(), z.unknown())),
  assistantQuery: (body: Record<string, unknown>) =>
    request("/api/assistant/query", z.record(z.string(), z.unknown()), json(body)),

  // -- output -----------------------------------------------------------
  report: (projectId: string, body: Record<string, unknown>) =>
    request(
      `/api/projects/${assertId(projectId, "project_id")}/reports`,
      z.record(z.string(), z.unknown()),
      json(body),
    ),
  reports: (projectId: string) =>
    request(
      `/api/projects/${assertId(projectId, "project_id")}/reports`,
      z.array(z.record(z.string(), z.unknown())),
    ),
  /** Fetch one generated report by id (the stored result, not a new run). */
  getReport: (reportId: string) =>
    request(
      `/api/reports/${assertId(reportId, "report_id")}`,
      z.record(z.string(), z.unknown()),
    ),
  reportMarkdown: (reportId: string) =>
    fetchText(`/api/reports/${assertId(reportId, "report_id")}/markdown`),
  exportProject: (projectId: string) =>
    request(
      `/api/projects/${assertId(projectId, "project_id")}/export`,
      z.record(z.string(), z.unknown()),
      json({ include_captures: true, include_reports: true }),
    ),
  importProject: (file: File, name?: string) => {
    const form = new FormData();
    if (name) form.append("name", name);
    form.append("file", file);
    return request("/api/projects/import", z.record(z.string(), z.unknown()), {
      method: "POST",
      body: form,
    });
  },

  // -- security ---------------------------------------------------------
  securityReport: () => request("/api/security/report", z.record(z.string(), z.unknown())),
  securityCheck: () =>
    request("/api/security/check", z.record(z.string(), z.unknown()), {
      method: "POST",
    }),
  auditEvents: (query = "") =>
    request(`/api/audit/events${query}`, PageSchema),
  verifyAudit: () =>
    request("/api/audit/verify", z.record(z.string(), z.unknown())),

  // -- jobs -------------------------------------------------------------
  jobs: (query = "") => request(`/api/jobs${query}`, z.array(z.record(z.string(), z.unknown()))),
  job: (id: string) =>
    request(`/api/jobs/${assertId(id, "job_id")}`, z.record(z.string(), z.unknown())),
};

export type Api = typeof api;