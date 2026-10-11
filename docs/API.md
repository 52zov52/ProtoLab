# REST API

Base URL `http://127.0.0.1:8010/api` (loopback only by default).

Interactive documentation is served at `/api/docs` in local secure mode, and the
OpenAPI schema at `/api/openapi.json`.

## Conventions

- **Identifiers only.** No endpoint accepts a filesystem path. Clients pass
  object identifiers, validated server-side against `^[A-Za-z0-9]{1,64}$`.
- **Pagination.** List endpoints accept `offset` and `limit` and return
  `{items, total, offset, limit, has_more}`.
- **Errors** are uniform:
  ```json
  {"error": {"code": "not_found", "message": "...", "details": {}}}
  ```
  Codes: `validation_failed` (400), `semantic_validation_failed` (422),
  `security_violation` (403), `not_found` (404), `conflict` (409),
  `limit_exceeded` / `payload_too_large` (413), `unsupported_format` (415),
  `rate_limited` (429), `dependency_unavailable` (503),
  `internal_error` (500).
- **No secrets in responses.** Stack traces, environment values and absolute
  paths outside managed storage are never returned.
- **Rate limiting.** A per-client sliding window (default 300 requests / 60 s)
  applies to all endpoints; exceeding it returns 429.

---

## System

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | Liveness, mode, bind address |

## Projects

| Method | Path | Purpose |
|---|---|---|
| GET | `/projects` | List projects with live counters |
| POST | `/projects` | Create a project |
| GET | `/projects/{project_id}` | Fetch one project |
| PATCH | `/projects/{project_id}` | Update name/description; merge settings (e.g. AI consent) |
| DELETE | `/projects/{project_id}` | Delete a project and its artefacts |
| GET | `/projects/{project_id}/metrics` | Live counts (packets, sessions, messages, counterexamples …) |
| GET | `/projects/{project_id}/captures` | Captures in the project |
| GET | `/projects/{project_id}/integrity` | Re-verify SHA-256 of every capture |
| POST | `/projects/{project_id}/export` | Build a `.mplab` archive |
| POST | `/projects/import` | Import a `.mplab` archive as a **new** project |

Every metric in `/metrics` is computed live. An empty project reports zeros; no
value is seeded, cached or estimated.

## Captures

| Method | Path | Purpose |
|---|---|---|
| POST | `/captures` | Upload (multipart: `file`, `project_id`, `name`) |
| GET | `/captures/{capture_id}` | Metadata, hash, analysis status |
| DELETE | `/captures/{capture_id}` | Remove the capture and its artefacts |
| POST | `/captures/{capture_id}/rename` | Change the display name |
| POST | `/captures/{capture_id}/analyze` | Index, split, reassemble, frame (synchronous) |
| POST | `/captures/{capture_id}/analyze-async` | Same, as a background job |
| GET | `/captures/{capture_id}/packets` | Paginated packet list with filters |
| GET | `/captures/{capture_id}/packets/{packet_index}/raw` | Original on-disk bytes of one packet |
| GET | `/captures/{capture_id}/sessions` | TCP sessions |
| GET | `/captures/{capture_id}/messages` | Framed messages |
| POST | `/captures/{capture_id}/export-pcapng` | Annotated PCAPNG with round-trip check |
| GET | `/captures/{capture_id}/tls` | JA3/JA3S aggregated across the capture's streams |
| GET | `/network/captures/{capture_id}/graph` | Graph scoped to one capture |
| POST | `/captures/diff` | Compare two captures |

`POST /analyze` accepts an optional framing rule:

```json
{
  "framing": {
    "method": "length_prefix",
    "config": {
      "length_offset": 0, "length_size": 2,
      "endianness": "big", "includes_header": "true",
      "max_length": 65535
    }
  },
  "detect_protocol": true
}
```

## Sessions and streams

| Method | Path | Purpose |
|---|---|---|
| GET | `/sessions/{session_id}` | Session metadata and role evidence |
| GET | `/sessions/{session_id}/streams` | Reconstructed streams (both directions) |
| GET | `/sessions/{session_id}/messages` | Messages across the session's streams |
| GET | `/sessions/{session_id}/timeline` | Observed TCP state timeline |
| GET | `/sessions/{session_id}/diagnostics` | Retransmissions, overlaps, holes, conflicts |
| GET | `/streams/{stream_id}` | Stream metadata |
| GET | `/streams/{stream_id}/bytes` | Hex window, coverage map, gaps, provenance |
| GET | `/streams/{stream_id}/messages` | Framed messages |
| GET | `/streams/{stream_id}/messages/{message_id}/hex` | One message with its source packets |
| GET | `/streams/{stream_id}/framing-suggestions` | Candidate framing rules with scores |
| GET | `/streams/{stream_id}/field-statistics` | Per-offset statistics and candidates |
| GET | `/streams/{stream_id}/tls` | JA3 / JA3S fingerprints |
| POST | `/streams/{stream_id}/compare` | Compare several messages offset by offset |

`/bytes` returns `holes` with a `reason` for each gap (`missing_segments`).
Missing bytes are never replaced with zeros.

## Hypotheses and interpretations

Project-scoped (canonical):

| Method | Path |
|---|---|
| GET/POST | `/projects/{project_id}/hypotheses` |
| GET/PUT | `/projects/{project_id}/hypotheses/{hypothesis_id}` |
| GET | `/projects/{project_id}/interpretation-support` |
| GET/POST | `/projects/{project_id}/interpreters` |
| GET | `/projects/{project_id}/interpretations` |
| GET/PUT/PATCH | `/projects/{project_id}/interpreters/{interpretation_id}` |
| POST | `/projects/{project_id}/interpreters/{interpretation_id}/validate` |
| GET | `/projects/{project_id}/validation-runs` |
| GET | `/projects/{project_id}/validation-runs/{run_id}` |
| GET | `/projects/{project_id}/validation-runs/{run_id}/counterexamples` |

Flat aliases for the create/update/validate paths named in the API
specification. These carry no project prefix, so pass `project_id` as a **query
parameter** where it is needed. Reading an interpretation uses the
project-scoped route.

| Method | Path |
|---|---|
| POST | `/interpreters` (`?project_id=…`) |
| PUT | `/interpreters/{interpretation_id}` |
| POST | `/interpreters/{interpretation_id}/validate` |
| GET | `/validation-runs/{run_id}` |
| GET | `/validation-runs/{run_id}/counterexamples` |

> The project-scoped routes are canonical. The flat aliases exist so the paths
> named in the API specification work directly.

A validation response:

```json
{
  "run_id": "…", "verdict": "consistent_with_corpus",
  "total": 21, "matched": 21, "partial": 0, "failed": 0,
  "unparsed": 0, "counterexamples": 0,
  "by_message_type": {"read_request": 4, "set_request": 2}
}
```

`verdict` is one of `consistent_with_corpus`, `partially_consistent`,
`contradicted`, `no_data`, `canceled`. Editing a specification marks previous
runs `stale` with a `stale_reason`.

## Experiments

| Method | Path |
|---|---|
| POST | `/projects/{project_id}/experiments` |
| GET | `/projects/{project_id}/experiments` |

Accepts `{"events": [{"timestamp", "action", "parameters", "observed_result"}]}`.
An unparseable timestamp returns 422.

## Jobs

| Method | Path |
|---|---|
| GET | `/jobs` |
| GET | `/jobs/{job_id}` |
| POST | `/jobs/{job_id}/cancel` |

## Assistant

| Method | Path | Purpose |
|---|---|---|
| GET | `/assistant/capabilities` | What the assistant can and cannot do |
| POST | `/assistant/query` | Compile and run a typed query |
| POST | `/assistant/explain` | Explain the parsed interpretation |
| POST | `/assistant/jwt` | Decode a JWT (decode ≠ verify) |

`POST /assistant/query` accepts `dry_run` to return the plan without executing
it. An unparseable request returns `status: "needs_clarification"` with
suggestions rather than guessing.

## Anomalies

| Method | Path |
|---|---|
| GET | `/anomalies/status` |
| GET | `/anomalies/models` |
| POST | `/anomalies/train` |
| POST | `/anomalies/score` |

Returns 503 `dependency_unavailable` when `scikit-learn` is not installed.

## Reports

| Method | Path |
|---|---|
| POST | `/projects/{project_id}/reports` |
| POST | `/reports/generate` |
| GET | `/projects/{project_id}/reports` |
| GET | `/reports/{report_id}` |
| GET | `/reports/{report_id}/markdown` |
| GET | `/reports/{report_id}/json` |

## Network graph

| Method | Path |
|---|---|
| POST | `/network/graph` |
| GET | `/network/captures/{capture_id}/graph` |

## Audit and security

| Method | Path |
|---|---|
| GET | `/audit/events` |
| GET | `/audit/verify` |
| GET | `/audit/export` |
| GET | `/audit/actions` |
| POST | `/security/check` (audited) |
| GET | `/security/report` (read-only) |
| GET | `/security/summary` |
| POST | `/security/host-header` |
| POST | `/security/origin` |