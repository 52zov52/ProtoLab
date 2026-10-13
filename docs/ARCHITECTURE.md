# Architecture

## Layers

```
frontend (Next.js 16, React 19, TypeScript strict, Tailwind 4)
   │  fetch, typed client, Zod validation on every response
   ▼
backend (FastAPI, Python 3.12+)
   │
   ├── api/            HTTP layer: routers, DI, middleware, security headers
   ├── services/       use cases: capture analysis, interpretation, jobs, archive
   ├── interpretation/ the specification schema and the bounded evaluator
   ├── analyzers/      pure analysis: reader, reassembly, framing, diff, TLS…
   ├── reporting/      report generation, typed query executor, LLM adapter
   ├── models/         SQLAlchemy entities
   └── core/           config, errors, logging, defensive helpers
   ▼
data/                 SQLite + immutable captures + stream artefacts
```

Dependencies point **downward only**. Analyzers know nothing about HTTP or the
database; services know nothing about the UI.

## Storage model

Metadata lives in SQLite. Binary payloads do **not**: a capture is stored once,
immutably, and derived artefacts are written beside it.

```
data/
  mplab.db                              SQLite: projects, packets, sessions,
                                        messages, hypotheses, runs, audit
  storage/<project_id>/
    captures/<capture_id>/
      original.pcap                     immutable upload, hashed at import
      streams.bin                       reconstructed bytes, all streams
      streams.json                      run offsets + contributing packets
      exports/                          generated PCAPNG, specs, reports
  secrets/                              (reserved; key logs are not ingested)
  logs/
```

Rationale: keeping 100 MB captures out of SQLite keeps the database small and
fast, and makes "the original bytes" a filesystem fact you can verify with
`sha256sum` rather than a row you must trust.

`streams.bin` plus `streams.json` is a run-length encoding of each direction:
contiguous byte runs with the packet indices that contributed them. A gap in
the stream is a gap in the runs, which is why holes cannot be silently filled
with zeros.

## Request pipeline

1. **Host header check** — rejects anything not on the allowlist. This is the
   DNS-rebinding defence.
2. **Origin check** — a request carrying a browser `Origin`/`Referer` outside
   the allowlist is rejected; state-changing requests require a matching
   origin.
3. **Body size limit** — from `Content-Length`, before parsing.
4. **Rate limit** — per-client sliding window.
5. **Dependency resolution** — one session per request, closed afterwards.
6. **Object resolution** — `load_project` / `load_capture` enforce that the
   object belongs to the addressed project.
7. **Handler**.
8. **Response headers** — `nosniff`, `X-Frame-Options: DENY`,
   `Referrer-Policy: no-referrer`, `no-store`.

Errors are converted to the uniform `{"error": {...}}` payload. Internal
exceptions never leak a traceback.

## Analysis pipeline

`CaptureAnalyzer.run()` performs:

1. **Index** packets with a streaming reader (PCAP and PCAPNG), enforcing size
   and count limits.
2. **Split** into TCP sessions. A 4-tuple is **not** sufficient: a capture that
   reuses the same addresses and ports yields two sessions. Flow roles are
   labelled `syn_observed` when a SYN proves them and
   `heuristic_first_payload` when it does not — a role is never asserted
   without evidence.
3. **Reassemble** each direction from sequence numbers, handling out-of-order
   delivery, retransmissions, overlaps, conflicts and holes. Conflicts are
   stored as diagnostics under a named, reproducible policy rather than being
   resolved silently.
4. **Frame** messages, if a rule is supplied.
5. **Detect** the protocol, heuristically, falling back to `unknown_binary`.
6. **Persist** metadata and artefacts.

### Why reassembly is written by hand

Having Scapy or TShark available does not prove a stream is reconstructed
correctly. The tests in `tests/test_tcp_reassembly.py` pin the behaviours that
matter: out-of-order delivery, byte-identical retransmission not duplicating
data, partial overlap extending the stream once, conflicting overlap producing
a diagnostic, gaps staying gaps, and sequence-number wraparound.

## Interpretation

`interpretation/engine.py` validates a specification into typed models and
walks them with a bounded evaluator. Bounds: 256 fields, nesting depth 4,
8192 repeat items, 256 KiB document. Unsupported constructs raise an explicit
error instead of being skipped.

This is the security boundary that stops an imported specification from
executing anything.

## Evidence model

Every conclusion carries the coordinates needed to re-check it:

```
project_id → capture_id → session_id → stream_id → message_id
          → stream byte range → packet indices → capture file offset
```

Results are not floats without provenance. `GET /streams/{id}/messages/{mid}/hex`
returns the message bytes **and** the packets that produced them, so an analyst
can always get back to the capture.

## Concurrency

- Synchronous analysis runs in a request.
- `POST /captures/{id}/analyze-async` queues a job bounded by a concurrency
  gate; `GET /jobs/{id}` polls and `POST /jobs/{id}/cancel` cancels.
- SQLite runs in WAL mode so a reader is not blocked by a writer.
- The rate limiter and job gate are in-process and therefore **single-process**;
  this is documented as a limitation rather than presented as distributed
  control.

## Schema lifecycle

The schema is versioned with Alembic (`backend/alembic`, current head `0001`).
`create_app` runs `Base.metadata.create_all` and then `alembic upgrade head`, so a
database made by an earlier build still opens: a database with tables but no
`alembic_version` row is **stamped** at head rather than migrated from scratch,
which would fail on the tables that already exist. `tests/test_migrations.py`
builds the schema from the migration and from the models into two throwaway
databases and compares them, so the two cannot drift apart silently.

Operators who manage the schema themselves run `alembic upgrade head` with
`MPLAB_AUTO_CREATE_SCHEMA=false`; the procedure is in `docs/UPGRADING.md`.

## Deployment

`docker-compose.yml` runs two services on loopback. The backend image is
non-root with a read-only root filesystem, `cap_drop: ALL` and no package
manager. The frontend is a multi-stage build with no dev dependencies in the
runtime image.

The compose file deliberately contains **no** database or cache service: the
application uses SQLite and the filesystem, and shipping a Postgres or Redis
the code never connects to would imply capabilities it does not have.