# Threat model

Scope: the Madrigal Protocol Lab local application as built in this repository.

This document describes what is defended, how, and — as importantly — what is
**not** defended. It is not a certification. Every control listed here has a
corresponding check in the test suite and a line in
[SECURITY.md](SECURITY.md); anything unverified is marked as such.

## 1. Assets

| Asset | Why it matters | Where it lives |
|---|---|---|
| Imported capture files | May contain confidential payloads; the source of every conclusion | `data/storage/<project>/captures/` |
| SHA-256 manifest | The only means of detecting silent modification | SQLite + `streams.json` |
| Derived interpretations | The deliverable; an incorrect one misleads the investigation | SQLite |
| Audit log | Evidence of what was done and by whom | SQLite `audit_events` |
| TLS key logs | Master secrets for observed sessions | Not implemented; see §6 |
| The analyst's notes and hypotheses | Reasoning that may not be shareable | SQLite |
| The host machine | Compromise here defeats every control in this document | — |

## 2. Trust boundaries

```
┌─ Browser (untrusted) ────────────┐
│  React UI. The analyst is trusted;│
│  capture content is NOT.         │
└──────────────┬───────────────────┘
               │  HTTP, Origin/Host checked
┌──────────────▼───────────────────┐
│  FastAPI on 127.0.0.1            │  ← the enforcement point
│  - Host allowlist                │
│  - Origin allowlist + CSRF       │
│  - body size, rate limits        │
│  - per-project object ownership  │
└──────────────┬───────────────────┘
               │  in-process calls
┌──────────────▼───────────────────┐
│  Analyzers (UNTRUSTED INPUT)     │  ← highest risk area
│  PCAP parser, TCP reassembly,    │
│  archive extraction              │
└──────────────┬───────────────────┘
               │
┌──────────────▼───────────────────┐
│  SQLite + filesystem artefacts   │  never web-served
└──────────────────────────────────┘
```

Two boundaries matter most:

1. **Browser → API.** A page on any other site must not be able to drive the
   local API. Enforced by the Host allowlist (defeats DNS rebinding) and the
   Origin allowlist with a same-origin requirement on state-changing requests.
2. **Bytes → analyzer.** Every byte in a capture, and every entry in a `.mplab`
   archive, is attacker-controlled. Parsers must fail safely and must never
   execute what they read.

## 3. Threats, mitigations and residual risk

### T1 — Malformed capture causes a parser crash, hang, or memory blowup
**Likelihood:** high (inputs are routinely hostile). **Impact:** denial of service.

The reader streams packets and enforces `MPLAB_MAX_PACKET_BYTES`,
`MPLAB_MAX_PACKETS_PER_CAPTURE`, `MPLAB_MAX_CAPTURE_BYTES` and
`MPLAB_MAX_TCP_SESSIONS_PER_CAPTURE`. Truncated and corrupt structures raise
`UnsupportedFormat`/`LimitExceeded` rather than being silently accepted.
*Residual:* a pathological but sub-limit file can still consume noticeable CPU;
limits bound memory but not time.

*Test:* `test_api_flows.py` imports a 68-byte non-capture and asserts a clean
error; the reassembly tests feed truncated records.

### T2 — Archive bomb, path traversal, or symlink in a `.mplab` import
**Likelihood:** medium. **Impact:** arbitrary file write outside the project.

Every member name is validated with `validate_relative_path` before extraction
(rejecting absolute paths, drive letters, `..`, control characters, over-long
names). Entry count, per-entry size, total uncompressed size, compression ratio
and directory depth are all bounded. Symlinks are rejected. Nothing is
overwritten: a new project is created only after every hash verifies.
*Residual:* a TOCTOU window exists between validation and extraction, closed by
staging into a private temporary directory and moving only after validation.

*Test:* `project_archive.py` limits; traversal is covered by
`test_traversal_filename_is_rejected`.

### T3 — Injection through filenames, packet metadata, comments or search text
**Likelihood:** medium. **Impact:** script execution in the UI, or SQL injection.

* **SQL:** every query is built through the SQLAlchemy expression language with
  bound parameters. The assistant never builds SQL from user text — it compiles
  a typed query object validated against an allowlist (§T8).
* **XSS:** React escapes by default; `dangerouslySetInnerHTML` is not used
  anywhere. Markdown is rendered as text. The UI also sends
  `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy:
  no-referrer` and a restrictive CSP.

*Residual:* none identified for stored XSS; the CSP is not a substitute for
escaping and is treated as defence in depth.

### T4 — Command injection via external tooling
**Likelihood:** low (no shell invocation in the current build). **Impact:** RCE.

No capture-derived value ever reaches a shell. Arguments, where a subprocess is
used at all, are passed as a list; no `shell=True` appears in the codebase.

*Residual:* TShark is not currently invoked. If it is added, it must receive a
managed path, a pinned version, a timeout and a fixed argument list.

### T5 — Localhost service driven by another site, or DNS rebinding
**Likelihood:** high (this is the standard attack on local tools). **Impact:**
full access to the API and its data.

A request whose `Host` is not on the allowlist is rejected with 403 — this is
what defeats rebinding, since the attacker controls the name that resolves to
127.0.0.1. Requests carrying a browser `Origin`/`Referer` outside the allowlist
are rejected, and a state-changing request must carry a matching `Origin`.

*Residual:* binding to loopback blocks remote access but not other local
processes. A malicious program running as the same user can call the API
directly; it is outside this application's control.

*Test:* `test_unknown_host_header_is_rejected`,
`test_cross_origin_request_is_rejected`, `test_allowed_origin_is_accepted`.

### T6 — Unauthorised access to another project's objects
**Likelihood:** low in local mode. **Impact:** data disclosure.

Every lookup resolves through `load_project` / `load_capture` /
`load_hypothesis` / `capture_in_project`, which raise `NotFound` when the object
does not belong to the addressed project. The client only ever passes
identifiers, which are validated against `^[A-Za-z0-9]{1,64}$` before
interpolation; the server never accepts a filesystem path from the client.

*Residual:* this is **ownership scoping, not authentication**. There are no
users, so any caller that reaches the API has full access to every project.

*Test:* `test_object_ownership_is_enforced`.

### T7 — Secrets leaking through logs, reports, errors or AI context
**Likelihood:** medium. **Impact:** credential disclosure.

A redaction filter sits on the root log handler and masks values whose key
matches a credential pattern, plus JWTs, TLS key-log lines and long hex blobs.
Exceptions are converted to a fixed message; stack traces, environment values
and absolute paths are never returned to the client. External AI is disabled by
default and, when enabled, receives only aggregated statistics — never capture
bytes, key logs or secrets.

*Residual:* redaction is pattern-based and best-effort. A secret in an
unrecognised format, or in a free-text analyst note, can still be logged. It is
a safety net, not a DLP system.

### T8 — Prompt injection or code execution via the assistant
**Likelihood:** medium. **Impact:** arbitrary query execution or data exfiltration.

Natural-language queries are parsed into a **typed** query object
(`entity`, `filters[]`, `sort`, `limit`) validated against an allowlist of
fields and operators. No Python, SQL or shell is generated from user text.
Unparseable input returns `needs_clarification` with suggestions instead of a
guess.

*Residual:* the parser can misinterpret intent; it cannot execute anything.

*Test:* `test_assistant_cannot_be_used_to_run_code` submits
`'; DROP TABLE packets; --` and asserts the schema survives.

### T9 — Denial of service through expensive or repeated requests
**Likelihood:** medium. **Impact:* API unavailability.

A per-client sliding-window rate limiter, a concurrency gate on analysis jobs,
request body size caps, archive limits and page-size caps are enforced in the
API process.

*Residual:* the limiter is **in-process and per-process**. It is not a
distributed control and resets when the process restarts. A remote deployment
must place a real limiter in front.

### T10 — Tampering with a capture after verification
**Likelihood:** medium. **Impact:** conclusions silently become false.

SHA-256 is computed at import and re-verified on demand
(`GET /projects/{id}/integrity`), and `GET /captures/{id}/packets/{n}/raw`
serves bytes read back from the original file, not from a database copy.

*Residual:* SHA-256 detects *change* only against a trusted reference. It does
not prove provenance and provides no confidentiality: an attacker who can edit
both the file and the database defeats it.

*Test:* `test_integrity_check_detects_modification` flips one byte and asserts
the mismatch is reported.

### T11 — Data leaving the machine
**Likelihood:** low by default. **Impact:** confidentiality loss.

No outbound connection is made by the application. `MPLAB_ALLOW_EXTERNAL_AI`
defaults to false; the Security Center reports the state of every integration
rather than assuming it is off.

*Residual:* the browser can reach whatever the analyst points it at, and the
host firewall is outside this application's control.

### T12 — Tampering with the audit log
**Likelihood:** low. **Impact:** loss of non-repudiation.

Audit entries are hash-chained: each entry hashes its contents together with the
previous entry's hash, and `GET /api/audit/verify` re-computes the chain.

*Residual — stated plainly:* **this is not tamper-proof.** A local administrator
with write access can rewrite the rows and the chain state together. The chain
detects accidental or naive modification, not a determined local attacker. It
is not an append-only external log and provides no cryptographic
non-repudiation.

## 4. What is explicitly NOT implemented

These are stated so the boundary is not misread:

- **Authentication and authorisation.** No login, no roles, no per-user
  isolation. `team_remote` mode exists as a configuration value but is *not* a
  turnkey multi-user deployment; it requires a reverse proxy providing
  authentication, CSRF protection and TLS.
- **At-rest encryption of projects.** Data is stored unencrypted, relying on
  filesystem permissions. There is no password-derived project key.
- **TLS key-log ingestion and decryption.** See [LIMITATIONS.md](LIMITATIONS.md).
- **Per-capture process isolation.** Capture parsing runs in the API process by
  default. The Docker deployment improves this (non-root, read-only rootfs, no
  capabilities) but a container is not an absolute boundary.
- **Secret scanning of capture payloads.** The Security Center scans project
  *text* files for key-like material; binary captures are skipped, so a secret
  inside a payload is not detected.

## 5. Verification

| Property | Checked by |
|---|---|
| Foreign `Host` rejected | `test_unknown_host_header_is_rejected` |
| Cross-origin request rejected | `test_cross_origin_request_is_rejected` |
| Allowed origin accepted | `test_allowed_origin_is_accepted` |
| Security headers present | `test_security_headers_are_present` |
| Oversized upload rejected | `test_oversized_upload_is_rejected` |
| Traversal filename contained | `test_traversal_filename_is_rejected` |
| Cross-project access refused | `test_object_ownership_is_enforced` |
| Assistant cannot execute code | `test_assistant_cannot_be_used_to_run_code` |
| Capture modification detected | `test_integrity_check_detects_modification` |
| Audit chain verifies | `test_audit_log_records_and_verifies` |
| Live-server posture | `scripts/live_check.py` |

A property with no automated check is described in [SECURITY.md](SECURITY.md)
as unverified rather than as passing.