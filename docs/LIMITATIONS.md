# Limitations

What this build does not do, and where a result stops being trustworthy.

This document exists because a tool that hides its limits cannot be trusted
with evidence. Nothing here is a plan to be completed later; it is the current
state.

---

## Not implemented

### TLS decryption via `SSLKEYLOGFILE`

**Fingerprinting works; decryption does not.**

JA3 and JA3S are computed from the plaintext handshake, so they work on an
encrypted session and need no keys — see
`GET /api/streams/{id}/tls`. What is **not** built is ingestion of a TLS key
log, key matching against observed sessions, and decryption of application
records.

There is deliberately no half-implementation: no fake "decrypted" view, and no
synthetic plaintext. A capture analysis of an encrypted protocol stops at the
handshake and says so.

Implementing it properly means delegating to a real TLS analyser with a
managed key-log path, matching keys to observed sessions, and reporting
per-session why decryption failed. It also means treating key logs as secrets:
owner-only storage, excluded from logs, reports and AI context.

### Authentication, authorisation and multi-user operation

There are no users, no login and no roles. `team_remote` mode exists as a
configuration value but is **not** a deployment: enabling it without a reverse
proxy providing authentication, CSRF protection and TLS would expose an
unauthenticated analysis API to the network.

### Encryption at rest

Projects are stored unencrypted, relying on filesystem permissions. There is no
password-derived project key, and no claim of confidentiality for captures on
disk. On Windows the POSIX permission model does not apply, so the Security
Center reports `unknown` rather than claiming the data is restricted.

### PDF report export

Reports export as Markdown and JSON. There is no PDF renderer.

### Extra protocol detectors beyond the built-in registry

The registry recognises HTTP/1.1, HTTP/2, gRPC over HTTP/2, MQTT, WebSocket,
DNS-over-TCP, TLS and unknown binary streams. It is extensible in structure,
but there is no plugin loader and no user-installable detector.

---

## Implemented with real constraints

These work, with limits worth knowing.

### Anomaly detection is optional

Requires `scikit-learn`:

```bash
pip install -e "backend[analytics]"
```

Without it the endpoints return `503 dependency_unavailable` and the UI shows
how to install it. Nothing degrades silently and **no invented scores are ever
returned**.

Scores rank unusualness within the chosen baseline. They are **not**
probabilities and carry no severity. The seed and model parameters are stored
so a run can be reproduced.

### Protocol detection is heuristic

A classification lists the signals that fired and the checks that did not pass.
When nothing is confirmed the result is `unknown_binary` — never a guess.

High entropy is **not** treated as proof of encryption: compression and
ordinary binary structures are also high-entropy.

### Anomaly and centrality findings are leads, not attributions

A high-centrality node is reported as a *candidate for further examination*,
with the basis stated. It is never called a C2 server, and a JA3 match is never
called malware.

### TLS fingerprint database is small and local

`FINGERPRINT_DB` in `tls_fingerprinting.py` holds a handful of clearly-sourced
entries. A match means "this hash is published for this client family" — not a
claim about the implementation language, and never an indication of
maliciousness. It is extensible by editing the table.

### The assistant compiles typed queries, not answers

Natural language becomes a validated query object with an allowlist of fields
and operators. It cannot execute code, and it returns
`needs_clarification` with suggestions when it cannot parse a request. It will
not answer a question the captured data cannot support.

### Reassembly has a named conflict policy

When two segments disagree about the same sequence range, the chosen policy is
recorded and reproducible, and the conflict is stored as a diagnostic. No
byte is discarded silently. Which policy is "right" is a judgement call the UI
surfaces rather than hides.

### Performance profile

Designed against captures up to ~100 MiB, ~250 000 packets, ~1000 sessions and
~100 000 messages on 4 vCPU / 8 GiB. Large tables are paginated and virtualized;
the browser never loads a whole capture.

This is now measured, not only designed: [PERFORMANCE.md](PERFORMANCE.md) records
a run on a 77 MiB / 246 000-packet / 1000-session / 240 000-message capture
(≈6 minutes, ≈1.4 GiB peak RSS on the benchmark machine, dominated by message
handling). The synchronous `/analyze` path blocks; large captures can be run
through the cancellable background job (`/api/captures/{id}/analyze-async`).

Exceeding a limit produces an **explicit error naming the limit** — data is
never silently truncated. Screens that hit a ceiling say what was not analysed.

### Isolation

Capture parsing runs in the API process in a local run. The Docker deployment
improves this — non-root, read-only root filesystem, `cap_drop: ALL`, no
package manager in the image — but a container is not an absolute security
boundary, and no claim is made that it is.

### Audit log integrity

Entries are hash-chained, which detects naive modification. It is **not**
tamper-proof: an administrator with file access can rewrite the rows and the
chain together. There is no external append-only sink.

### Rate limiting

In-process and per-process. Not a distributed control, and it resets when the
process restarts. A remote deployment needs a real limiter in front.

---

## Things the tool deliberately will not do

- **Detect a protocol from the port number alone.**
- **Zero-fill a gap.** A lost segment stays a hole.
- **Report an unreliable TLS fingerprint with a hash.** A truncated handshake
  gets `md5: null` and a reason.
- **Align different-length messages without saying how.** The alignment method
  is returned with the comparison, and absent bytes are rendered as *absent*.
- **Call a difference from baseline an anomaly.** The diff view says explicitly
  that a difference is not, by itself, suspicious.
- **Accept a specification silently.** An unsupported construct is a loud
  error, never a skipped field.
- **Reinterpret an unknown schema version.**
- **Claim a hypothesis is proven.** "Consistent with corpus" is what the tool
  reports, and the field statistics say the same thing in prose.

---

## Dependencies

`npm audit` currently reports **4 high** advisories, all in
`@next/eslint-plugin-next`'s transitive tree (`braces`, `fast-glob`,
`micromatch`). These are **dev-only lint tooling**: they are not imported by the
application and the runtime container installs with `--omit=dev`, so they are
not present in the shipped image. There is no patched version of the plugin
pinned to Next 16.4.0 at the time of writing.

The same audit was run before the upgrade from Next 15.5.3, which carried a
**critical** RCE in the React flight protocol; that one was fixed.

A clean scan is a snapshot in time, not proof that no vulnerability exists, and
it does not cover container base images. `pip-audit` is not installed in this
environment, so the Python dependency tree has **not** been scanned — the
Security Center reports this as `unknown` rather than `pass`.

---

## Frontend libraries that were specified but not used

The brief named Monaco Editor, TanStack Table, D3/Cytoscape and Recharts. None
is imported by the current code, so they were **removed** rather than left as
unused dependencies:

| Specified | Current reality |
|---|---|
| Monaco Editor | Rules are edited as JSON through a form; no embedded editor |
| TanStack Table / Virtual | Tables render server-side rows with API pagination, not client-side virtualisation |
| D3 / Cytoscape | The network graph uses a small hand-written SVG layout (deterministic circular placement) |
| Recharts | Statistics are rendered as text and tables; there is no charting |

Removing them removes a real attack surface and 45 packages, but it means those
capabilities are **not** implemented. Adding them back is a deliberate step, not
an oversight.

---

## Known gaps in test coverage

Stated so the suite is not over-claimed:

- Frontend tests cover formatting, hex rendering and comparison. The larger
  pages (workbench, graph, assistant) have no component tests; they are covered
  indirectly by the backend end-to-end tests.
- Analysis has been benchmarked once at profile scale
  ([PERFORMANCE.md](PERFORMANCE.md)); there has been no *load* or *soak* test and
  no repeated-run stress test, and the figures are from a Windows workstation,
  not the target container.
- Security tests cover the controls listed in [SECURITY.md](SECURITY.md). There
  is no fuzzing campaign against the PCAP/PCAPNG parsers.
- `npm audit` and `pip-audit` were run once at build time. A clean result is a
  snapshot in time and does not cover container base images.