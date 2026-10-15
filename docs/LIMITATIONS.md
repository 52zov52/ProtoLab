# Limitations

What this build does not do, and where a result stops being trustworthy.

This document exists because a tool that hides its limits cannot be trusted
with evidence. Nothing here is a plan to be completed later; it is the current
state.

---

## Not implemented

### UI libraries from §4 that were not adopted

**shadcn/ui and a graph library (D3.js / Cytoscape.js) are not used.**

The §4 stack was adopted where it changes what the analyst can do:

- TanStack Table + TanStack Virtual — packet and message tables (windowing,
  sorting) in `components/packet-table.tsx` and `components/message-table.tsx`.
- Recharts — the outlier-score ranking on the Anomaly Detection page.
- Monaco Editor — the interpretation editor, bundled locally in
  `components/spec-editor.tsx` with a textarea fallback.

What was deliberately left as it is:

- **shadcn/ui.** `components/ui.tsx` already provides the panel, badge, empty
  state, error state, caveat and confirmation primitives the product needs, with
  the graphite design tokens in one place. Migrating them to shadcn would move
  that vocabulary into generated files without adding a capability, and would
  add a per-component dependency on the component registry's version.
- **D3.js / Cytoscape.js.** The network graph is a small SVG that already pans,
  zooms, colours edges by detected protocol and marks hub candidates. Its
  layout is deterministic circular, which is a property worth keeping (the same
  capture always draws the same picture); a force simulation would not be.

Both are recorded as deviations from §4 rather than as gaps to be filled later.
If the graph later needs thousands of nodes to stay interactive, a switch to
Cytoscape is the natural place to spend that complexity.

### TLS decryption via `SSLKEYLOGFILE`

**Fingerprinting works without keys; decryption works only with a key log the
operator supplies, and only for the suites listed below.**

JA3 and JA3S are computed from the plaintext handshake, so they work on an
encrypted session and need no keys — see `GET /api/streams/{id}/tls`.
Application records are decrypted only from a key log uploaded to
`POST /projects/{id}/keylogs` and used by `POST /streams/{id}/decrypt`.

**Implemented suites**

* TLS 1.2 AES-GCM (`0x009C`, `0x009D`, `0xC013`, `0xC014`, `0xC02B`, `0xC02C`).
* TLS 1.2 AES-CBC with HMAC (`0x002F`, `0x0035`, `0x003C`).
* TLS 1.3 AES-GCM and ChaCha20-Poly1305 (`0x1301`, `0x1302`, `0x1303`).

Anything else — a suite outside that table, an incomplete key log, a record
truncated by the capture — is reported per record with the reason and **no
plaintext shown**. For AEAD, decryption is authentication, so a failed tag means
the bytes are not what the keys claim, and nothing is invented in their place.

A key log is treated as the secret it is: stored under a server-generated name with
owner-only permissions, hashed, never returned by the API, and never included in a
report, the AI context or an exported `.mplab` archive.

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

### Anomaly detection has two detectors, and the weaker one is weaker

With `scikit-learn` installed:

```bash
pip install -e "backend[analytics]"
```

the baseline is an **Isolation Forest**, which is what this product is designed
around. Without it, training falls back to a **robust per-feature profile** — the
median and the median absolute deviation per feature, with the outlier threshold
read off the corpus's own distance distribution.

The fallback is not a disguised forest and does not pretend to be one:

* `GET /api/anomalies/status` reports which detector is active, and the training
  summary and the stored model record `robust_profile` as their algorithm;
* asking for `algorithm: "isolation_forest"` without scikit-learn fails loudly
  instead of quietly training a different model;
* the profile's own training summary carries a warning saying which detector was
  used and that the forest needs the extra;
* the backend image installs scikit-learn, so `docker compose up` gets the
  forest anyway.

What the profile detector cannot do: it has no notion of interactions between
features, and its score is a distance from the baseline in robust units rather
than a forest score. A score is therefore comparable **within one baseline only**
— never across two models, and never as a probability or a severity. No invented
scores are ever returned under either detector.

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