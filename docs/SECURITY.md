# Security

What is actually enforced in this build, how to check it yourself, and what is
explicitly *not* covered.

This is a local single-user research tool. It is not a hardened multi-tenant
service and does not claim to be. The threat model is in
[THREAT_MODEL.md](THREAT_MODEL.md); this document is the operational checklist.

---

## Security modes

| Mode | Bind | Accounts | Verified by tests |
|---|---|---|---|
| `local_secure` (default) | loopback only | none | yes |
| `team_remote` | **not verified** | **not implemented** | no |

`team_remote` is a configuration value, not a deployment. Enabling it without
putting a reverse proxy in front of the API would expose an unauthenticated
analysis API to the network. The Security Center reports this as
`unknown`, never as `pass`.

### The container bind exception

Inside a container the API binds `0.0.0.0` **within its own network namespace**,
because a published port routes to the namespace rather than to its loopback.
This is not the same exposure as binding a host interface, but it is also not
something this process can verify from the inside.

The operator records the trade-off with `MPLAB_ALLOW_NON_LOOPBACK_BIND=true`,
and the Security Center then reports the bind check as **`unknown`**, with the
message `UNVERIFIED`, because it cannot inspect the container's port mapping.
The real boundary is the host-side publish mapping
(`127.0.0.1:8010:8010`), which must be checked by hand.

---

## Verified controls

Each row states the property, how to check it, and what test covers it. Run:

```bash
python -m pytest backend/tests -q          # 109 tests
python scripts/live_check.py              # against a running server
```

### Network boundary

| Property | How to verify | Test |
|---|---|---|
| API binds loopback by default | `curl http://127.0.0.1:8010/api/health` | `live_check.py` |
| Foreign `Host` header rejected | `curl -H 'Host: evil.example' .../api/health` → 403 | `test_unknown_host_header_is_rejected` |
| Cross-origin request rejected | `curl -H 'Origin: https://attacker.example' ...` → 403 | `test_cross_origin_request_is_rejected` |
| Configured origin accepted | `Origin: http://127.0.0.1:3000` → not 403 | `test_allowed_origin_is_accepted` |
| CORS headers returned to allowed origins | `curl -i -H 'Origin: http://127.0.0.1:3000' .../api/health` | `test_allowed_origin_receives_cors_headers` |
| Preflight answered for allowed origin | `curl -X OPTIONS -H 'Origin: ...' -H 'Access-Control-Request-Method: POST' ...` | `test_preflight_is_answered_for_an_allowed_origin` |
| No wildcard origin ever emitted | see `test_response_never_uses_a_wildcard_origin` | yes |
| Security headers set | inspect response headers | `test_security_headers_are_present` |

The `Host` allowlist is the control that defeats DNS rebinding. The middleware
deliberately does **not** try to decide "is this request local?" from the
`Host` header — `Host` is attacker-controlled and can never prove where a
request went. Loopback binding plus the allowlist is the real boundary.

**Why CORS needs its own tests.** The UI is served from port 3000 and the API
from port 8010, so every call is cross-origin. Validating the `Origin` header
is necessary but *not sufficient*: without `Access-Control-Allow-Origin` on the
response the browser discards the body and the UI silently shows nothing. The
two halves must be tested together, because either alone is broken — a server
that rejects everything is as unusable as one that emits `*`. Credentials are
never enabled, and the emitted origin is always the exact allow-listed value.

### Untrusted input

| Property | How to verify | Test |
|---|---|---|
| Upload size capped | POST an oversized file → 413 | `test_oversized_upload_is_rejected` |
| Path traversal contained | upload named `../../etc/passwd.pcap` | `test_traversal_filename_is_rejected` |
| Duplicate capture refused | re-import the same bytes → 409 | `test_duplicate_import_is_refused` |
| Cross-project access refused | GET a hypothesis under another project → 404 | `test_object_ownership_is_enforced` |
| Malformed identifier rejected | `GET /api/projects/../../etc` | `test_invalid_identifier_is_rejected` |
| Archive entries validated | `project_archive.py` limits | see THREAT_MODEL T2 |
| Truncated protocol record survives | `test_truncated_length_field_produces_a_diagnostic_not_a_crash` | yes |
| Truncated TLS handshake survives | `test_truncated_handshake_is_reported_unreliable_and_unhashed` | yes |

Uploads are streamed to a temporary file under a size ceiling, then copied into
managed storage under a **random server-side name**. The user-supplied filename
is display-only and never becomes a path.

### Code execution

| Property | How to verify | Test |
|---|---|---|
| No execution from a specification | submit a spec with an unsupported construct | `test_no_execution_primitives_are_reachable_from_a_specification` |
| Excessive nesting rejected | deeply nested spec → error | `test_excessive_nesting_is_rejected` |
| Oversized spec rejected | huge spec → error | `test_oversized_document_is_rejected` |
| Unknown schema version refused | future version → explicit error | `test_unknown_schema_version_refuses_to_be_reinterpreted` |
| Assistant cannot run code | `'; DROP TABLE packets; --` | `test_assistant_cannot_be_used_to_run_code` |

Imported specifications are validated against a strict schema. Unknown field
kinds, unknown keys and unbounded repeat groups are **rejected explicitly**,
never ignored. There is no `eval`, `exec`, dynamic import or expression
evaluation anywhere in the interpretation path.

### Data integrity

| Property | How to verify | Test |
|---|---|---|
| Capture modification detected | flip one byte, then `GET /projects/{id}/integrity` | `test_integrity_check_detects_modification` |
| Audit chain verifies | `GET /api/audit/verify` | `test_audit_log_records_and_verifies` |
| Stale results detectable | edit a rule, re-read the previous run | `test_wrong_hypothesis_produces_a_counterexample` |

SHA-256 detects *unintended change against a trusted reference*. It does **not**
prove provenance and provides **no confidentiality**.

---

## Security Center

`POST /api/security/check` (audited) and `GET /api/security/report` (read-only)
run local checks and report one of four verdicts:

| Verdict | Meaning |
|---|---|
| `pass` | the property was verified and holds |
| `fail` | the property was checked and does not hold |
| `unknown` | the check could not be performed here, and says why |
| `na` | not applicable to this configuration |

The response includes a `scope` string stating that these are configuration and
permission checks, **not** a penetration test or a certification.

Current result on a default local run (Windows, dev dependencies):

```
{'pass': 10, 'fail': 0, 'unknown': 3, 'na': 1}
```

The `unknown` verdicts are honest and expected: POSIX permission bits cannot be
verified on Windows, `pip-audit` is not installed, and host reachability depends
on a firewall this process cannot inspect. A tool that showed all-green here
would be lying.

---

## Manual checks

Some properties cannot be fully automated:

```bash
# 1. Loopback only
netstat -ano | findstr :8010        # expect 127.0.0.1, never 0.0.0.0

# 2. Data directory permissions (POSIX)
ls -ld data data/secrets            # expect drwx------ (0700)

# 3. No secrets in logs
grep -riE "password|secret|BEGIN .*PRIVATE KEY" data/logs/

# 4. Dependency scanning (a snapshot, not a proof)
pip install pip-audit && pip-audit -r backend/pyproject.toml
npm audit --prefix frontend
```

## Known limitations

Stated plainly, because a security document that only lists strengths is not
useful:

1. **No authentication.** Any caller that reaches the API has full access to
   every project. Local mode assumes a single trusted operator on the machine.
2. **No at-rest encryption.** Projects are stored unencrypted, relying on
   filesystem permissions. There is no password-derived project key.
3. **Audit chaining is not tamper-proof.** A local administrator with file
   access can rewrite the rows and the chain together. It detects accidental or
   naive modification only.
4. **The rate limiter is in-process and per-process.** It is not a distributed
   control and resets on restart.
5. **Capture parsing is not isolated by default** in a local run. The Docker
   deployment improves this (non-root, read-only rootfs, `cap_drop: ALL`), but a
   container is not an absolute security boundary, and on Windows local
   permission semantics differ from POSIX.
6. **Secrets are not scanned inside capture payloads.** The Security Center
   scans project text files; binary `.pcap`/`.pcapng` are skipped.
7. **The log redaction filter is best-effort.** It catches credential-shaped
   keys, JWTs, TLS key-log lines and long hex blobs. A secret in an unexpected
   format, or inside a free-text analyst note, can still be logged.
8. **Windows permissions are not enforced.** `chmod` is a no-op on NTFS, so the
   Security Center reports `unknown` there instead of claiming the directory is
   restricted.
9. **A clean dependency scan is a snapshot in time**, not evidence that no
   vulnerabilities exist, and it does not cover container base images.

---

## Reporting a vulnerability

This is a local research tool with no public security contact. If you find an
issue in the capture parser or the archive importer, the most useful report
includes a minimal input that triggers it and the observed behaviour.