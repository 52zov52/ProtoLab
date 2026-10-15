# Testing

```bash
# Backend - 370 tests (test_api_docs.py keeps docs/API.md honest; test_dependencies.py keeps pyproject honest; test_prose_localization.py keeps the Russian catalogue honest)
python -m pytest backend -q

# Frontend - 147 tests
cd frontend && npm test

# Type safety and lint (Next 16 removed `next lint`; ESLint runs via the CLI)
cd frontend && npm run typecheck && npm run lint

# End-to-end, in-process (17 steps)
python scripts/demo_scenario.py

# Performance benchmark on a generated capture (Этап 3, §22)
python scripts/benchmark_analysis.py --conversations 1000 --messages 120 --payload 256

# Regenerate the example artefacts in examples/ (§31 п.9–14)
python scripts/build_examples.py

# End-to-end, against a running server
python -m app &
python scripts/live_check.py

# Schema migrations (Alembic; the API also migrates itself on startup)
cd backend && python -m alembic upgrade head       # apply, or create the schema
cd backend && python -m alembic current            # current revision
cd backend && python -m alembic revision --autogenerate -m "add a column"
```

## Migrations

`backend/alembic/` holds the schema migrations; the URL comes from the same
settings object the API uses (`MPLAB_DATABASE_URL`, or the SQLite file under
`MPLAB_DATA_DIR`), so the CLI and the application can never disagree about which
database they touch.

```bash
cd backend
python -m alembic upgrade head
```

The application migrates itself on startup: `create_all` runs first so a
database created by an earlier build still opens, and Alembic then runs to head.
A database with tables but no `alembic_version` row is **stamped** at head
instead of upgraded — replaying `0001_initial` against existing tables would
abort on the first one. `tests/test_migrations.py` builds the schema both ways
and compares them, so "the models and the migration agree" is a checked claim
rather than an assumption.

To add a migration: change a model, run `revision --autogenerate`, then read the
generated file — autogenerate cannot see a rename or a data-dependent change.
Then run `pytest tests/test_migrations.py`, which fails if the migration no
longer reproduces the models.

## Layout

| File | Covers |
|---|---|
| `test_tcp_reassembly.py` | Stream reconstruction |
| `test_interpretation.py` | Specification schema and evaluator |
| `test_tls_fingerprinting.py` | JA3/JA3S algorithm |
| `test_tls_api.py` | Fingerprinting through the API on real captures |
| `test_api_flows.py` | End-to-end vertical slice (includes upload size limits) |
| `test_api_docs.py` | docs/API.md matches the exposed routes |
| `test_regressions.py` | The four bugs fixed on the way to the baseline (padding, before-base, delimiter, wide header) |
| `test_sample_protocol.py` | End-to-end on a real third-party capture (§8.8) |
| `test_examples.py` | `examples/` archive imports, published spec reproduces the verdict (§31 п.9–14) |
| `test_byte_analysis.py` | Byte-column classification and entropy |
| `test_anomaly_detection.py` | Isolation Forest: seeding, refusal, API round-trip |
| `test_llm_narration.py` | LLM degradation, redaction, context cap, consent |
| `test_migrations.py` | Alembic reproduces the models; an existing database is stamped, not replayed |
| `test_anomaly_profile.py` | The numpy baseline finds planted outliers, is deterministic, and degrades honestly |
| `test_llm_providers.py` | Narration providers over real HTTP; the API key never leaks |
| `test_dependencies.py` | Every third-party import is declared in pyproject; no BOM in a source file |
| `test_prose_localization.py` | Every sentence the API renders verbatim has a Russian entry, placeholders intact |
| `test_narration_language.py` | The model is told which language to answer in; both provider spellings configure the same provider |
| `test_anomaly_honesty.py` | The stated reason the forest was skipped is the real reason; corpora under the floor still train |
| `test_assistant_russian.py` | A Russian question compiles to the same plan as its English twin |
| `test_suggested_queries.py` | Every example the interface offers is one the compiler can actually run |
| `test_framing_validation.py` | A framing rule the analyst supplied is refused with 422 before anything is written |
| `test_tls_decryption.py` | TLS 1.2/1.3 round trips, and every refusal path (wrong key, flip, truncation, unsupported) |
| `test_tls_keylog_api.py` | Key-log upload/list/delete, ownership, size ceiling, decrypt refusal |
| `test_bind_config.py` | Bind/loopback security configuration |
| `test_cors.py` | CORS headers present for allowed origins, absent otherwise |
| `test_frontend_safety.py` | No `dangerouslySetInnerHTML`, no remote assets, headers set |
| `frontend/tests/format.test.ts` | Formatting, hex conversion, status tones |
| `frontend/tests/hex-viewer.test.tsx` | Hex rendering and message comparison |
| `frontend/tests/evidence-links.test.ts` | Report evidence → navigation mapping |
| `frontend/tests/column-classes.test.ts` | Byte-column class presentation |
| `frontend/tests/graph-colors.test.ts` | Protocol-derived graph edge colours |
| `frontend/tests/diff-heatmap.test.ts` | Diff heat-map colouring |
| `frontend/tests/packet-table.test.ts` | Packet table virtualization helpers |
| `frontend/tests/tcp-state-diagram.test.tsx` | TCP state-diagram layout (§8.1) |
| `frontend/tests/captures-page.test.tsx` | Captures empty/error states and import failure (§23) |
| `frontend/tests/hypotheses-page.test.tsx` | Rule editor validation and the rule → corpus → counterexamples loop (§23) |
| `frontend/tests/i18n.test.tsx` | RU/EN selection, persistence, `<html lang>`, and translation coverage (Этап 8) |
| `frontend/tests/workspace-project.test.tsx` | A project the server does not know is dropped; an unreachable backend is not |
| `frontend/tests/packets-page.test.tsx` | Packet table: capture selector, list failure, per-packet bytes, filters in the request (§23) |
| `frontend/tests/sessions-page.test.tsx` | TCP sessions: empty state, selection → observed timeline and diagnostics (§23) |
| `frontend/tests/overview-page.test.tsx` | Project picker: switch, create, delete the active project (§23) |
| `frontend/tests/reports-page.test.tsx` | Report export links point at the backend for the selected report (§23) |
| `frontend/tests/streams-page.test.tsx` | Coverage gaps stay gaps; a hidden protocol label hides the stream, not the data |
| `frontend/tests/empty-states.test.tsx` | Every tool names the selection it needs instead of showing a blank panel |
| `frontend/tests/packet-table.test.tsx` | Packet table windowing (window + clamping) and sorting over the loaded page |
| `frontend/tests/message-table.test.tsx` | Message table windowing, tail clamping and the compare-limit selection |
| `frontend/tests/anomalies-page.test.tsx` | Anomaly scoring: honest outage, ranked result and per-entity explanation |
| `frontend/tests/graph-view.test.tsx` | Graph element mapping: node scale, hub flag, edges to filtered-out endpoints |
| `frontend/tests/russian-ui.test.tsx` | A Russian interface shows no English sentences, and the provider badge states what is true |
| `frontend/tests/russian-plurals.test.ts` | Russian counted nouns take one / two / five forms, including the 11-14 case |
| `frontend/tests/russian-no-english-words.test.ts` | No unexplained Latin word survives inside a Russian translation |
| `frontend/tests/assistant-suggestions.test.tsx` | Clicking a suggestion puts the language on screen into the query box |

## The test bench

`tests/` runs against real capture files generated by
`tools/testbench/generate.py`, which emits genuine TCP conversations (SYN,
data, FIN, checksums) into PCAP files. Tests skip with a clear message if the
bench has not been generated.

```bash
python tools/testbench/generate.py --out data/testbench
```

Each capture targets a specific behaviour:

| Capture | Tests |
|---|---|
| `basic.pcap` | The baseline exchange |
| `basic.pcapng` | The same in pcapng |
| `lossy_segments.pcap` | A lost segment produces a hole, not zeros |
| `retransmissions.pcap` | Byte-identical retransmissions do not duplicate bytes |
| `mixed_lengths.pcap` | Messages of strongly varying length |
| `port_reuse.pcap` | A reused 4-tuple yields two sessions, not one |
| `rst_no_syn.pcap` | RST close; a connection starting without SYN |
| `two_connections.pcap` | Distinct 4-tuples stay separate |
| `set_parameter_{10,20,60}.pcap` | A field tracks a known parameter change |
| `measurements_{8,64,192}.pcap` | Response length varies with the request |
| `unknown_status.pcap` | A status a first hypothesis will not account for |
| `tls_handshake.pcap` | A complete ClientHello/ServerHello |
| `tls_truncated.pcap` | A ClientHello cut short by the capture |

`data/testbench/ground_truth.json` records the real protocol layout. It is
**never given to the application** — the analyst is expected to recover it from
the bytes, which is what makes the bench a test rather than a lookup.

## What the suite asserts about correctness

These are the properties that a plausible-looking but wrong implementation
would fail:

**Reassembly**
- out-of-order segments reassemble by sequence number
- an exact retransmission does not duplicate bytes
- a partial overlap extends the stream exactly once
- conflicting overlaps record a diagnostic under a named policy
- a gap stays a gap and is not zero-filled
- sequence numbers wrap around correctly
- reassembly is deterministic under packet reordering
- provenance lists every packet that contributed a merged byte
- zero-length payloads are ignored

**Framing**
- fixed-length, length-prefix, delimiter and signature framing
- an invalid length stops framing with an explicit error, not a crash
- a truncated length field produces a diagnostic, not a crash

**Interpretation**
- fields extract correctly; endianness is respected
- out-of-bounds fields are reported as errors
- conditional and repeat groups evaluate against their conditions
- constant, range and enum constraints detect violations
- unknown field kinds, unknown keys, excessive nesting and oversized documents
  are **rejected explicitly**
- an unknown `schema_version` is refused, not reinterpreted
- no execution primitive is reachable from a specification

**Security**
- foreign `Host` rejected; cross-origin rejected; configured origin accepted
- security headers present
- oversized upload rejected; traversal filename contained
- cross-project access refused; invalid identifiers rejected
- the assistant cannot execute code
- capture modification detected; audit chain verifies

**Research**
- a plausible but wrong rule produces counterexamples, and fixing the rule
  marks the previous run stale
- a specification applies to a capture it has never seen
- field inference ranks the real length field first
- protocol detection falls back to `unknown_binary` rather than guessing
- a reused 4-tuple is not merged
- TLS fingerprinting reports a truncated handshake as unreliable with no hash
- the archived example project re-imports with matching hashes, and the published
  specification reproduces `consistent_with_corpus` on a re-analysed capture
- the four fixed bugs stay fixed: Ethernet padding is not payload, a segment
  before the base does not blow up the stream, a delimiter after a hole is still
  found, and a length prefix inside a wide fixed header frames correctly

## Frontend tests

The frontend tests target the claims that are easy to break and expensive to
get wrong:

- a lost segment renders as `GAP`, never as `00`
- a byte absent from a shorter message renders as *absent*, never as `0x00`
- hex highlighting covers exactly the requested half-open range
- status tones never report an unknown value as good
- byte formatting degrades to `-` rather than printing `NaN`
- with no project selected the Captures tool says so instead of showing an empty
  list, an empty project gets an explicit empty state, a failed request is shown
  with a Retry, and a rejected import reports why
- a project id that the server does not know (a stale `?project=` link, or a
  project deleted underneath the app) is dropped, so the tool that creates
  projects is reachable again; an unreachable backend keeps the selection
  instead of discarding the analyst's work
- the rule editor does not claim a broken draft is valid JSON, invalid JSON never
  reaches the server, a server rejection is reported, and the rule → corpus →
  counterexamples loop renders the counterexample it produced
- switching the language changes the UI, `<html lang>` and the stored preference;
  a stored preference is applied on load; and every `t("…")` literal in `app/`
  and `components/` has a Russian entry, so nothing is silently left in English

## The demo scenario as a test

`scripts/demo_scenario.py` is both documentation and an end-to-end test: it
walks all 17 steps and exits non-zero if any behaves unexpectedly. Run it after
changing the analysis or interpretation code.

## Continuous integration

`.github/workflows/ci.yml` runs exactly the commands above on every push: the
backend suite (with the analytics extra and a freshly generated test bench), the
in-process `demo_scenario.py`, and the frontend tests, typecheck, lint and build.
The end-to-end scenario is part of the CI run, so a change that breaks the
researcher path fails the build rather than only the demo.

## Adding tests

- New analyzer behaviour → a test in `test_tcp_reassembly.py` or a sibling.
- New endpoints → a test in `test_api_flows.py`.
- New API routes → update `docs/API.md`; `test_api_docs.py` will fail otherwise.
- New UI behaviour → a test under `frontend/tests/`.

Never write a test that asserts a mock's return value. Assert the property the
product claims.