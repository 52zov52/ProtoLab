# Madrigal Protocol Lab

A local laboratory for reverse-engineering undocumented binary network protocols.

It turns raw PCAP/PCAPNG captures into a **checkable specification** of a
protocol you did not write: reassemble the TCP streams, find message
boundaries, compare the bytes against a log of what the operator actually did,
state a hypothesis about the wire format, execute it as a rule, and find the
messages that contradict it.

The product's core commitment is that **no conclusion is asserted without
evidence you can open**. Every field, framing rule and verdict links back to the
capture bytes and packets it was derived from, and a rule that fails is shown
failing rather than quietly adjusted.

---

## What works today

| Capability | Status | Where |
|---|---|---|
| PCAP / PCAPNG import, SHA-256 integrity | working | `/api/captures` |
| TCP session splitting (port reuse kept separate) | working | `/api/captures/{id}/sessions` |
| TCP reassembly: out-of-order, retransmission, overlap, holes, conflicts | working | `/api/streams/{id}/bytes` |
| Message framing (8 methods + heuristic suggestion) | working | `/api/streams/{id}/framing-suggestions` |
| Binary message comparison with explicit absent bytes | working | `/api/streams/{id}/compare` |
| Field statistics and inferred candidates | working | `/api/streams/{id}/field-statistics` |
| Declarative interpretation + validation + counterexamples | working | `/api/projects/{id}/interpreters` |
| Apply a rule to a capture it has never seen | working | same, via `capture_ids` |
| Portable project export/import (`.mplab`) | working | `/api/projects/{id}/export` |
| Annotated PCAPNG export with round-trip verification | working | `/api/captures/{id}/export-pcapng` |
| Capture diff | working | `/api/captures/diff` |
| Network graph + centrality | working | `/api/network/graph` |
| Protocol detection (HTTP/1.1, HTTP/2, TLS, MQTT, ...) | working | `/api/graph`, stream records |
| TLS JA3/JA3S fingerprinting | working | `/api/streams/{id}/tls` |
| TLS decryption from an uploaded key log | working (limited suites) | `/api/streams/{id}/decrypt` |
| Key log management (upload / list / delete) | working | `/api/projects/{id}/keylogs` |
| Investigation report (Markdown + JSON) | working | `/api/projects/{id}/reports` |
| Typed NLP search (no LLM code execution) | working | `/api/assistant/query` |
| Security Center with honest verdicts | working | `POST /api/security/check` |
| Schema migrations (Alembic) | working | `backend/alembic` |
| Anomaly detection (Isolation Forest, numpy profile fallback) | working | `/api/anomalies/train`, `/api/anomalies/score` |
| Optional narration by an LLM | **off by default** | local Ollama or any OpenAI-compatible endpoint |
| Multi-user auth / remote mode | **not implemented** | see [Limitations](#known-limitations) |

"optional" means the module reports itself unavailable rather than degrading
silently. There are no placeholder buttons.

TLS decryption works for the cipher suites listed in
[docs/LIMITATIONS.md](docs/LIMITATIONS.md) (TLS 1.2 AES-GCM/CBC+HMAC, TLS 1.3
AES-GCM/ChaCha20-Poly1305) and only from a key log the operator uploads. Any
record that cannot be opened says so; none is ever approximated.

---

## Requirements

- Python 3.11+ (developed and tested on 3.12; runs on 3.14)
- Node.js 20+ (for the frontend)
- Optional: Docker, `scikit-learn` for anomaly detection

No cloud account, no API key, no network access.

---

## Install and run (without Docker)

```bash
# 1. Backend
python -m venv .venv
.venv/Scripts/python -m pip install -e "backend[dev]"   # Windows
# .venv/bin/pip install -e "backend[dev]"              # Linux/macOS

# 2. Generate the synthetic test bench (real TCP conversations, real PCAPs)
.venv/bin/python tools/testbench/generate.py --out data/testbench

# 3. Start the API on loopback
cd backend && ../.venv/bin/python -m app

# 4. Start the UI (second terminal)
cd frontend && npm ci && npm run dev
```

Open <http://127.0.0.1:3000>. The API listens on <http://127.0.0.1:8010> and
interactive docs are at `/api/docs`.

> `data/` is created on first run with owner-only permissions. Nothing is
> written outside it.

## Install and run (with Docker)

```bash
docker compose up --build
```

Both services publish on loopback only. The backend runs as a non-root user
with a read-only root filesystem and all capabilities dropped.

One detail that is easy to get wrong: inside a container the API binds
`0.0.0.0` **in the container's own network namespace**, because a published port
routes to the namespace and not to its loopback. Reachability is restricted by
the host-side mapping `127.0.0.1:8010:8010`, and the Host/Origin allowlist still
applies. The Security Center reports this case as `unknown` rather than `pass`,
because it cannot inspect the container's port mapping from inside.

> **Not verified here.** Docker was not available in the environment where this
> was built, so the compose file and both Dockerfiles were reviewed statically
> and the backend bind behaviour is covered by tests (`test_bind_config.py`),
> but `docker compose up` has not actually been executed.

---

## Verify the installation

```bash
# Backend: 201 tests covering reassembly, framing, interpretation, security,
# examples, TLS fingerprinting *and* TLS decryption, migrations
python -m pytest backend -q

# Frontend: 103 tests over hex rendering, tables, graph, pages, localization and
# formatting, plus lint and types
cd frontend && npm test && npm run typecheck && npm run lint

# End-to-end demonstration against an in-process client (17 steps)
python scripts/demo_scenario.py

# Recover the bundled third-party protocol from its bytes
python scripts/explore_sample_protocol.py

# End-to-end demonstration against a running server
python -m app &
python scripts/live_check.py
```

`demo_scenario.py` is the judge-facing script: it walks the entire researcher
path and prints what happened at each step, so the output *is* the evidence.

Every push runs those same commands in CI (`.github/workflows/ci.yml`): the
backend suite against a freshly generated test bench, the demo scenario, and the
frontend tests, typecheck, lint and build.

---

## The research workflow

1. **Import** a capture. The file is hashed (SHA-256) and stored unmodified
   under a random server-side name.
2. **Analyse** it. Packets are indexed, the capture is split into TCP
   sessions, and each direction is reassembled from sequence numbers.
3. **Inspect** the reconstruction. Holes, overlaps, conflicts and
   retransmissions are reported as diagnostics, never patched over with zeros.
4. **Frame** the stream. Ask for framing suggestions, or supply your own rule.
   One TCP packet is *not* assumed to be one message.
5. **Compare** messages. Several side by side, with identical and changed bytes
   highlighted. A byte a shorter message does not have is shown as *absent*,
   not as `0x00`.
6. **Hypothesise.** Propose a field, attach the messages that support it, and
   record the ones that contradict it.
7. **Execute** the hypothesis as a declarative specification and validate it
   against the corpus.
8. **Read the counterexamples.** Every failure names the rule violated, the
   offending bytes, the source packet, and alternative explanations.
9. **Revise** and re-validate. The previous run is marked stale automatically.
10. **Apply** the corrected rule to captures it has never seen.
11. **Export** the project as a portable archive and re-import it elsewhere to
    confirm the result reproduces.

A completed run of this workflow is checked in under [`examples/`](examples/):
the portable `.mplab` archive, the accepted machine-readable specification, the
rejected rule with the counterexamples it produced, the rule applied to a record
it had never seen, and the final report. `scripts/build_examples.py` regenerates
them from the real `sample_protocol/` capture.

---

## Documentation

| Document | Contents |
|---|---|
| [docs/USER_GUIDE.md](docs/USER_GUIDE.md) | Walkthrough of every tab, button and field |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Module layout and data flow |
| [docs/PROTOCOL_RESEARCH.md](docs/PROTOCOL_RESEARCH.md) | The reverse-engineering method |
| [docs/INTERPRETATION_FORMAT.md](docs/INTERPRETATION_FORMAT.md) | Specification schema |
| [docs/API.md](docs/API.md) | REST endpoints |
| [docs/PROJECT_FORMAT.md](docs/PROJECT_FORMAT.md) | The `.mplab` archive |
| [docs/SECURITY.md](docs/SECURITY.md) | Verified controls and their limits |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | Assets, trust boundaries, threats |
| [docs/LIMITATIONS.md](docs/LIMITATIONS.md) | What is not implemented |
| [docs/PERFORMANCE.md](docs/PERFORMANCE.md) | Measured throughput and known bottlenecks |
| [docs/LOCALIZATION.md](docs/LOCALIZATION.md) | RU/EN localization: mechanism, catalogues, coverage test |
| [docs/UPGRADING.md](docs/UPGRADING.md) | Upgrading an install: backup → upgrade → verify |
| [docs/TESTING.md](docs/TESTING.md) | How the suite is organised |
| [docs/DEMO_SCENARIO.md](docs/DEMO_SCENARIO.md) | The 17-step walkthrough |
| [docs/TZ_PRODUCTION.md](docs/TZ_PRODUCTION.md) | Production-readiness spec for a handover developer |
| [examples/README.md](examples/README.md) | Worked example: archive, spec, counterexample, report |

---

## Configuration

Every knob is an environment variable; see [.env.example](.env.example). You
do not need it for a local run.

The default profile is **Local Secure**: loopback bind, no accounts, no
outbound network, external AI disabled.

---

## Known limitations

Stated plainly, because a tool that hides its limits cannot be trusted with
evidence:

- **TLS decryption is not implemented.** JA3/JA3S fingerprinting works and
  needs no keys, but there is no `SSLKEYLOGFILE` ingestion yet.
- **There is no authentication.** Local mode is single-user by design. Do not
  bind to a LAN address. `team_remote` mode is *not* a turnkey multi-user
  deployment; see docs/SECURITY.md.
- **Audit log hash chaining detects modification, it does not prevent it.** An
  administrator with file access can rewrite both the log and the chain.
- **Isolation is per-process, not per-container, in the default run.** Capture
  parsing happens inside the API process unless you enable the container
  deployment.
- **Protocol detection is heuristic.** A negative result means *no analyser
  confirmed a protocol*, which is reported as `unknown_binary` — never as a
  guess.
- **Anomaly scores are not probabilities.** They rank relative unusualness
  within a chosen baseline and carry no severity meaning.

The full list, with the reasoning behind each, is in
[docs/LIMITATIONS.md](docs/LIMITATIONS.md).