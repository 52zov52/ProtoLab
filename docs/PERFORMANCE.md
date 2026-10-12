# Performance

Measured numbers for the capture-analysis pipeline, and what the measurement
surfaced. Nothing here is modelled or extrapolated: every figure came from a
run of `scripts/benchmark_analysis.py` on the machine below, and the run that
produced each number is described next to it.

## How the numbers were produced

`scripts/benchmark_analysis.py`:

1. builds a **real** libpcap file with the same generator that produces the
   test bench (`tools/testbench/generate.py`), so the frames, checksums and TCP
   conversations are genuine;
2. runs the **shipping** `CaptureAnalyzer` — the exact code behind
   `POST /api/captures/{id}/analyze` — with the same dataset, framing rule and
   limits the endpoint uses;
3. timestamps each stage through the analyzer's own progress callback;
4. reads process peak working set (RSS) from the OS and Python peak allocation
   from `tracemalloc`;
5. times the read paths the UI depends on through the ASGI app.

```bash
python scripts/benchmark_analysis.py --conversations 1000 --messages 120 --payload 256
python scripts/benchmark_analysis.py --conversations 1000 --messages 120 --payload 256 --json
```

## Environment

| | |
|---|---|
| CPU | AMD Ryzen 5 5600X (6 cores / 12 threads) |
| RAM | 15.9 GiB |
| OS | Windows 10 Pro |
| Runtime | Python 3.14.0 |
| Database | SQLite (WAL), single process, `local_secure` mode |

This is a developer workstation, not the 4 vCPU / 8 GiB Linux container the
limits are written for. The numbers below are what this machine did; they are
not a claim about any other machine.

## The capture

Generated to exercise the documented profile, deliberately above its message
count so the worst case is visible rather than hidden:

| | |
|---|---|
| Size | 80 960 024 bytes (77.2 MiB) |
| Packets | 246 000 |
| TCP sessions | 1 000 |
| Streams | 2 000 (both directions) |
| Framed messages | **240 000** (the documented profile says ~100 000) |

## Import

| Step | Time |
|---|---|
| Generate the capture | 4.5 s |
| `POST /api/captures` (stream to disk, hash, copy) | 0.3 s |

## Analysis (`POST /api/captures/{id}/analyze`)

| Stage | Seconds | Share |
|---|---:|---:|
| Read + decode packets | 16.95 | 4.6 % |
| Insert packet rows | 12.97 | 3.5 % |
| Reassemble + frame + persist messages | 337.04 | 91.9 % |
| **Total** | **366.96** | **100 %** |

That is about **1.53 ms per framed message** end to end. The dominant stage is
message handling (framing, feature extraction, byte-to-packet attribution and
persistence), not packet reading — the reader and indexer together are under
9 % of the run.

## Memory

| | |
|---|---|
| Working set before analysis | 89.3 MiB |
| **Peak working set (RSS)** | **1 457.4 MiB (1.42 GiB)** |
| Python peak allocation (`tracemalloc`) | 592.4 MiB |

The peak is dominated by packet rows held in memory before the batched insert
and by the reassembled stream buffers. It stays well under the 8 GiB the
profile targets, but it is not a small number and is reported rather than
rounded away.

## Read paths the UI depends on

Server-side latency through the ASGI app, one request each, against the
fully-analysed 240 000-message capture:

| Endpoint | Latency |
|---|---:|
| `GET /api/captures/{id}/packets?limit=1000` | 39.7 ms |
| `GET /api/captures/{id}/sessions` | 9.3 ms |
| `POST /api/network/graph` | 757.8 ms |
| `POST /api/projects/{id}/reports` | 3 063.8 ms |

The UI never loads a whole capture: the packet list is paginated and virtualized
and the table requests one window at a time. The two heavier reads (graph and
report) build their result across the whole capture and are the reasons those
screens have explicit loading states.

## What the benchmark surfaced

Writing the benchmark is what made the following visible; they are fixed in the
same change.

### Bug: every capture above 2 MiB was rejected on upload

The global request-body guard applied `max_json_body_bytes` (2 MiB) to **every**
request, including multipart capture uploads. The upload endpoint's real ceiling
is `max_upload_bytes` (100 MiB) and the profile promised ~100 MiB captures, but
anything over 2 MiB was answered `413` before reaching the handler — a capture
of the documented size could never be imported.

The guard now uses the upload ceiling for `multipart/form-data` bodies and the
JSON ceiling for everything else; the endpoint still re-checks the real limit
while streaming, so the middleware is a second gate, not the only one.
Regression test: `test_upload_above_the_json_body_limit_is_accepted`
(`backend/tests/test_api_flows.py`).

### Cost centres, and two optimisations

Two avoidable costs were removed while measuring:

1. **Message persistence.** Messages and stream ranges were added one ORM object
   at a time. They are now collected and written with `bulk_insert_mappings`;
   none of the rows needed an ORM identity.
2. **Range attribution.** For each message the code scanned *every* run in the
   stream (O(messages × runs)). It now uses the stream's interval index
   (`ReassembledStream.runs_intersecting`), so a message touches only the runs
   that overlap it.

Effect on the same 240 000-message capture:

| Revision | Analysis time |
|---|---:|
| As benchmarked first | 438.4 s |
| After bulk inserts | 377.6 s |
| After the interval index | 366.96 s |

≈ 16 % faster, with the suite itself noticeably quicker. The remaining cost is
real work (framing, per-message features, JSON payloads, SQLite writes) rather
than a single fixable hot spot, which is why the number is documented instead of
quietly left off.

## Heavy work runs in the background

The synchronous `/analyze` endpoint is the demo path. For large captures the UI
uses `POST /api/captures/{id}/analyze-async`, which queues the same
`run_analysis_job` through FastAPI background tasks. The job reports progress,
is polled at `GET /api/jobs/{id}` and can be cancelled at
`POST /api/jobs/{id}/cancel`; the analyzer's progress callback checks for
cancellation between stages and the job records a terminal status on every exit
path. Framing scans are additionally bounded
(`max_messages_per_stream`), and exceeding a limit is an explicit error naming
the limit — never a silent truncation.

## What is *not* measured here

- **UI memory.** Only the backend was measured. The frontend avoids loading a
  whole capture by construction (pagination + virtualization), but no browser
  memory profile was captured.
- **Soak behaviour.** These are single runs. There is no long-running or
  repeated-run stress test.
- **The target container.** Numbers are for a Windows workstation with SQLite;
  a container on different hardware will differ.
- **Other machines / parallel load.** Everything is single-process,
  single-capture, no concurrency.
