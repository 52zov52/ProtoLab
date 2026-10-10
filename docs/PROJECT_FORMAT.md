# Portable project format (`.mplab`)

A `.mplab` archive is a ZIP carrying everything needed to re-open an
investigation on another machine: the original captures (optionally), the
research record, and a manifest with hashes.

The purpose is that a colleague can **re-run the analysis and get the same
answer**. Anything that cannot be reproduced from the archive is stated as such
in the import result.

---

## Layout

```
project.mplab
├── manifest.json          metadata, counts, per-file SHA-256
└── data/
    ├── research.json      hypotheses, interpretations, runs, experiments
    └── captures/          the original capture files (optional)
```

### `manifest.json`

```json
{
  "format": "madrigal-protocol-lab-project",
  "version": 1,
  "generator": "madrigal-protocol-lab/0.1.0",
  "created_at": "2026-10-10T18:37:46.680091+00:00",
  "project": {
    "id": "5c1afbf1238845ba8e23eb879d5e50b1",
    "name": "Device protocol investigation",
    "description": "",
    "schema_version": 1,
    "settings": {},
    "created_at": "2026-10-10T18:37:46.610393"
  },
  "counts": {
    "captures": 1, "hypotheses": 0, "interpretations": 0,
    "experiments": 0, "validation_runs": 0, "reports": 0
  },
  "files": [
    {"path": "data/research.json", "sha256": "…", "size": 1297},
    {"path": "data/captures/<capture_id>/original.pcap",
     "sha256": "…", "expected_sha256": "…", "size": 1113,
     "capture_id": "8b217250d752479e90793454a7199a8a"}
  ]
}
```

The manifest version is `version`, and the format identifier is
`madrigal-protocol-lab-project`.

Each capture entry records both the hash of the bytes actually written
(`sha256`) and the hash recorded at import time (`expected_sha256`). A
difference between the two means the file changed after import, and is reported
as a mismatch rather than silently accepted.

Analyzer versions are recorded per record rather than in the manifest — the
validation run carries the `analyzer_version` that produced it, and the
interpretation carries the `checksum` of the rule it was run against. Together
these make a result checkable rather than merely repeatable: if the engine
version changes, the same archive may legitimately produce a different verdict,
and the archived result says which engine produced it.

### `data/research.json`

The research record: hypotheses with their status and rationale,
interpretations with their specifications and checksums, validation runs and
their outcomes, counterexamples, and the experiment log.

---

## Import semantics

`POST /api/projects/import` (multipart `file`, optional `name`):

1. **Validate before extracting.** Every member name is checked for absolute
   paths, drive letters, `..`, control characters and excessive length.
   Symlinks and special file types are refused.
2. **Bound the archive.** Entry count, per-entry size, total uncompressed size,
   compression ratio and directory depth are all limited, so a zip bomb is
   rejected rather than unpacked.
3. **Stage into a temporary directory.** Nothing touches the live project yet.
4. **Verify every SHA-256** in the manifest. Mismatches are reported; the
   affected capture is not imported.
5. **Create a new project.** An existing project is never overwritten. Import
   always produces a new `project_id`.

### What is restored, and what is not

| Restored | Consequence |
|---|---|
| Captures (when `include_captures`) | Re-analysis is reproducible |
| Hypotheses and interpretations | The rule set travels with the result |
| Validation runs | Marked **stale** on import |
| Counterexamples | Available for review |
| Experiment log | Available for correlation |

**Reconstructed streams are not stored in the archive.** They are deterministic
re-derivable from the capture, and re-running the analysis is part of the
reproducibility guarantee. Re-analysis after import reproduces the same session
and message counts.

**Imported validation runs are marked stale** because they describe results
obtained elsewhere. They must be re-run before being cited.

The import response states both facts explicitly in its `notes` array — this is
deliberate, so nobody mistakes a restored record for a locally reproduced one.

---

## Compatibility

The manifest `version` is checked on import. An unknown version is **rejected
with an explicit error** rather than reinterpreted — the archive is not a
future version of this tool that happens to be a bit different.

---

## Reproducing a result from an archive

```bash
# 1. Import into a clean directory
curl -F file=@project.mplab http://127.0.0.1:8010/api/projects/import

# 2. Re-run the analysis on each imported capture
curl -X POST http://127.0.0.1:8010/api/captures/$ID/analyze \
     -H 'Content-Type: application/json' -d @framing.json

# 3. Re-run the validation
curl -X POST \
  http://127.0.0.1:8010/api/projects/$PROJECT/interpreters/$RULE/validate \
  -H 'Content-Type: application/json' -d "{\"capture_ids\":[\"$ID\"]}"
```

The demo scenario performs exactly this and compares the replayed verdict with
the original, failing loudly if they differ.

---

## Machine-readable exports

Beyond the archive, individual artefacts export on their own:

| Export | Endpoint |
|---|---|
| Specification (JSON) | `GET /reports/{id}/json`, or the interpretation payload |
| Report (Markdown) | `GET /reports/{id}/markdown` |
| Report (JSON) | `GET /reports/{id}/json` |
| Validation run | `GET /validation-runs/{id}` |
| Counterexamples | `GET /validation-runs/{id}/counterexamples` |
| Annotated PCAPNG | `POST /captures/{id}/export-pcapng` |
| Audit log | `GET /audit/export` |

The annotated PCAPNG carries per-packet comments and preserves the original
timestamps and packet data. It is verified by re-reading the file after writing
it. It deliberately does **not** claim to carry the project: graphs, hypotheses
and validation results live in the `.mplab` archive, not in a capture file.