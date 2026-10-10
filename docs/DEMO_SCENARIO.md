# Demonstration scenario

The judge-facing path through the product, from an empty project to a
transferable, re-verified result.

```bash
python tools/testbench/generate.py --out data/testbench   # once
python scripts/demo_scenario.py                            # runs all 17 steps
```

The script uses an in-process client and a temporary data directory, so it
leaves nothing behind and is safe to run repeatedly. `--keep` preserves the
workspace for inspection.

To watch it against a real server instead:

```bash
python -m app
python scripts/live_check.py
```

---

## The steps

### 1. Create the project
`POST /api/projects`. A blank project honestly reports zero captures, packets
and messages.

### 2. Import the baseline capture
`POST /api/captures` with `data/testbench/basic.pcap`. The file is hashed
(SHA-256), stored under a random server-side name, and left unmodified.
Re-importing the same bytes is refused with 409.

### 3. Import the action log
`POST /projects/{id}/experiments`. The operator's actions with timestamps. This
is what later allows a candidate field to be correlated with a known parameter
change.

### 4. Reconstruct the session
`POST /captures/{id}/analyze`.

Output shows one TCP session, the client and server endpoints, and the
`role_rationale` — the evidence for the role assignment, not just the result.
The timeline reports whether SYN, FIN and RST were actually observed.

### 5. Ask which framing rules fit
`GET /streams/{id}/framing-suggestions`. Each candidate carries a score and
the evidence behind it. The script selects the 2-byte big-endian prefix at
offset 0 that includes the header.

### 6. Apply the framing rule
Re-analyse with the chosen rule. Messages are listed with their stream offsets
and declared lengths.

### 7. Propose a hypothesis — deliberately wrong
Create an interpretation claiming the length field is **little-endian and
excludes the header**. A plausible mistake, and the most instructive step in
the demonstration.

Validation reports `contradicted` with a count of counterexamples.

### 8. Open a counterexample
`GET /validation-runs/{id}/counterexamples`. For the first failure the script
prints the message, its stream offsets, the `violated_rule`, each reason in
plain language, and alternative explanations — including "this may be a capture
gap", which is frequently the right answer.

### 9. Correct the rule and re-validate
`PUT /interpreters/{id}` with the big-endian, header-inclusive rule. The
interpretation becomes version 2 with a new checksum, and the previous run is
automatically marked **stale** with the reason "the specification changed after
this run". Re-validation returns `consistent_with_corpus`.

### 10. Apply the rule to unseen captures
The corrected rule is validated against four captures it has never seen, with
different parameter values and different response sizes. Each prints its
verdict and match count.

### 11. Field statistics
Per-offset statistics show the length field's support rate and, importantly,
its **contradiction count** — the messages that do not fit. The rationale text
says explicitly that fitting the corpus is support, not proof.

### 12. Export an annotated PCAPNG
`POST /captures/{id}/export-pcapng`. Packets and timestamps are preserved,
selected packets carry comments. The file is **re-read** to verify the comments
survived, and mismatches are reported. The export states that it does not
contain the project.

### 13. Export the portable project
`POST /projects/{id}/export` produces a `.mplab` archive with a manifest and
per-file hashes.

### 14. Import it into a new project directory
`POST /projects/import`. A **new** project id; nothing is overwritten. Hash
mismatches are reported. The response states that reconstructed streams are not
in the archive and that imported runs are marked stale.

### 15. Reproduce the result
Re-analyse the imported capture and re-run the validation. Session, stream and
message counts must match the original, and the verdict must be identical. If
it differs, the script fails loudly.

### 16. Generate the report
A 15-section report where each conclusion carries evidence references.
`ai_used` is `false` when no model is configured — the report is generated from
template and real data, not narration.

### 17. Integrity and security
Source hashes re-verified; the Security Center run. Non-`pass` verdicts are
printed with their reason — on a typical local run these are honest "I could
not verify this" entries, not silent green ticks.

---

## What to look at

1. **Step 7–9 is the point of the product.** Most tools would quietly accept a
   plausible rule. Here the wrong rule is *applied*, *fails loudly*, and the
   specific failing bytes are named.
2. **Staleness.** After the fix, the old run is visibly marked stale. A stale
   result cannot be mistaken for a current one.
3. **Step 15.** The result is not just re-displayed; it is re-derived in a fresh
   directory and compared.
4. **Step 17.** The Security Center reports `unknown` where it genuinely cannot
   verify. That is the behaviour to check, not the green checks.

---

## Using the UI instead

The same path is available in the interface:

| Screen | Step |
|---|---|
| Overview | 1 |
| Captures | 2 |
| Hypotheses & Rules | 3, 7 |
| Stream Explorer | 4, 5, 6 |
| Protocol Workbench | 8, 11 |
| Reports | 16 |
| Security | 17 |
| Top bar | 13, 14 |

Export/import buttons live in the top bar; the security panel is in the left
navigation.

---

## Expected output

```
[ 7] Propose a first interpretation - deliberately WRONG
    verdict: contradicted
    matched=0 failed=7 counterexamples=7

[ 8] Open a concrete counterexample
    violated rule: declared_length_exceeds_message
      alternative: No alternative reading could be derived automatically; inspect
      the raw bytes for this message in the stream viewer.

[ 9] Revise the rule (big-endian, header included) and re-validate
    previous run is now stale=True: The specification changed after this run,
    so its results describe an older rule version.
    verdict: consistent_with_corpus
    matched=7 failed=0

    set_parameter_10.pcap   -> verdict=consistent_with_corpus  matched=4  failed=0
    set_parameter_20.pcap   -> verdict=consistent_with_corpus  matched=4  failed=0
    set_parameter_60.pcap   -> verdict=consistent_with_corpus  matched=4  failed=0
    measurements_192.pcap   -> verdict=consistent_with_corpus  matched=2  failed=0

[15] Reproduce the validation in the new project
    re-validation verdict: consistent_with_corpus
    matched=7 failed=0

SCENARIO RESULT
All 17 demonstration steps completed with the expected behaviour.
```