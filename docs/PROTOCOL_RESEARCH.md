# Protocol research methodology

How to get from a capture to a defensible specification. The method matters as
much as the tooling: a conclusion you cannot trace is not a finding.

---

## 0. Ground rules

- **The capture is the only authority.** Not the port number, not the vendor,
  not what the protocol "usually" looks like.
- **An absence of evidence is reported as an absence**, not filled in. A lost
  segment is a hole, not a zero. An undecoded region is `unknown`, not `0x00`.
- **Distinguish observation from interpretation.** "Bytes 0–1 equal the message
  length in 21 of 21 messages" is an observation. "Bytes 0–1 are the length
  field" is a hypothesis. The tool labels both separately.
- **Write down what would falsify your claim.** If nothing could, you have a
  belief, not a hypothesis.

---

## 1. Import and verify

Import the capture. The file is hashed with SHA-256 and stored unmodified under
a random server-side name. Verify with `GET /projects/{id}/integrity` whenever
you doubt a result — every later conclusion inherits the file's trustworthiness.

## 2. Identify sessions, not just addresses

Split into TCP sessions and look at each one's diagnostics. Two sessions sharing
an address and port pair are two connections; merging them corrupts both
reconstructions.

Before trusting a direction's bytes, read:

| Signal | Question it answers |
|---|---|
| `saw_syn` | Was the start of this connection captured? |
| `saw_fin` / `saw_rst` | How did it end? |
| `completeness_status` | Is `complete`, or is one end missing? |
| `role_confidence` | Is the client/server labelling proven or inferred? |

If the capture does not include the SYN, roles are marked as an assumption.
Do not write "the device sent" when you only know "the higher port did".

## 3. Check reconstruction quality before reading bytes

Open `GET /sessions/{id}/diagnostics` and read the coverage map.

- **Holes** — a segment was never captured. Bytes there are unknown.
  Anything that depends on them is provisional.
- **Overlaps/conflicts** — two segments disagreed. The chosen policy is named;
  check it matches your expectation.
- **Retransmissions** — exact duplicates must not appear twice in the stream. If
  they do, every offset after them is wrong.

If the reconstruction is incomplete, say so in your notes. A rule validated on a
stream with a hole in the middle may have only *appeared* to work.

## 4. Find boundaries

Do not assume one packet is one message. A single TCP segment can hold several
messages, and one message can span many segments.

Ask `GET /streams/{id}/framing-suggestions`. It scores candidate rules against
the actual bytes and explains each score. Suggestions are candidates ranked by
evidence, not answers — read the evidence line.

Then **test the rule against counterexamples**: apply it and look at what
fails. A rule that frames everything without complaint is often framing by
accident.

## 5. Correlate with what the operator actually did

Import the action log (`POST /projects/{id}/experiments`). Now you have an
experimental corpus: actions with timestamps, and messages with timestamps.

The most productive move is to compare a request under **one known parameter
change** against a request under another. Bytes that move together are
candidates for the parameter field.

**Correlation is not causation.** Two messages 2 ms apart may be unrelated. To
claim a field carries a parameter, show the field tracking the parameter across
*several* captures with different values, and say how many cases did not fit.

## 6. Read the field statistics, not your intuition

`GET /streams/{id}/field-statistics` reports, per offset: how often a value
occurred, how many distinct values, min/max, entropy, how often it changed
between consecutive messages, and — importantly — **contradiction count**: the
messages that do not fit the candidate reading.

A candidate at offset 0, size 2, big-endian with support 21/21 and 0
contradictions is a good hypothesis. One with support 18/21 is a hypothesis
with three known counterexamples, which you should look at before using.

Absent positions are **not** counted as zero. If a field does not exist in
shorter messages, the statistics say so rather than inventing a value.

## 7. State the hypothesis with its status

Every field carries a `semantic_status`:

`observed` (you measured it) · `hypothesis` (you believe it) · `assumed` ·
`unknown`.

A specification that marks everything `observed` is overclaiming, and the
counterexample workflow stops working because there is nothing left to refute.

## 8. Execute and validate

Write the specification (see [INTERPRETATION_FORMAT.md](INTERPRETATION_FORMAT.md))
and validate it against the corpus. Read the verdict, then **read the
counterexamples** — they are the most informative output the tool produces.

For each counterexample, the tool records:

- which rule was violated (`invalid_length`, `declared_length_exceeds_message`,
  `field_out_of_bounds`, …),
- the exact byte range and the source packets,
- why it failed, in plain language,
- alternative explanations — including "this may be a capture gap", which is
  frequently the right one.

## 9. Revise, and let the old result go stale

Correct the rule and re-validate. The previous run is marked `stale` with a
reason automatically. Never cite a stale run as if it described the current
rule — the tool refuses to let you do so silently.

## 10. Apply it somewhere it has never been

The real test. Apply the specification to a capture from a different session,
time or parameter value. If it holds, say exactly **how many messages** it held
on and how many it did not. "Works on 4 of 4 messages in this corpus" is a
statement; "works" is not.

## 11. Export so someone else can check

Export the project as a `.mplab` archive and re-import it in a clean
directory. Re-run the analysis and the validation. If the verdict matches, the
result is reproducible and transferable — that is the deliverable.

---

## Worked example

The synthetic test bench (`tools/testbench/generate.py`) contains a device
protocol with a 2-byte big-endian length prefix, a type byte and a request id.
The analyst is not told this. `scripts/demo_scenario.py` performs the full
path, including deliberately proposing the **wrong** rule (little-endian,
header excluded) so the counterexample step has something real to show.

For the full walkthrough see [DEMO_SCENARIO.md](DEMO_SCENARIO.md).

---

## Anti-patterns

| Anti-pattern | Why it fails |
|---|---|
| Grouping TCP flows by the 5-tuple alone | Merges unrelated connections that reuse a port |
| Concatenating payloads in capture order | Produces a corrupted stream whenever a segment arrives out of order |
| Treating a checksum-like field as a checksum | It changes with other bytes for many reasons |
| High entropy ⇒ encrypted | Compression and binary structures are high-entropy too |
| Naming a field because it "looks like" a counter | Requires showing it increments with something observed |
| Reporting a high centrality node as C2 | Centrality is not attribution |
| Citing a rule as proven | "Consistent with corpus" is not universal validity |
| Silently zero-filling a gap | Fabricates data that was never captured |