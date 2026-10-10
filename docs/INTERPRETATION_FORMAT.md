# Interpretation format

An interpretation is a **declarative** description of how to read a binary
message. It is data, not code: it is validated against a strict schema and
interpreted by a bounded evaluator. There is no `eval`, no expression language
and no way to reach the filesystem, the network or the environment from a
specification.

Supported `schema_version`: **1.0**. A document declaring any other version is
**rejected**, never silently reinterpreted.

---

## Minimal example

```json
{
  "schema_version": "1.0",
  "protocol_name": "MadrigalTestDevice",
  "description": "Recovered from the basic capture.",
  "framing": {
    "method": "length_prefix",
    "length_field": {
      "offset": 0,
      "size": 2,
      "endianness": "big",
      "includes_header": true
    }
  },
  "fields": [
    {
      "name": "length",
      "kind": "uint16",
      "offset": 0,
      "size": 2,
      "endianness": "big",
      "semantic_status": "observed",
      "description": "Total message length including these two bytes."
    },
    {
      "name": "message_type",
      "kind": "enum",
      "offset": 2,
      "size": 1,
      "semantic_status": "hypothesis",
      "description": "1=read, 2=set, 3=measurements, 4=ack, 5=heartbeat",
      "values": { "1": "read_parameter", "2": "set_parameter" }
    },
    {
      "name": "request_id",
      "kind": "uint16",
      "offset": 3,
      "size": 2,
      "endianness": "big",
      "semantic_status": "hypothesis"
    }
  ],
  "message_types": [
    {
      "name": "read_request",
      "when": { "field": "message_type", "operator": "equals", "value": { "raw": 1 } }
    }
  ]
}
```

---

## Top level

| Field | Type | Notes |
|---|---|---|
| `schema_version` | `"1.0"` | Must match exactly |
| `protocol_name` | string | Display name |
| `description` | string | What the analyst believes this is |
| `framing` | object | How to find message boundaries |
| `fields` | array | Field definitions, in order |
| `message_types` | array | Optional named rules over extracted fields |
| `notes` | string | Free text |

## `framing`

`method` is one of:

| Method | Meaning |
|---|---|
| `fixed_length` | Every message is `size` bytes |
| `length_prefix` | A length field precedes the body |
| `delimiter` | Messages end with a delimiter |
| `signature` | Messages start with a fixed byte pattern |
| `header_rule` | Boundaries follow explicit header rules |
| `heuristic` | Best-effort boundary detection |
| `manual` | Boundaries supplied by the analyst |

### `length_field`

| Field | Type | Default | Notes |
|---|---|---|---|
| `offset` | int | required | Byte offset of the length field |
| `size` | 1, 2, 4, 8 | required | Width in bytes |
| `endianness` | `big` / `little` | `big` | |
| `includes_header` | bool | `true` | Whether the length counts itself |
| `multiplier` | int | `1` | `declared * multiplier` |
| `subtract` | int | `0` | `declared * multiplier - subtract` |
| `max_length` | int | — | Rejects absurd declarations |

`includes_header` is the field most often guessed wrong, and it is exactly what
a counterexample exposes: with the wrong value, framing stops short or overruns.

## `fields`

| Field | Type | Notes |
|---|---|---|
| `name` | string | Unique key in the result |
| `kind` | see below | Interpretation |
| `offset` | int | Absolute byte offset |
| `size` | 1, 2, 4, 8 | For fixed-width kinds |
| `endianness` | `big` / `little` | For integer and float kinds |
| `values` | object | For `enum`: raw value → label |
| `condition` | object | For `if`: read only when true |
| `count` | int | For `repeat`: element count |
| `count_from` | string | For `repeat`: field naming the count |
| `size` | int | For `repeat`: element size |
| `semantic_status` | enum | See below |
| `description` | string | Why the analyst believes this |

### `kind`

| Group | Values |
|---|---|
| Unsigned | `uint8` `uint16` `uint32` `uint64` |
| Signed | `int8` `int16` `int32` `int64` |
| Float | `float32` `float64` |
| Opaque | `bytes` `ascii` `unknown` |
| Semantic | `enum` |
| Control | `if` `repeat` |

`unknown` records a region the analyst has not decoded. It is deliberately not
zero-filled: an unnamed region stays visible in the output.

### `semantic_status`

Marks how confident the analyst is, so a reader never mistakes a guess for a
fact:

`observed` · `hypothesis` · `assumed` · `unknown`

### Conditional and repeated fields

```json
{"name": "payload", "kind": "if",
 "condition": {"field": "message_type", "operator": "equals", "value": {"raw": 3}},
 "size": 64}
```

```json
{"name": "samples", "kind": "repeat",
 "count_from": "sample_count", "size": 4}
```

A `repeat` **must** be explicitly bounded — by `count` or `count_from`. An
unbounded repeat is rejected, so a hostile specification cannot make the engine
allocate without limit.

### Constraints

```json
{"name": "message_type", "kind": "uint8", "offset": 2, "size": 1,
 "constraints": [{"kind": "range", "minimum": 1, "maximum": 5}]}
```

| Constraint | Detects |
|---|---|
| `range` | A value outside an expected interval |
| `enum` | A value outside a known set |
| `constant` | A field that changed when it should not have |

A violated constraint produces a **counterexample**, not a silently coerced
value.

## `message_types`

Named rules over extracted fields, used to group results:

```json
{"name": "set_request",
 "when": {"field": "message_type", "operator": "equals", "value": {"raw": 2}}}
```

Operators: `equals`, `not_equals`, `in`, `gt`, `gte`, `lt`, `lte`, `exists`.

---

## What is deliberately unsupported

These are rejected with an explicit error rather than ignored or approximated,
because a specification that silently skips a construct produces confident
wrong answers:

- Arithmetic or comparison **expressions** in field values.
- Scripting, macros, or any form of embedded code.
- `regex`, `eval`, `exec`, dynamic import, or template evaluation.
- Unbounded `repeat` groups.
- Recursive field definitions.
- `schema_version` values this build does not understand.
- Constructs nested beyond the depth limit.

`GET /api/projects/{id}/interpretation-support` returns the machine-readable
version of this list, including whether the build performs any **checksum
verification** of an imported specification against a trusted reference.

---

## Validation outcomes

| `verdict` | Meaning |
|---|---|
| `consistent_with_corpus` | Every message in the corpus satisfied the rule |
| `partially_consistent` | Some messages failed or were partially parsed |
| `contradicted` | The corpus contradicts the rule |
| `no_data` | The selected corpus contained no messages |
| `canceled` | The run was cancelled |

"Consistent with corpus" is a statement about **this corpus**, not a proof of
universal correctness. The field statistics that produced the rule usually
say so in the same words.

Each counterexample records the rule violated, the offending byte range, the
source packet references, and alternative explanations (including "this may be a
capture gap").

---

## Versioning and staleness

Every interpretation carries a version and a **checksum** over its normalized
JSON. A validation run stores the checksum it was produced under. Editing the
specification marks earlier runs `stale` with a reason, so an old result can
never be cited as if it described the current rule.

## Worked example: a hypothesis that fails

The specification above, changed to `endianness: "little"` with
`includes_header: false`, is a *plausible* mistake. Applied to the corpus it
produces counterexamples with `violated_rule` values such as
`invalid_length`, `declared_length_exceeds_message` or `field_out_of_bounds`.
This is the intended workflow: state the wrong rule, see exactly which messages
break it, correct it, re-validate.