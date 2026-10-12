"""Hypotheses, executable interpretations and validation runs.

This is where a hypothesis stops being a note and becomes evidence.  Running a
validation produces, for every message in the corpus:

* the extracted field values,
* whether the specification's constraints held,
* the byte range that proves it,
* and, when it fails, a first-class **counterexample** pointing at the exact
  bytes that contradict the rule.

Changing a specification marks the previous run ``stale`` rather than deleting
it, so the history of what was believed and when stays inspectable.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from ..analyzers.byte_analysis import shannon_entropy
from ..interpretation.engine import (
    ENGINE_VERSION,
    InterpretationEngine,
    InterpretationSpec,
    SpecError,
    export_spec,
    parse_spec,
)
from ..models import (
    Capture,
    Evidence,
    Hypothesis,
    Interpretation,
    Message,
    Packet,
    Stream,
    TcpSession,
    ValidationResult,
    ValidationRun,
)
from ..core.errors import Conflict, NotFound, ValidationFailed
from .stream_store import StreamStore

VALIDATION_VERSION = f"validation/{ENGINE_VERSION}"

HYPOTHESIS_STATUSES = (
    "draft",
    "proposed",
    "testing",
    "supported",
    "contradicted",
    "revised",
    "rejected",
)

OUTCOME_MATCHED = "matched"
OUTCOME_PARTIAL = "partial"
OUTCOME_FAILED = "failed"
OUTCOME_UNPARSED = "unparsed"


def interpretation_payload(row: Interpretation) -> dict[str, Any]:
    """Serialise an interpretation for the API.

    The ORM attribute is ``schema_json`` (its historical name); the API field is
    ``specification``.  This mapping lives in one place so the project-scoped
    routes and the flat aliases cannot drift apart — the previous arrangement
    left ``GET /projects/{id}/interpretations`` returning a 500 because it handed
    raw ORM rows to ``InterpretationOut``, which expects ``specification``.
    """
    return {
        "id": row.id,
        "project_id": row.project_id,
        "hypothesis_id": row.hypothesis_id,
        "name": row.name,
        "specification": row.schema_json,
        "version": row.version,
        "checksum": row.checksum,
        "created_at": row.created_at,
        "notes": row.notes,
    }


@dataclass
class CorpusSelection:
    capture_ids: list[str]
    session_ids: list[str] = field(default_factory=list)
    directions: list[str] = field(default_factory=lambda: ["a2b", "b2a"])
    limit_per_stream: int = 50_000

    def to_dict(self) -> dict[str, Any]:
        return {
            "capture_ids": self.capture_ids,
            "session_ids": self.session_ids,
            "directions": self.directions,
            "limit_per_stream": self.limit_per_stream,
        }


@dataclass
class ValidationSummary:
    run_id: str
    total: int
    matched: int
    partial: int
    failed: int
    unparsed: int
    counterexamples: int
    by_message_type: dict[str, int]
    verdict: str
    notes: list[str]


class InterpretationService:
    def __init__(self, session: Session, storage) -> None:
        self.db = session
        self.storage = storage

    # -- hypotheses -------------------------------------------------------- #

    def create_hypothesis(
        self,
        project_id: str,
        *,
        name: str,
        description: str = "",
        scope: dict[str, Any] | None = None,
        proposed_structure: dict[str, Any] | None = None,
        observations: list[Any] | None = None,
        evidence_refs: list[Any] | None = None,
        status: str = "draft",
        author: str = "analyst",
        origin: str = "analyst",
    ) -> Hypothesis:
        name = (name or "").strip()
        if not name:
            raise ValidationFailed("Hypothesis name must not be empty.")
        if status not in HYPOTHESIS_STATUSES:
            raise ValidationFailed(
                f"Unknown hypothesis status {status!r}.",
                details={"allowed": list(HYPOTHESIS_STATUSES)},
            )
        hypothesis = Hypothesis(
            project_id=project_id,
            name=name[:200],
            description=description or "",
            scope=scope or {},
            proposed_structure=proposed_structure or {},
            observations=observations or [],
            evidence_refs=evidence_refs or [],
            status=status,
            author=author[:120],
            origin=origin[:32],
        )
        self.db.add(hypothesis)
        self.db.commit()
        return hypothesis

    def update_hypothesis(self, hypothesis_id: str, patch: dict[str, Any]) -> Hypothesis:
        hypothesis = self.db.get(Hypothesis, hypothesis_id)
        if hypothesis is None:
            raise NotFound(f"Hypothesis {hypothesis_id!r} does not exist.")
        if "status" in patch and patch["status"] not in HYPOTHESIS_STATUSES:
            raise ValidationFailed(f"Unknown hypothesis status {patch['status']!r}.")
        for key in (
            "name", "description", "scope", "proposed_structure",
            "observations", "evidence_refs", "counterexample_refs",
            "unknown_regions", "status",
        ):
            if key in patch:
                setattr(hypothesis, key, patch[key])
        hypothesis.version += 1
        self.db.commit()
        return hypothesis

    # -- interpretations --------------------------------------------------- #

    def create_interpretation(
        self,
        project_id: str,
        *,
        name: str,
        schema_json: dict[str, Any] | str | bytes,
        hypothesis_id: str | None = None,
        notes: str = "",
    ) -> Interpretation:
        try:
            spec = parse_spec(schema_json)
        except SpecError as exc:
            raise ValidationFailed(f"The specification was rejected: {exc}") from exc
        row = Interpretation(
            project_id=project_id,
            hypothesis_id=hypothesis_id,
            name=(name or spec.protocol_name)[:200],
            schema_json=export_spec(spec),
            checksum=spec.compute_checksum(),
            notes=notes,
        )
        self.db.add(row)
        self.db.flush()
        self._mark_previous_stale(project_id, row.id)
        self.db.commit()
        return row

    def update_interpretation(self, interpretation_id: str, schema_json: Any, *, notes: str | None = None) -> Interpretation:
        row = self.db.get(Interpretation, interpretation_id)
        if row is None:
            raise NotFound(f"Interpretation {interpretation_id!r} does not exist.")
        try:
            spec = parse_spec(schema_json)
        except SpecError as exc:
            raise ValidationFailed(f"The specification was rejected: {exc}") from exc
        old_checksum = row.checksum
        row.schema_json = export_spec(spec)
        row.checksum = spec.compute_checksum()
        row.version += 1
        if notes is not None:
            row.notes = notes
        self.db.flush()
        if old_checksum != row.checksum:
            self._mark_previous_stale(row.project_id, row.id)
        self.db.commit()
        return row

    def _mark_previous_stale(self, project_id: str, current_id: str) -> None:
        """Mark runs produced by *other* interpretations in this project stale.

        Rationale: a run is only meaningful against the exact specification that
        produced it.  When an interpretation is edited, its own older runs become
        stale because the rule they describe no longer exists; runs belonging to
        other interpretations are untouched.
        """
        rows = (
            self.db.execute(
                select(ValidationRun.id, ValidationRun.interpretation_id).where(
                    ValidationRun.project_id == project_id,
                    ValidationRun.stale.is_(False),
                )
            )
            .all()
        )
        for run_id, interpretation_id in rows:
            if interpretation_id == current_id:
                self.db.execute(
                    update(ValidationRun)
                    .where(ValidationRun.id == run_id)
                    .values(stale=True)
                )

    # -- validation -------------------------------------------------------- #

    def validate(
        self,
        interpretation: Interpretation,
        corpus: CorpusSelection,
        *,
        progress=None,
        cancel_check=None,
    ) -> ValidationSummary:
        spec = parse_spec(interpretation.schema_json)
        engine = InterpretationEngine(spec)

        run = ValidationRun(
            interpretation_id=interpretation.id,
            project_id=interpretation.project_id,
            corpus=corpus.to_dict(),
            settings={"engine_version": ENGINE_VERSION, "spec_checksum": spec.compute_checksum()},
            status="running",
            analyzer_version=VALIDATION_VERSION,
        )
        self.db.add(run)
        self.db.commit()

        totals = {"matched": 0, "partial": 0, "failed": 0, "unparsed": 0}
        counterexamples = 0
        by_type: dict[str, int] = {}
        processed = 0

        try:
            for capture_id in corpus.capture_ids:
                capture = self.db.get(Capture, capture_id)
                if capture is None:
                    raise NotFound(f"Capture {capture_id!r} does not exist.")
                store = self._stream_store(capture)
                if not store.available:
                    run.status = "failed"
                    run.summary = {
                        "error": (
                            "The capture has not been analysed yet, so no reconstructed "
                            "stream is available to validate against. Run the analysis "
                            "first."
                        )
                    }
                    run.completed_at = datetime.now(timezone.utc)
                    self.db.commit()
                    raise Conflict(
                        "The selected capture has not been analysed yet.",
                        details={"capture_id": capture_id},
                    )

                query = (
                    select(Message, Stream)
                    .join(Stream, Stream.id == Message.stream_id)
                    .join(TcpSession, TcpSession.id == Stream.session_id)
                    .where(
                        Message.capture_id == capture_id,
                        Stream.direction.in_(corpus.directions),
                    )
                    .order_by(Stream.id, Message.index_in_stream)
                )
                if corpus.session_ids:
                    query = query.where(TcpSession.id.in_(corpus.session_ids))
                rows = self.db.execute(query).all()

                per_stream: dict[str, int] = {}
                for message_row, stream_row in rows:
                    if per_stream.get(stream_row.id, 0) >= corpus.limit_per_stream:
                        continue
                    per_stream[stream_row.id] = per_stream.get(stream_row.id, 0) + 1
                    if cancel_check is not None and cancel_check():
                        run.status = "canceled"
                        run.completed_at = datetime.now(timezone.utc)
                        self.db.commit()
                        return self._finalise(run, totals, counterexamples, by_type, "canceled")

                    outcome, extracted, diagnostics, evidence = self._apply(
                        engine, store, stream_row, message_row
                    )
                    totals[outcome] = totals.get(outcome, 0) + 1
                    type_name = extracted.get("message_type") if isinstance(extracted, dict) else None
                    label = (
                        type_name.get("label") if isinstance(type_name, dict)
                        else type_name if isinstance(type_name, str)
                        else "unlabelled"
                    )
                    key = f"{label}:{outcome}"
                    by_type[key] = by_type.get(key, 0) + 1

                    violated = next(
                        (
                            d.get("code")
                            for d in diagnostics
                            if d.get("severity") == "error"
                        ),
                        None,
                    )
                    result = ValidationResult(
                        validation_run_id=run.id,
                        message_id=message_row.id,
                        stream_id=stream_row.id,
                        capture_id=capture_id,
                        outcome=outcome,
                        extracted_fields=_jsonable(extracted),
                        diagnostics={"entries": diagnostics},
                        evidence_refs=evidence,
                        violated_rule=violated,
                    )
                    self.db.add(result)
                    processed += 1
                    if outcome == OUTCOME_FAILED and processed % 50 == 0:
                        self.db.flush()
                    if progress is not None and processed % 200 == 0:
                        progress(min(0.95, processed / 1000.0), f"Validated {processed} messages")

                self.db.flush()
                if progress is not None:
                    progress(0.9, f"Finished capture {capture.name}")
        except _Interrupted:
            run.status = "canceled"
            run.completed_at = datetime.now(timezone.utc)
            self.db.commit()
            return self._finalise(run, totals, counterexamples, by_type, "canceled")

        self.db.commit()
        verdict = self._verdict(totals, processed)
        return self._finalise(run, totals, counterexamples, by_type, verdict)

    def _verdict(self, totals: dict[str, int], processed: int) -> str:
        if processed == 0:
            return "no_data"
        if totals.get(OUTCOME_FAILED, 0) == 0 and totals.get(OUTCOME_UNPARSED, 0) == 0:
            return "consistent_with_corpus"
        if totals.get(OUTCOME_FAILED, 0) / processed > 0.1:
            return "contradicted"
        return "partially_consistent"

    def _finalise(
        self,
        run: ValidationRun,
        totals: dict[str, int],
        counterexamples: int,
        by_type: dict[str, int],
        verdict: str,
    ) -> ValidationSummary:
        summary = {
            "total": sum(totals.values()),
            "matched": totals.get("matched", 0),
            "partial": totals.get("partial", 0),
            "failed": totals.get("failed", 0),
            "unparsed": totals.get("unparsed", 0),
            "counterexamples": sum(
                1
                for row in self.db.query(ValidationResult)
                .filter(
                    ValidationResult.validation_run_id == run.id,
                    ValidationResult.outcome == OUTCOME_FAILED,
                )
                .all()
            ),
            "by_message_type": by_type,
            "verdict": verdict,
            "notes": [
                "'Supported by observed data' means the rule held for every message in "
                "this corpus. It is not a proof that the rule is universally correct.",
            ],
        }
        run.summary = summary
        if run.status != "canceled":
            run.status = "completed"
        run.completed_at = datetime.now(timezone.utc)
        self.db.commit()
        return ValidationSummary(
            run_id=run.id,
            total=summary["total"],
            matched=summary["matched"],
            partial=summary["partial"],
            failed=summary["failed"],
            unparsed=summary["unparsed"],
            counterexamples=summary["counterexamples"],
            by_message_type=by_type,
            verdict=verdict,
            notes=summary["notes"],
        )

    # -- per-message ------------------------------------------------------- #

    def _apply(
        self, engine: InterpretationEngine, store: StreamStore, stream_row: Stream, message_row: Message
    ) -> tuple[str, dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
        descriptor = store.get(stream_row.id)
        if descriptor is None:
            return (
                OUTCOME_UNPARSED,
                {},
                [{"severity": "error", "code": "stream_missing",
                  "message": "the reconstructed stream artefact is missing"}],
                [],
            )
        stream = store.build(descriptor)
        payload = stream.read(message_row.start_offset, message_row.end_offset - message_row.start_offset)
        if len(payload) != message_row.present_length or not message_row.complete:
            return (
                OUTCOME_PARTIAL,
                {},
                [{
                    "severity": "warning",
                    "code": "partial_message",
                    "message": (
                        "the message spans a gap in the reconstructed stream; only "
                        f"{len(payload)} of {message_row.end_offset - message_row.start_offset} "
                        "bytes are available"
                    ),
                }],
                message_row.packet_references,
            )
        try:
            # Framing is part of the rule, so a framing failure is a validation
            # failure - not a silent pass.  Without this, a specification whose
            # length convention is wrong would still "match" every message.
            _spans, framing_diagnostics = engine.split_messages(payload)
        except SpecError as exc:
            return (
                OUTCOME_UNPARSED,
                {},
                [{"severity": "error", "code": "framing_error", "message": str(exc)}],
                message_row.packet_references,
            )
        framing_errors = [d for d in framing_diagnostics if d.get("severity") == "error"]
        if framing_errors:
            return (
                OUTCOME_FAILED,
                {},
                framing_errors,
                list(message_row.packet_references)
                + [
                    {
                        "kind": "framing_violation",
                        "start_offset": message_row.start_offset,
                        "end_offset": message_row.end_offset,
                        "rule": d.get("code"),
                    }
                    for d in framing_errors
                ],
            )
        try:
            result = engine.parse(payload)
        except SpecError as exc:
            return (
                OUTCOME_UNPARSED,
                {},
                [{"severity": "error", "code": "spec_error", "message": str(exc)}],
                message_row.packet_references,
            )
        errors = [d for d in result.diagnostics if d.get("severity") == "error"]
        warnings = [d for d in result.diagnostics if d.get("severity") != "error"]
        outcome = OUTCOME_FAILED if errors else (OUTCOME_PARTIAL if warnings else OUTCOME_MATCHED)

        evidence = list(message_row.packet_references)
        for diagnostic in errors:
            offset = diagnostic.get("offset")
            if isinstance(offset, int) and 0 <= offset <= len(payload):
                evidence.append(
                    {
                        "kind": "violated_byte",
                        "start_offset": message_row.start_offset + offset,
                        "end_offset": message_row.start_offset + offset + 1,
                        "byte": payload[offset : offset + 1].hex(),
                        "rule": diagnostic.get("code"),
                    }
                )
        extracted = dict(result.fields)
        if result.message_type:
            extracted["__message_type__"] = result.message_type
        return outcome, extracted, result.diagnostics, evidence

    # -- helpers ----------------------------------------------------------- #

    def _stream_store(self, capture: Capture) -> StreamStore:
        paths = self.storage.capture_paths(capture.project_id, capture.id, capture.format)
        store = StreamStore(paths.stream_blob, paths.stream_index)
        for descriptor in store.descriptors().values() if store.available else []:
            descriptor.capture_id = capture.id
        return store

    def counterexamples(self, run_id: str, limit: int = 100) -> list[dict[str, Any]]:
        rows = (
            self.db.execute(
                select(ValidationResult, Message, Stream)
                .join(Message, Message.id == ValidationResult.message_id)
                .join(Stream, Stream.id == Message.stream_id)
                .where(
                    ValidationResult.validation_run_id == run_id,
                    ValidationResult.outcome == OUTCOME_FAILED,
                )
                .limit(limit)
            )
            .all()
        )
        out: list[dict[str, Any]] = []
        for result, message, stream in rows:
            entries = (result.diagnostics or {}).get("entries", [])
            errors = [d for d in entries if d.get("severity") == "error"]
            out.append(
                {
                    "result_id": result.id,
                    "message_id": message.id,
                    "stream_id": stream.id,
                    "capture_id": message.capture_id,
                    "start_offset": message.start_offset,
                    "end_offset": message.end_offset,
                    "length": message.end_offset - message.start_offset,
                    "violated_rule": result.violated_rule,
                    "reasons": errors,
                    "extracted_fields": result.extracted_fields,
                    "evidence": result.evidence_refs,
                    "alternative_explanations": _alternatives(message, errors),
                    "explanation": _counterexample_narrative(message, errors),
                }
            )
        return out

    def get_run(self, run_id: str) -> ValidationRun:
        run = self.db.get(ValidationRun, run_id)
        if run is None:
            raise NotFound(f"Validation run {run_id!r} does not exist.")
        return run


class _Interrupted(Exception):
    pass


def _alternatives(message: Message, errors: list[dict[str, Any]]) -> list[str]:
    """Plausible alternative readings of a counterexample."""
    out: list[str] = []
    if not message.complete:
        out.append(
            "The message range overlaps a gap in the reconstructed stream, so the "
            "capture may simply be incomplete rather than the rule being wrong."
        )
    diagnostics = message.diagnostics or {}
    if diagnostics.get("reason"):
        out.append(f"Framing diagnostic on this message: {diagnostics['reason']}.")
    if diagnostics.get("rejected_length") is not None:
        out.append(
            "The declared length at this offset was outside the accepted range; a "
            "different length convention (body-only, or a different endianness) "
            "would explain it."
        )
    for error in errors:
        if error.get("code") == "unmapped_value":
            out.append(
                "The specification declares a value map that does not cover this "
                "input; adding the observed value would explain the result without "
                "changing the field layout."
            )
        if error.get("code") == "constraint_violated":
            out.append(
                "Either the constraint range is wrong, or this byte range carries a "
                "different meaning than assumed."
            )
    if not out:
        out.append(
            "No alternative reading could be derived automatically; inspect the raw "
            "bytes for this message in the stream viewer."
        )
    return out


def _counterexample_narrative(message: Message, errors: list[dict[str, Any]]) -> str:
    where = ", ".join(
        f"{e.get('field', '?')}: {e.get('message', '')}" for e in errors
    ) or "the message did not satisfy the specification"
    return (
        f"Rule violated at stream offsets {message.start_offset}..{message.end_offset} "
        f"({message.end_offset - message.start_offset} bytes, capture message "
        f"#{message.index_in_stream}): {where}."
    )


def _jsonable(value: Any) -> Any:
    try:
        json.dumps(value)
        return value
    except TypeError:
        return {k: str(v) for k, v in dict(value).items()}


_ = (func, select, Iterable, Packet, Evidence, InterpretationSpec, shannon_entropy)