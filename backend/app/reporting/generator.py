"""Investigation report generation.

The report is assembled from stored facts.  Every section names the evidence it
came from, so a reader can click a claim and land on the bytes that support it.
A language model, when one is enabled, may only add a clearly-labelled
narrative paragraph to a report that already exists without it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Sequence

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..core.config import Limits
from ..core.logging import get_logger
from ..models import (
    Capture,
    Evidence,
    ExperimentEvent,
    Hypothesis,
    Interpretation,
    Message,
    Packet,
    Project,
    Report,
    Stream,
    TcpSession,
    ValidationResult,
    ValidationRun,
)
from ..interpretation.engine import parse_spec

log = get_logger("mplab.report")

REPORT_VERSION = "report/1.1"


@dataclass
class Section:
    number: int
    title: str
    body: str
    evidence: list[dict[str, Any]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "number": self.number,
            "title": self.title,
            "body": self.body,
            "evidence": self.evidence,
            "notes": self.notes,
        }


@dataclass
class ReportContext:
    project: Project
    captures: list[Capture]
    sessions: list[TcpSession]
    streams: list[Stream]
    messages: list[Message]
    hypotheses: list[Hypothesis]
    interpretations: list[Interpretation]
    runs: list[ValidationRun]
    experiments: list[ExperimentEvent]
    counterexamples: list[ValidationResult]
    integrity: dict[str, Any]


def collect_context(
    session: Session,
    project: Project,
    *,
    capture_ids: Sequence[str] = (),
    interpretation_ids: Sequence[str] = (),
    storage=None,
    limits: Limits | None = None,
) -> ReportContext:
    captures = list(
        session.execute(
            select(Capture).where(
                Capture.project_id == project.id,
                *([Capture.id.in_(list(capture_ids))] if capture_ids else []),
            )
        )
        .scalars()
        .all()
    )
    ids = [c.id for c in captures]
    sessions = (
        list(
            session.execute(select(TcpSession).where(TcpSession.capture_id.in_(ids)))
            .scalars()
            .all()
        )
        if ids
        else []
    )
    streams = (
        list(
            session.execute(
                select(Stream).where(Stream.session_id.in_([s.id for s in sessions]))
            )
            .scalars()
            .all()
        )
        if sessions
        else []
    )
    messages = (
        list(
            session.execute(
                select(Message)
                .where(Message.capture_id.in_(ids))
                .order_by(Message.capture_id, Message.stream_id, Message.index_in_stream)
                .limit(50_000)
            )
            .scalars()
            .all()
        )
        if ids
        else []
    )
    hypotheses = list(
        session.execute(
            select(Hypothesis).where(Hypothesis.project_id == project.id)
        ).scalars().all()
    )
    interpretations = list(
        session.execute(
            select(Interpretation)
            .where(
                Interpretation.project_id == project.id,
                *([Interpretation.id.in_(list(interpretation_ids))] if interpretation_ids else []),
            )
            .order_by(Interpretation.created_at)
        ).scalars().all()
    )
    runs = list(
        session.execute(
            select(ValidationRun)
            .where(ValidationRun.interpretation_id.in_([i.id for i in interpretations]))
            .order_by(ValidationRun.started_at)
        ).scalars().all()
        if interpretations
        else []
    )
    experiments = list(
        session.execute(
            select(ExperimentEvent)
            .where(ExperimentEvent.project_id == project.id)
            .order_by(ExperimentEvent.timestamp)
            .limit(5_000)
        ).scalars().all()
    )
    counterexamples = (
        list(
            session.execute(
                select(ValidationResult)
                .where(
                    ValidationResult.validation_run_id.in_([r.id for r in runs]),
                    ValidationResult.outcome == "failed",
                )
                .limit(500)
            ).scalars().all()
        )
        if runs
        else []
    )
    integrity: dict[str, Any] = {"all_match": None, "captures": [], "note": "Integrity was not verified during this run."}
    if storage is not None:
        from ..services.project_service import ProjectService

        integrity = ProjectService(session, storage, limits).verify_integrity(project)
    return ReportContext(
        project=project,
        captures=captures,
        sessions=sessions,
        streams=streams,
        messages=messages,
        hypotheses=hypotheses,
        interpretations=interpretations,
        runs=runs,
        experiments=experiments,
        counterexamples=counterexamples,
        integrity=integrity,
    )


def build_sections(ctx: ReportContext) -> list[Section]:
    sections: list[Section] = []

    sections.append(
        Section(
            1,
            "Project",
            f"**{ctx.project.name}**\n\n{ctx.project.description or '_No description recorded._'}",
            evidence=[{"kind": "project", "id": ctx.project.id}],
        )
    )

    capture_lines = []
    capture_evidence = []
    for capture in ctx.captures:
        status = capture.analysis_status
        capture_lines.append(
            f"- `{capture.name}` - format {capture.format}, {capture.file_size} bytes, "
            f"SHA-256 `{capture.sha256}`, analysis: {status}"
        )
        capture_evidence.append(
            {"kind": "capture", "id": capture.id, "sha256": capture.sha256}
        )
    sections.append(
        Section(
            2,
            "Source captures",
            "\n".join(capture_lines) if capture_lines else "_No captures imported._",
            evidence=capture_evidence,
            notes=[
                "SHA-256 lets a reader confirm they hold the same bytes; it does not "
                "prove where the file came from."
            ],
        )
    )

    experiment_lines = [
        f"- {datetime.fromtimestamp(e.timestamp, tz=timezone.utc).isoformat()} "
        f"{e.action} {json.dumps(e.parameters, ensure_ascii=False)}"
        for e in ctx.experiments[:200]
    ]
    sections.append(
        Section(
            3,
            "Experiment conditions",
            "\n".join(experiment_lines) if experiment_lines else "_No experiment log imported._",
            evidence=[{"kind": "experiment", "id": e.id} for e in ctx.experiments[:50]],
        )
    )

    corpus = {
        "tcp_sessions": len(ctx.sessions),
        "streams": len(ctx.streams),
        "messages": len(ctx.messages),
    }
    corpus["bytes_in_streams"] = sum(s.present_bytes or 0 for s in ctx.streams)
    sections.append(
        Section(
            4,
            "Corpus examined",
            "\n".join(f"- {key}: {value}" for key, value in corpus.items()),
            evidence=[{"kind": "session", "id": s.id} for s in ctx.sessions[:50]],
        )
    )

    endpoint_counts: dict[str, int] = {}
    for session in ctx.sessions:
        for endpoint in (session.client_endpoint, session.server_endpoint):
            if endpoint:
                endpoint_counts[endpoint] = endpoint_counts.get(endpoint, 0) + 1
    endpoint_lines = [f"- `{k}` in {v} session(s)" for k, v in sorted(endpoint_counts.items())]
    sections.append(
        Section(
            5,
            "TCP sessions observed",
            "\n".join(endpoint_lines) if endpoint_lines else "_No TCP sessions found._",
            evidence=[{"kind": "session", "id": s.id} for s in ctx.sessions[:100]],
        )
    )

    patterns = _pattern_findings(ctx)
    sections.append(
        Section(
            6,
            "Observed patterns",
            "\n".join(f"- {p}" for p in patterns) if patterns else "_Not enough data to state a pattern._",
            evidence=[],
            notes=["Each pattern above is a description of observed bytes, not a claim about meaning."],
        )
    )

    spec_sections = []
    spec_evidence = []
    for interpretation in ctx.interpretations:
        try:
            spec = parse_spec(interpretation.schema_json)
        except Exception as exc:  # pragma: no cover - defensive
            spec_sections.append(f"- `{interpretation.name}` could not be parsed: {exc}")
            continue
        fields = ", ".join(f"{f.name}:{f.kind}@{f.offset}" for f in spec.fields)
        spec_sections.append(
            f"- **{interpretation.name}** (v{interpretation.version}, "
            f"checksum `{interpretation.checksum[:16]}`)\n"
            f"  - framing: `{spec.framing.method}`\n"
            f"  - fields: {fields or '_none_'}"
        )
        spec_evidence.append(
            {"kind": "interpretation", "id": interpretation.id, "version": interpretation.version}
        )
    sections.append(
        Section(
            7,
            "Proposed protocol structure",
            "\n".join(spec_sections) if spec_sections else "_No interpretation created yet._",
            evidence=spec_evidence,
            notes=["Field names are analyst labels unless marked otherwise in the specification."],
        )
    )

    run_lines = []
    run_evidence = []
    for run in ctx.runs:
        summary = run.summary or {}
        run_lines.append(
            f"- run `{run.id}` on {run.started_at.isoformat()}: "
            f"{summary.get('verdict', run.status)} - matched {summary.get('matched', 0)}, "
            f"failed {summary.get('failed', 0)} of {summary.get('total', 0)}"
            + ("  **(stale: rule changed afterwards)**" if run.stale else "")
        )
        run_evidence.append({"kind": "validation_run", "id": run.id})
    sections.append(
        Section(
            8,
            "Validated rules",
            "\n".join(run_lines) if run_lines else "_No validation run recorded._",
            evidence=run_evidence,
            notes=[
                "A rule that held across a corpus is supported by that corpus. It is not "
                "proven for data that has not been observed."
            ],
        )
    )

    if ctx.counterexamples:
        lines = []
        evidence = []
        for result in ctx.counterexamples[:50]:
            entries = (result.diagnostics or {}).get("entries", [])
            errors = [e for e in entries if e.get("severity") == "error"]
            lines.append(
                f"- message `{result.message_id}`: "
                + "; ".join(e.get("message", "") for e in errors)
            )
            evidence.append({"kind": "validation_result", "id": result.id, "message_id": result.message_id})
        section_body = "\n".join(lines)
    else:
        section_body = "_No counterexamples were recorded for the current rule versions._"
        evidence = []
    sections.append(
        Section(
            9,
            "Counterexamples",
            section_body,
            evidence=evidence,
            notes=[
                "A counterexample may be a wrong rule or an incomplete capture; both "
                "explanations are kept until one is ruled out."
            ],
        )
    )

    unknown = _unknown_regions(ctx)
    sections.append(Section(10, "Unresolved regions", unknown, evidence=[]))

    quality = _capture_quality(ctx)
    sections.append(Section(11, "Capture quality diagnostics", quality, evidence=[]))

    sections.append(Section(12, "Limitations", _limitations(ctx)))

    sections.append(Section(13, "Conclusions", _conclusions(ctx)))

    sections.append(Section(14, "Recommended next experiments", _recommendations(ctx)))

    sections.append(Section(15, "Reproduction instructions", _reproduction(ctx)))
    return sections


def _pattern_findings(ctx: ReportContext) -> list[str]:
    out: list[str] = []
    by_protocol: dict[str, int] = {}
    for stream in ctx.streams:
        by_protocol[stream.protocol_label] = by_protocol.get(stream.protocol_label, 0) + 1
    for protocol, count in sorted(by_protocol.items()):
        out.append(f"{count} stream(s) classified as `{protocol}`")
    lengths = [m.present_length or 0 for m in ctx.messages]
    if lengths:
        out.append(
            f"message lengths range from {min(lengths)} to {max(lengths)} bytes "
            f"({len(set(lengths))} distinct values over {len(lengths)} messages)"
        )
    conflicting = [s for s in ctx.streams if s.conflicts]
    if conflicting:
        out.append(f"{len(conflicting)} stream(s) contain byte conflicts at overlapping offsets")
    gapped = [s for s in ctx.streams if s.holes]
    if gapped:
        out.append(f"{len(gapped)} stream(s) contain gaps; some bytes were never captured")
    return out


def _unknown_regions(ctx: ReportContext) -> str:
    lines = []
    for interpretation in ctx.interpretations:
        try:
            spec = parse_spec(interpretation.schema_json)
        except Exception:
            continue
        unknown = [f.name for f in spec.fields if f.kind == "unknown" or f.semantic_status == "unknown"]
        if unknown:
            lines.append(f"- `{interpretation.name}` leaves {', '.join(unknown)} unexplained")
    if not lines:
        lines.append("- No explicitly unknown regions were declared in the current specifications.")
    return "\n".join(lines)


def _capture_quality(ctx: ReportContext) -> str:
    lines = []
    incomplete = [s for s in ctx.sessions if s.completeness_status != "complete"]
    lines.append(f"- {len(incomplete)} of {len(ctx.sessions)} sessions were not fully captured")
    truncated = sum(1 for s in ctx.streams if (s.diagnostics or {}).get("is_truncated_start"))
    lines.append(f"- {truncated} stream(s) had no observed connection start")
    if ctx.integrity.get("all_match") is not None:
        lines.append(
            f"- source integrity: {'all files match their recorded hashes' if ctx.integrity['all_match'] else 'MISMATCH DETECTED'}"
        )
    return "\n".join(lines)


def _limitations(ctx: ReportContext) -> str:
    return "\n".join(
        [
            "- Conclusions cover only the captures listed above.",
            "- A reconstructed stream can be incomplete; gaps are shown, never filled.",
            "- Conflicting bytes at overlapping offsets were resolved by the recorded "
            "policy, and both variants remain recorded.",
            "- Field semantics are analyst hypotheses until a validation run supports them.",
            "- No claim here has been confirmed against the device documentation.",
        ]
    )


def _conclusions(ctx: ReportContext) -> str:
    supported = [
        h for h in ctx.hypotheses if h.status == "supported"
    ]
    contradicted = [h for h in ctx.hypotheses if h.status == "contradicted"]
    lines = []
    if supported:
        lines.append(
            f"- {len(supported)} hypothesis/hypotheses are supported by every message in "
            "the current corpus."
        )
    if contradicted:
        lines.append(f"- {len(contradicted)} hypothesis/hypotheses are contradicted by the corpus.")
    if ctx.counterexamples:
        lines.append(
            f"- {len(ctx.counterexamples)} message(s) contradict the current rules and remain unresolved."
        )
    if not lines:
        lines.append("- No hypothesis has been carried to a supported state yet.")
    return "\n".join(lines)


def _recommendations(ctx: ReportContext) -> str:
    suggestions = [
        "- Capture a second recording of the same action sequence and validate the current rules against it.",
        "- Vary one parameter at a time so its field can be isolated by correlation.",
        "- Record a session that starts at connection establishment so the stream has no unknown prefix.",
        "- Investigate the counterexamples above before extending the rules further.",
    ]
    if not ctx.experiments:
        suggestions.insert(
            0,
            "- Import the experiment action log so messages can be tied to the action that produced them.",
        )
    return "\n".join(suggestions)


def _reproduction(ctx: ReportContext) -> str:
    steps = [
        "1. Import the .mplab project archive (or the individual PCAP files listed above).",
        "2. Re-run capture analysis with the recorded options.",
        "3. Import the interpretation specification(s) - the checksum is printed in section 7.",
        "4. Run validation against the same corpus; the verdict must match section 8.",
    ]
    options = ctx.captures[0].stats.get("options") if ctx.captures else None
    if options:
        steps.insert(2, f"   Analysis options used: `{json.dumps(options, sort_keys=True)}`")
    return "\n".join(steps)


def render_markdown(ctx: ReportContext, sections: list[Section], title: str) -> str:
    lines = [f"# {title}", "", f"_Generated by Madrigal Protocol Lab ({REPORT_VERSION}) on "
             f"{datetime.now(timezone.utc).isoformat()}_", ""]
    for section in sections:
        lines.append(f"## {section.number}. {section.title}")
        lines.append("")
        lines.append(section.body)
        lines.append("")
        if section.evidence:
            refs = ", ".join(
                f"{e.get('kind')}:{e.get('id')}" for e in section.evidence[:15]
            )
            more = "" if len(section.evidence) <= 15 else f" (+{len(section.evidence) - 15} more)"
            lines.append(f"_Evidence: {refs}{more}_")
            lines.append("")
        for note in section.notes:
            lines.append(f"> {note}")
            lines.append("")
    return "\n".join(lines)


def store_report(
    session: Session, ctx: ReportContext, sections: list[Section], markdown: str, title: str
) -> Report:
    report = Report(
        project_id=ctx.project.id,
        title=title,
        generator="template",
        sections=[s.to_dict() for s in sections],
        markdown=markdown,
        facts={
            "captures": [c.id for c in ctx.captures],
            "sessions": len(ctx.sessions),
            "streams": len(ctx.streams),
            "messages": len(ctx.messages),
            "hypotheses": [h.id for h in ctx.hypotheses],
            "interpretations": [
                {"id": i.id, "version": i.version, "checksum": i.checksum}
                for i in ctx.interpretations
            ],
            "validation_runs": [r.id for r in ctx.runs],
            "counterexamples": len(ctx.counterexamples),
            "integrity": ctx.integrity.get("all_match"),
        },
    )
    session.add(report)
    session.commit()
    return report


_ = (Evidence, Packet, func, Session, REPORT_VERSION)