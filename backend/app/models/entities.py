"""SQLAlchemy models for Madrigal Protocol Lab.

Design notes
------------
* Imported capture files are treated as immutable.  Nothing in this schema
  mutates the original bytes; every derived artefact lives in a separate table
  and/or a separate file in managed storage.
* Packet payloads are **not** stored inline.  ``Packet.payload_offset`` /
  ``payload_length`` point into the immutable original capture file, so a
  250k-packet capture stays cheap and the original remains the single source of
  truth.
* Every derived row carries enough provenance (capture id, session id, stream
  offset, source packet ids, analyzer version) to satisfy the "evidence"
  requirement of the product.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    JSON,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..db.base import Base, created_column, new_id, updated_column, utcnow


def _pk() -> Mapped[str]:
    return mapped_column(String(32), primary_key=True, default=new_id)


class Project(Base):
    __tablename__ = "projects"

    id: Mapped[str] = _pk()
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    schema_version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    settings: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = created_column()
    updated_at: Mapped[datetime] = updated_column()

    captures: Mapped[list["Capture"]] = relationship(
        back_populates="project", cascade="all, delete-orphan"
    )


class Capture(Base):
    __tablename__ = "captures"

    id: Mapped[str] = _pk()
    project_id: Mapped[str] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True, nullable=False
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    relative_path: Mapped[str] = mapped_column(String(512), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    file_size: Mapped[int] = mapped_column(BigInteger, nullable=False)
    format: Mapped[str] = mapped_column(String(16), nullable=False)
    link_type: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    imported_at: Mapped[datetime] = created_column()
    analysis_status: Mapped[str] = mapped_column(String(32), default="pending", nullable=False)
    diagnostics: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    stats: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    source_kind: Mapped[str] = mapped_column(String(32), default="user_upload", nullable=False)
    immutable: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    project: Mapped[Project] = relationship(back_populates="captures")
    packets: Mapped[list["Packet"]] = relationship(
        back_populates="capture", cascade="all, delete-orphan", passive_deletes=True
    )
    sessions: Mapped[list["TcpSession"]] = relationship(
        back_populates="capture", cascade="all, delete-orphan", passive_deletes=True
    )

    __table_args__ = (
        UniqueConstraint("project_id", "name", name="uq_capture_name_in_project"),
    )


class Packet(Base):
    __tablename__ = "packets"

    id: Mapped[str] = _pk()
    capture_id: Mapped[str] = mapped_column(
        ForeignKey("captures.id", ondelete="CASCADE"), index=True, nullable=False
    )
    packet_index: Mapped[int] = mapped_column(BigInteger, nullable=False)
    timestamp: Mapped[float] = mapped_column(Float, nullable=False)
    captured_length: Mapped[int] = mapped_column(Integer, nullable=False)
    original_length: Mapped[int] = mapped_column(Integer, nullable=False)
    source_address: Mapped[str] = mapped_column(String(45), index=True, nullable=False)
    destination_address: Mapped[str] = mapped_column(String(45), index=True, nullable=False)
    source_port: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    destination_port: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    transport_protocol: Mapped[str] = mapped_column(String(16), default="", nullable=False)
    tcp_sequence: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    tcp_acknowledgment: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    tcp_flags: Mapped[int | None] = mapped_column(Integer, nullable=True)
    tcp_window: Mapped[int | None] = mapped_column(Integer, nullable=True)
    tcp_options: Mapped[str | None] = mapped_column(String(64), nullable=True)
    payload_offset: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    payload_length: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    truncated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    session_id: Mapped[str | None] = mapped_column(
        ForeignKey("tcp_sessions.id", ondelete="SET NULL"), index=True, nullable=True
    )

    capture: Mapped[Capture] = relationship(back_populates="packets")

    __table_args__ = (
        UniqueConstraint("capture_id", "packet_index", name="uq_packet_index_in_capture"),
        Index("ix_packet_capture_time", "capture_id", "timestamp"),
        Index("ix_packet_capture_tuple", "capture_id", "source_address",
              "destination_address", "source_port", "destination_port"),
    )


class TcpSession(Base):
    __tablename__ = "tcp_sessions"

    id: Mapped[str] = _pk()
    capture_id: Mapped[str] = mapped_column(
        ForeignKey("captures.id", ondelete="CASCADE"), index=True, nullable=False
    )
    project_id: Mapped[str] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True, nullable=False
    )
    session_identity: Mapped[str] = mapped_column(String(96), index=True, nullable=False)
    endpoint_a: Mapped[str] = mapped_column(String(64), nullable=False)
    endpoint_b: Mapped[str] = mapped_column(String(64), nullable=False)
    client_endpoint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    server_endpoint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    role_confidence: Mapped[str] = mapped_column(String(24), default="unknown", nullable=False)
    start_time: Mapped[float] = mapped_column(Float, nullable=False)
    end_time: Mapped[float] = mapped_column(Float, nullable=False)
    start_packet_index: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    completeness_status: Mapped[str] = mapped_column(String(24), default="unknown", nullable=False)
    reconstruction_policy: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    diagnostics: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    analyzer_version: Mapped[str] = mapped_column(String(32), default="", nullable=False)
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    capture: Mapped[Capture] = relationship(back_populates="sessions")
    streams: Mapped[list["Stream"]] = relationship(
        back_populates="session", cascade="all, delete-orphan", passive_deletes=True
    )

    __table_args__ = (
        UniqueConstraint("capture_id", "session_identity", name="uq_session_identity_in_capture"),
        Index("ix_session_capture_time", "capture_id", "start_time"),
    )


class Stream(Base):
    __tablename__ = "streams"

    id: Mapped[str] = _pk()
    session_id: Mapped[str] = mapped_column(
        ForeignKey("tcp_sessions.id", ondelete="CASCADE"), index=True, nullable=False
    )
    direction: Mapped[str] = mapped_column(String(16), nullable=False)  # a2b / b2a
    local_endpoint: Mapped[str] = mapped_column(String(64), nullable=False)
    remote_endpoint: Mapped[str] = mapped_column(String(64), nullable=False)
    first_sequence: Mapped[int] = mapped_column(BigInteger, nullable=False)
    stream_length: Mapped[int] = mapped_column(BigInteger, nullable=False)
    present_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    artifact_path: Mapped[str] = mapped_column(String(512), nullable=False)
    holes: Mapped[list[Any]] = mapped_column(JSON, default=list, nullable=False)
    coverage_map: Mapped[list[Any]] = mapped_column(JSON, default=list, nullable=False)
    diagnostics: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    conflicts: Mapped[list[Any]] = mapped_column(JSON, default=list, nullable=False)
    protocol_label: Mapped[str] = mapped_column(String(48), default="unknown", nullable=False)
    protocol_confidence: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    protocol_signals: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    analyzer_version: Mapped[str] = mapped_column(String(32), default="", nullable=False)

    session: Mapped[TcpSession] = relationship(back_populates="streams")
    messages: Mapped[list["Message"]] = relationship(
        back_populates="stream", cascade="all, delete-orphan", passive_deletes=True
    )


class StreamRange(Base):
    __tablename__ = "stream_ranges"

    id: Mapped[str] = _pk()
    stream_id: Mapped[str] = mapped_column(
        ForeignKey("streams.id", ondelete="CASCADE"), index=True, nullable=False
    )
    start_offset: Mapped[int] = mapped_column(BigInteger, nullable=False)
    end_offset: Mapped[int] = mapped_column(BigInteger, nullable=False)
    packet_references: Mapped[list[Any]] = mapped_column(JSON, default=list, nullable=False)
    completeness: Mapped[str] = mapped_column(String(24), default="complete", nullable=False)
    conflict_status: Mapped[str] = mapped_column(String(24), default="none", nullable=False)

    __table_args__ = (
        Index("ix_stream_range_lookup", "stream_id", "start_offset", "end_offset"),
    )


class Message(Base):
    __tablename__ = "messages"

    id: Mapped[str] = _pk()
    stream_id: Mapped[str] = mapped_column(
        ForeignKey("streams.id", ondelete="CASCADE"), index=True, nullable=False
    )
    session_id: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    capture_id: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    index_in_stream: Mapped[int] = mapped_column(Integer, nullable=False)
    start_offset: Mapped[int] = mapped_column(BigInteger, nullable=False)
    end_offset: Mapped[int] = mapped_column(BigInteger, nullable=False)
    present_length: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    declared_length: Mapped[int | None] = mapped_column(Integer, nullable=True)
    timestamp: Mapped[float] = mapped_column(Float, nullable=False)
    framing_method: Mapped[str] = mapped_column(String(32), default="", nullable=False)
    framing_rule_version: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    complete: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    packet_references: Mapped[list[Any]] = mapped_column(JSON, default=list, nullable=False)
    diagnostics: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    features: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    body_preview: Mapped[str] = mapped_column(Text, default="", nullable=False)

    stream: Mapped[Stream] = relationship(back_populates="messages")

    __table_args__ = (
        UniqueConstraint("stream_id", "index_in_stream", name="uq_message_index_in_stream"),
        Index("ix_message_stream_offset", "stream_id", "start_offset"),
    )


class FramingRule(Base):
    """A versioned, stored framing configuration."""

    __tablename__ = "framing_rules"

    id: Mapped[str] = _pk()
    project_id: Mapped[str] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True, nullable=False
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    method: Mapped[str] = mapped_column(String(32), nullable=False)
    config: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = created_column()
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    notes: Mapped[str] = mapped_column(Text, default="", nullable=False)


class Hypothesis(Base):
    __tablename__ = "hypotheses"

    id: Mapped[str] = _pk()
    project_id: Mapped[str] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True, nullable=False
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    scope: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    proposed_structure: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    observations: Mapped[list[Any]] = mapped_column(JSON, default=list, nullable=False)
    evidence_refs: Mapped[list[Any]] = mapped_column(JSON, default=list, nullable=False)
    counterexample_refs: Mapped[list[Any]] = mapped_column(JSON, default=list, nullable=False)
    unknown_regions: Mapped[list[Any]] = mapped_column(JSON, default=list, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="draft", nullable=False)
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    author: Mapped[str] = mapped_column(String(120), default="analyst", nullable=False)
    origin: Mapped[str] = mapped_column(String(32), default="analyst", nullable=False)
    created_at: Mapped[datetime] = created_column()
    updated_at: Mapped[datetime] = updated_column()

    interpretations: Mapped[list["Interpretation"]] = relationship(
        back_populates="hypothesis", cascade="all, delete-orphan", passive_deletes=True
    )


class Interpretation(Base):
    __tablename__ = "interpretations"

    id: Mapped[str] = _pk()
    project_id: Mapped[str] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True, nullable=False
    )
    hypothesis_id: Mapped[str | None] = mapped_column(
        ForeignKey("hypotheses.id", ondelete="CASCADE"), index=True, nullable=True
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    schema_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    checksum: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = created_column()
    is_current: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    notes: Mapped[str] = mapped_column(Text, default="", nullable=False)

    hypothesis: Mapped[Hypothesis | None] = relationship(back_populates="interpretations")
    runs: Mapped[list["ValidationRun"]] = relationship(
        back_populates="interpretation", cascade="all, delete-orphan", passive_deletes=True
    )


class ValidationRun(Base):
    __tablename__ = "validation_runs"

    id: Mapped[str] = _pk()
    interpretation_id: Mapped[str] = mapped_column(
        ForeignKey("interpretations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    project_id: Mapped[str] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True, nullable=False
    )
    corpus: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    settings: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    started_at: Mapped[datetime] = created_column()
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    status: Mapped[str] = mapped_column(String(24), default="running", nullable=False)
    summary: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    stale: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    analyzer_version: Mapped[str] = mapped_column(String(32), default="", nullable=False)

    interpretation: Mapped[Interpretation] = relationship(back_populates="runs")
    results: Mapped[list["ValidationResult"]] = relationship(
        back_populates="run", cascade="all, delete-orphan", passive_deletes=True
    )


class ValidationResult(Base):
    __tablename__ = "validation_results"

    id: Mapped[str] = _pk()
    validation_run_id: Mapped[str] = mapped_column(
        ForeignKey("validation_runs.id", ondelete="CASCADE"), index=True, nullable=False
    )
    message_id: Mapped[str | None] = mapped_column(String(32), index=True, nullable=True)
    stream_id: Mapped[str | None] = mapped_column(String(32), index=True, nullable=True)
    outcome: Mapped[str] = mapped_column(String(32), default="matched", nullable=False)
    extracted_fields: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    diagnostics: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    evidence_refs: Mapped[list[Any]] = mapped_column(JSON, default=list, nullable=False)
    violated_rule: Mapped[str | None] = mapped_column(String(120), nullable=True)
    capture_id: Mapped[str | None] = mapped_column(String(32), index=True, nullable=True)

    run: Mapped[ValidationRun] = relationship(back_populates="results")


class ExperimentEvent(Base):
    __tablename__ = "experiment_events"

    id: Mapped[str] = _pk()
    project_id: Mapped[str] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True, nullable=False
    )
    timestamp: Mapped[float] = mapped_column(Float, nullable=False)
    raw_timestamp: Mapped[str | None] = mapped_column(String(64), nullable=True)
    action: Mapped[str] = mapped_column(String(120), nullable=False)
    parameters: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    observed_result: Mapped[str | None] = mapped_column(String(256), nullable=True)
    expected_result: Mapped[str | None] = mapped_column(String(256), nullable=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    link_rule: Mapped[str] = mapped_column(String(64), default="none", nullable=False)
    linked_message_ids: Mapped[list[Any]] = mapped_column(JSON, default=list, nullable=False)
    note: Mapped[str] = mapped_column(Text, default="", nullable=False)

    links: Mapped[list["ExperimentMessageLink"]] = relationship(
        back_populates="event", cascade="all, delete-orphan", passive_deletes=True
    )


class ExperimentMessageLink(Base):
    __tablename__ = "experiment_message_links"

    id: Mapped[str] = _pk()
    event_id: Mapped[str] = mapped_column(
        ForeignKey("experiment_events.id", ondelete="CASCADE"), index=True, nullable=False
    )
    message_id: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    link_type: Mapped[str] = mapped_column(String(24), default="inferred", nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=0.5, nullable=False)
    rationale: Mapped[str] = mapped_column(Text, default="", nullable=False)

    event: Mapped[ExperimentEvent] = relationship(back_populates="links")


class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[str] = _pk()
    project_id: Mapped[str] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True, nullable=False
    )
    source_id: Mapped[str | None] = mapped_column(String(32), index=True, nullable=True)
    entity_type: Mapped[str] = mapped_column(String(48), nullable=False)
    entity_id: Mapped[str | None] = mapped_column(String(32), index=True, nullable=True)
    stream_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    byte_ranges: Mapped[list[Any]] = mapped_column(JSON, default=list, nullable=False)
    packet_indexes: Mapped[list[Any]] = mapped_column(JSON, default=list, nullable=False)
    rule_ref: Mapped[str | None] = mapped_column(String(120), nullable=True)
    interpretation_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    confidence: Mapped[float] = mapped_column(Float, default=1.0, nullable=False)
    contradicts: Mapped[list[Any]] = mapped_column(JSON, default=list, nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    created_at: Mapped[datetime] = created_column()


class Annotation(Base):
    __tablename__ = "annotations"

    id: Mapped[str] = _pk()
    project_id: Mapped[str] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True, nullable=False
    )
    target_type: Mapped[str] = mapped_column(String(32), nullable=False)
    target_id: Mapped[str | None] = mapped_column(String(32), index=True, nullable=True)
    text: Mapped[str] = mapped_column(Text, default="", nullable=False)
    tags: Mapped[list[Any]] = mapped_column(JSON, default=list, nullable=False)
    author: Mapped[str] = mapped_column(String(120), default="analyst", nullable=False)
    created_at: Mapped[datetime] = created_column()
    updated_at: Mapped[datetime] = updated_column()


class KeyLog(Base):
    """TLS key log reference.  The bytes live in ``data/secrets`` with 0600."""

    __tablename__ = "key_logs"

    id: Mapped[str] = _pk()
    project_id: Mapped[str] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True, nullable=False
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    storage_path: Mapped[str] = mapped_column(String(512), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    size_bytes: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    line_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    labels: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = created_column()


class AnomalyModel(Base):
    __tablename__ = "anomaly_models"

    id: Mapped[str] = _pk()
    project_id: Mapped[str] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True, nullable=False
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    algorithm: Mapped[str] = mapped_column(String(48), default="isolation_forest", nullable=False)
    params: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    feature_names: Mapped[list[Any]] = mapped_column(JSON, default=list, nullable=False)
    training_summary: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    seed: Mapped[int] = mapped_column(Integer, default=42, nullable=False)
    blob: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    created_at: Mapped[datetime] = created_column()


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[str] = _pk()
    project_id: Mapped[str] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True, nullable=False
    )
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    generator: Mapped[str] = mapped_column(String(64), default="template", nullable=False)
    sections: Mapped[list[Any]] = mapped_column(JSON, default=list, nullable=False)
    markdown: Mapped[str] = mapped_column(Text, default="", nullable=False)
    facts: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    ai_used: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    ai_model: Mapped[str | None] = mapped_column(String(120), nullable=True)
    ai_warnings: Mapped[list[Any]] = mapped_column(JSON, default=list, nullable=False)
    created_at: Mapped[datetime] = created_column()


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[str] = _pk()
    created_at: Mapped[datetime] = created_column()
    action: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    outcome: Mapped[str] = mapped_column(String(24), default="success", nullable=False)
    risk: Mapped[str] = mapped_column(String(16), default="info", nullable=False)
    project_id: Mapped[str | None] = mapped_column(String(32), index=True, nullable=True)
    object_type: Mapped[str | None] = mapped_column(String(48), nullable=True)
    object_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    actor: Mapped[str] = mapped_column(String(120), default="local-user", nullable=False)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    prev_hash: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    entry_hash: Mapped[str] = mapped_column(String(64), default="", nullable=False)


class Job(Base):
    __tablename__ = "jobs"

    id: Mapped[str] = _pk()
    project_id: Mapped[str | None] = mapped_column(String(32), index=True, nullable=True)
    kind: Mapped[str] = mapped_column(String(48), nullable=False)
    status: Mapped[str] = mapped_column(String(24), default="queued", nullable=False)
    progress: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    stage: Mapped[str] = mapped_column(String(120), default="", nullable=False)
    params: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    result: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = created_column()
    updated_at: Mapped[datetime] = updated_column()
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (Index("ix_job_status_created", "status", "created_at"),)