"""Request/response schemas.

Every request body is validated here, which is the first of two boundaries
(the second is object-level ownership inside the service layer).  String fields
carry explicit length limits so an oversized field cannot reach the database.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

MAX_NAME = 200
MAX_TEXT = 20_000


class APIModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


# --------------------------------------------------------------------------- #
# Projects
# --------------------------------------------------------------------------- #


class ProjectCreate(APIModel):
    name: str = Field(min_length=1, max_length=MAX_NAME)
    description: str = Field(default="", max_length=MAX_TEXT)
    settings: dict[str, Any] = Field(default_factory=dict)


class ProjectUpdate(APIModel):
    """Partial update. Omitted fields are left untouched."""

    name: str | None = Field(default=None, min_length=1, max_length=MAX_NAME)
    description: str | None = Field(default=None, max_length=MAX_TEXT)
    settings: dict[str, Any] | None = None


class ProjectOut(APIModel):
    id: str
    name: str
    description: str
    schema_version: int
    created_at: datetime
    updated_at: datetime
    settings: dict[str, Any]


class ProjectSummaryOut(APIModel):
    id: str
    name: str
    created_at: datetime
    updated_at: datetime
    capture_count: int
    hypothesis_count: int
    interpretation_count: int
    message_count: int


class ProjectMetrics(APIModel):
    project_id: str
    captures: int
    packets: int
    tcp_sessions: int
    streams: int
    messages: int
    hypotheses: int
    interpretations: int
    validation_runs: int
    counterexamples: int
    sessions_with_reconstruction_problems: int
    bytes_stored: int
    analyst_versions: dict[str, str]


# --------------------------------------------------------------------------- #
# Captures
# --------------------------------------------------------------------------- #


class CaptureOut(APIModel):
    id: str
    project_id: str
    name: str
    sha256: str
    file_size: int
    format: str
    imported_at: datetime
    analysis_status: str
    diagnostics: dict[str, Any]
    stats: dict[str, Any]
    source_kind: str
    relative_path: str


class AnalyzeRequest(APIModel):
    flow_policy: Literal["syn_only", "syn_fin_rst", "syn_fin_rst_idle"] = "syn_fin_rst_idle"
    idle_timeout: float = Field(default=120.0, ge=0.0, le=86_400.0)
    conflict_policy: Literal["first_writer_wins", "last_writer_wins"] = "first_writer_wins"
    framing: dict[str, Any] | None = None
    detect_protocol: bool = True

    @field_validator("framing")
    @classmethod
    def _size_framing(cls, value: Any) -> Any:
        if value is not None and len(value) > 64:
            raise ValueError("framing configuration has too many keys")
        return value


class PacketOut(APIModel):
    packet_index: int
    timestamp: float
    captured_length: int
    original_length: int
    source_address: str
    destination_address: str
    source_port: int
    destination_port: int
    transport_protocol: str
    tcp_sequence: int | None
    tcp_acknowledgment: int | None
    tcp_flags: int | None
    tcp_window: int | None
    tcp_options: str | None
    payload_length: int
    truncated: bool
    session_id: str | None


class Page(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[Any]
    total: int
    offset: int
    limit: int
    has_more: bool


# --------------------------------------------------------------------------- #
# Sessions / streams / messages
# --------------------------------------------------------------------------- #


class SessionOut(APIModel):
    id: str
    capture_id: str
    session_identity: str
    endpoint_a: str
    endpoint_b: str
    client_endpoint: str | None
    server_endpoint: str | None
    role_confidence: str
    start_time: float
    end_time: float
    completeness_status: str
    diagnostics: dict[str, Any]
    analyzer_version: str


class StreamOut(APIModel):
    id: str
    session_id: str
    direction: str
    local_endpoint: str
    remote_endpoint: str
    stream_length: int
    present_bytes: int
    holes: list[dict[str, Any]]
    coverage_map: list[dict[str, int]]
    diagnostics: dict[str, Any]
    conflicts: list[dict[str, Any]]
    protocol_label: str
    protocol_confidence: float
    analyzer_version: str


class MessageOut(APIModel):
    id: str
    stream_id: str
    index_in_stream: int
    start_offset: int
    end_offset: int
    present_length: int
    declared_length: int | None
    timestamp: float
    framing_method: str
    framing_rule_version: str
    confidence: float
    complete: bool
    packet_references: list[dict[str, Any]]
    diagnostics: dict[str, Any]
    features: dict[str, Any]


# --------------------------------------------------------------------------- #
# Framing
# --------------------------------------------------------------------------- #


class FramingRequest(APIModel):
    framing: dict[str, Any]
    regenerate: bool = True


class CompareRequest(APIModel):
    message_ids: list[str] = Field(min_length=2, max_length=32)
    align: Literal["positional"] = "positional"


class HexRequest(APIModel):
    offset: int = Field(ge=0, default=0)
    length: int = Field(default=512, ge=1, le=65536)


# --------------------------------------------------------------------------- #
# Hypotheses / interpretations
# --------------------------------------------------------------------------- #


class HypothesisCreate(APIModel):
    name: str = Field(min_length=1, max_length=MAX_NAME)
    description: str = Field(default="", max_length=MAX_TEXT)
    scope: dict[str, Any] = Field(default_factory=dict)
    proposed_structure: dict[str, Any] = Field(default_factory=dict)
    observations: list[Any] = Field(default_factory=list, max_length=200)
    evidence_refs: list[Any] = Field(default_factory=list, max_length=200)
    status: Literal[
        "draft", "proposed", "testing", "supported", "contradicted", "revised", "rejected"
    ] = "draft"
    author: str = Field(default="analyst", max_length=120)
    origin: Literal["analyst", "inference", "assistant", "imported"] = "analyst"


class HypothesisUpdate(APIModel):
    name: str | None = Field(default=None, max_length=MAX_NAME)
    description: str | None = Field(default=None, max_length=MAX_TEXT)
    scope: dict[str, Any] | None = None
    proposed_structure: dict[str, Any] | None = None
    observations: list[Any] | None = None
    evidence_refs: list[Any] | None = None
    counterexample_refs: list[Any] | None = None
    unknown_regions: list[Any] | None = None
    status: Literal[
        "draft", "proposed", "testing", "supported", "contradicted", "revised", "rejected"
    ] | None = None


class HypothesisOut(APIModel):
    id: str
    project_id: str
    name: str
    description: str
    scope: dict[str, Any]
    proposed_structure: dict[str, Any]
    observations: list[Any]
    evidence_refs: list[Any]
    counterexample_refs: list[Any]
    unknown_regions: list[Any]
    status: str
    version: int
    author: str
    origin: str
    created_at: datetime
    updated_at: datetime


class InterpretationCreate(APIModel):
    name: str | None = Field(default=None, max_length=MAX_NAME)
    # Named ``specification`` rather than ``schema_json``: ``schema_json`` is a
    # deprecated Pydantic BaseModel attribute and would shadow it.
    specification: dict[str, Any]
    hypothesis_id: str | None = None
    notes: str = Field(default="", max_length=MAX_TEXT)


class InterpretationUpdate(APIModel):
    specification: dict[str, Any] | None = None
    notes: str | None = Field(default=None, max_length=MAX_TEXT)


class InterpretationOut(APIModel):
    id: str
    project_id: str
    hypothesis_id: str | None
    name: str
    specification: dict[str, Any]
    version: int
    checksum: str
    created_at: datetime
    notes: str


class ValidationRequest(APIModel):
    capture_ids: list[str] = Field(min_length=1, max_length=64)
    session_ids: list[str] = Field(default_factory=list, max_length=64)
    directions: list[Literal["a2b", "b2a"]] = Field(default_factory=lambda: ["a2b", "b2a"])
    limit_per_stream: int = Field(default=50_000, ge=1, le=500_000)


class ValidationRunOut(APIModel):
    id: str
    interpretation_id: str
    project_id: str
    corpus: dict[str, Any]
    settings: dict[str, Any]
    started_at: datetime
    completed_at: datetime | None
    status: str
    summary: dict[str, Any]
    stale: bool
    analyzer_version: str


# --------------------------------------------------------------------------- #
# Experiments
# --------------------------------------------------------------------------- #


class ExperimentImport(APIModel):
    events: list[dict[str, Any]] = Field(min_length=1, max_length=20_000)

    @field_validator("events")
    @classmethod
    def _limit(cls, value: list[dict[str, Any]]) -> list[dict[str, Any]]:
        for event in value:
            for key, item in event.items():
                if isinstance(item, str) and len(item) > 4096:
                    raise ValueError(f"experiment field {key!r} exceeds 4096 characters")
        return value


class ExperimentEventOut(APIModel):
    id: str
    project_id: str
    timestamp: float
    raw_timestamp: str | None
    action: str
    parameters: dict[str, Any]
    observed_result: str | None
    expected_result: str | None
    metadata_json: dict[str, Any]
    linked_message_ids: list[Any]
    note: str


# --------------------------------------------------------------------------- #
# Diff / graph / anomalies / assistant / reports
# --------------------------------------------------------------------------- #


class DiffRequest(APIModel):
    base_capture_id: str
    compare_capture_id: str
    focus: Literal["endpoints", "sessions", "messages", "bytes", "diagnostics", "all"] = "all"
    max_bytes: int = Field(default=4096, ge=64, le=1_048_576)


class GraphRequest(APIModel):
    capture_ids: list[str] = Field(min_length=1, max_length=64)
    min_bytes: int = Field(default=0, ge=0)
    protocol: str | None = Field(default=None, max_length=48)
    include_centrality: bool = True


class AnomalyTrainRequest(APIModel):
    name: str = Field(min_length=1, max_length=MAX_NAME)
    capture_ids: list[str] = Field(min_length=1, max_length=64)
    scope: Literal["messages", "sessions"] = "messages"
    contamination: float = Field(default=0.05, ge=0.001, le=0.5)
    n_estimators: int = Field(default=100, ge=10, le=1000)
    max_samples: int = Field(default=50_000, ge=100, le=500_000)
    seed: int = Field(default=42, ge=0, le=2**31 - 1)
    algorithm: Literal["auto", "isolation_forest", "robust_profile"] = "auto"


class AnomalyScoreRequest(APIModel):
    model_id: str
    capture_ids: list[str] = Field(min_length=1, max_length=64)
    scope: Literal["messages", "sessions"] = "messages"
    limit: int = Field(default=200, ge=1, le=2000)


class AssistantQuery(APIModel):
    query: str = Field(min_length=1, max_length=1000)
    capture_ids: list[str] = Field(default_factory=list, max_length=64)
    dry_run: bool = True
    use_llm: bool = False


class ReportRequest(APIModel):
    title: str = Field(default="Investigation report", max_length=MAX_NAME)
    capture_ids: list[str] = Field(default_factory=list, max_length=64)
    interpretation_ids: list[str] = Field(default_factory=list, max_length=32)
    use_llm: bool = False


class ExportProjectRequest(APIModel):
    include_captures: bool = True
    include_reports: bool = True


class KeyLogOut(APIModel):
    """A key log reference.

    Deliberately without the file's contents: a secret has no place in a
    report or in a listing, so only what the log *carries* is reported.
    """

    id: str
    project_id: str
    name: str
    sha256: str
    size_bytes: int
    line_count: int
    labels: dict[str, int]
    created_at: datetime


class DecryptRequest(APIModel):
    keylog_id: str


class PcapngExportRequest(APIModel):
    comment_prefix: str = Field(default="mplab", max_length=64)
    include_hypotheses: bool = True