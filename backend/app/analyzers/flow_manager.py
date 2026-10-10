"""TCP conversation splitting.

A 5-tuple is *not* a session.  A long-lived device connection, a NAT rebinding
and a port reuse all produce the same (ip, port, ip, port, proto) triple at
different times.  This module therefore groups packets with an explicit,
documented session-splitting policy:

``syn``
    A SYN (without ACK) starts a new session for the same 5-tuple.
``fin_rst``
    A FIN or RST closes the current session; the next packet starts a new one.
``idle_timeout``
    A gap larger than ``idle_timeout`` seconds starts a new session.

The active policy is stored on every :class:`TcpSession` row so a result can
always be explained after the fact.  When several conditions could apply, the
*first* one recorded is the one that was used.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Iterable, Iterator

from .capture_reader import FLAG_ACK, FLAG_FIN, FLAG_RST, FLAG_SYN, describe_flags
from .tcp_reassembly import Segment, find_duplicate_ack_runs

FLOW_VERSION = "flow-manager/1.1"

DEFAULT_IDLE_TIMEOUT = 120.0


@dataclass(slots=True)
class FlowKey:
    a_ip: str
    a_port: int
    b_ip: str
    b_port: int

    @property
    def canonical(self) -> tuple[str, int, str, int]:
        return (self.a_ip, self.a_port, self.b_ip, self.b_port)

    def endpoint_a(self) -> str:
        return f"{self.a_ip}:{self.a_port}"

    def endpoint_b(self) -> str:
        return f"{self.b_ip}:{self.b_port}"


@dataclass
class FlowPacket:
    """A decoded TCP packet, already stripped of link framing."""

    packet_index: int
    timestamp: float
    source_ip: str
    source_port: int
    dest_ip: str
    dest_port: int
    seq: int
    ack: int
    flags: int
    window: int
    payload: bytes
    options: str | None
    frame_truncated: bool
    anomalies: list[str] = field(default_factory=list)

    @property
    def payload_length(self) -> int:
        return len(self.payload)


@dataclass
class TcpFlow:
    key: FlowKey
    ordinal: int
    packets: list[FlowPacket] = field(default_factory=list)
    session_identity: str = ""
    start_time: float = 0.0
    end_time: float = 0.0
    split_reason: str = "first_observation"
    client_endpoint: str | None = None
    server_endpoint: str | None = None
    role_confidence: str = "unknown"
    role_rationale: str = ""
    saw_syn: bool = False
    saw_syn_ack: bool = False
    saw_fin: bool = False
    saw_rst: bool = False
    #: How many distinct directions have sent a FIN.  A connection is only
    #: finished once both have (a half-close still carries data).
    fin_directions: int = 0
    fin_seen: set[str] = field(default_factory=set)
    truncated_start: bool = False
    truncated_end: bool = False
    closure_state: str = "open"
    a_to_b_isn: int | None = None
    b_to_a_isn: int | None = None
    diagnostics: list[dict[str, object]] = field(default_factory=list)

    @property
    def endpoint_a(self) -> str:
        return self.key.endpoint_a()

    @property
    def endpoint_b(self) -> str:
        return self.key.endpoint_b()

    def role_packet_count(self, role: str) -> int:
        if role == "a2b":
            return sum(
                1
                for p in self.packets
                if (p.source_ip, p.source_port) == self.key.canonical[:2]
            )
        return sum(
            1
            for p in self.packets
            if (p.source_ip, p.source_port) == self.key.canonical[2:]
        )

    def role_bytes(self, role: str) -> int:
        total = 0
        for p in self.packets:
            if role == "a2b":
                if (p.source_ip, p.source_port) == self.key.canonical[:2]:
                    total += p.payload_length
            else:
                if (p.source_ip, p.source_port) == self.key.canonical[2:]:
                    total += p.payload_length
        return total

    def completeness(self) -> str:
        if self.saw_rst:
            return "reset"
        if self.saw_syn and self.saw_fin and not self.truncated_start and not self.truncated_end:
            return "complete"
        if self.saw_syn and not self.saw_fin and not self.truncated_start:
            return "open_at_capture_end"
        if not self.saw_syn and self.saw_fin:
            return "truncated_start"
        if self.saw_syn and self.truncated_end:
            return "truncated_end"
        return "partial"

    def segments(self, role: str) -> list[Segment]:
        canonical = self.key.canonical
        out: list[Segment] = []
        for p in self.packets:
            if role == "a2b":
                match = (p.source_ip, p.source_port) == canonical[:2]
            else:
                match = (p.source_ip, p.source_port) == canonical[2:]
            if match and p.payload:
                out.append(
                    Segment(
                        packet_index=p.packet_index,
                        timestamp=p.timestamp,
                        sequence=p.seq,
                        payload=p.payload,
                        flags=p.flags,
                        window=p.window,
                        options=p.options,
                    )
                )
        return out


class FlowSplitter:
    """Groups decoded TCP packets into sessions."""

    def __init__(
        self,
        *,
        policy: str = "syn_fin_rst_idle",
        idle_timeout: float = DEFAULT_IDLE_TIMEOUT,
        max_sessions: int = 20_000,
    ) -> None:
        if policy not in ("syn_only", "syn_fin_rst", "syn_fin_rst_idle"):
            raise ValueError(f"unknown flow-splitting policy {policy!r}")
        self.policy = policy
        self.idle_timeout = idle_timeout
        self.max_sessions = max_sessions
        self._flows: dict[tuple[str, int, str, int], list[TcpFlow]] = defaultdict(list)
        self._active: dict[tuple[str, int, str, int], TcpFlow] = {}
        self._ordinal = 0

    def _canonical(self, pkt: FlowPacket) -> tuple[str, int, str, int]:
        forward = (pkt.source_ip, pkt.source_port, pkt.dest_ip, pkt.dest_port)
        backward = (pkt.dest_ip, pkt.dest_port, pkt.source_ip, pkt.source_port)
        return min(forward, backward)

    def _split_reason(self, pkt: FlowPacket, current: TcpFlow | None) -> str | None:
        if current is None:
            return None
        if self.policy == "syn_only":
            return None
        if pkt.flags & FLAG_SYN and not (pkt.flags & FLAG_ACK):
            return "new_syn"
        if self.policy in ("syn_fin_rst", "syn_fin_rst_idle"):
            if pkt.flags & FLAG_RST:
                # A reset tears the connection down immediately.
                return "reset"
            if pkt.flags & FLAG_FIN:
                # A single FIN only half-closes: the peer may still be sending.
                # The connection is finished once *both* sides have sent one.
                return "fin" if current.fin_directions >= 2 else None
        if self.policy == "syn_fin_rst_idle" and (
            pkt.timestamp - current.end_time
        ) > self.idle_timeout:
            return "idle_timeout"
        return None

    def add(self, pkt: FlowPacket) -> TcpFlow:
        key = self._canonical(pkt)
        current = self._active.get(key)
        reason = self._split_reason(pkt, current)
        if reason is not None:
            if current is not None:
                current.diagnostics.append(
                    {
                        "code": "session_split",
                        "reason": reason,
                        "packet_index": pkt.packet_index,
                        "detail": _split_detail(reason, pkt, self.idle_timeout),
                    }
                )
                self._close(current, pkt, reason)
            current = self._open(key, reason)
        if current is None:
            current = self._open(key, "first_observation")
        self._active[key] = current
        current.packets.append(pkt)
        if not current.packets[:-1]:
            current.start_time = pkt.timestamp
        current.end_time = pkt.timestamp
        self._track_state(current, pkt)
        return current

    def _open(self, key: tuple[str, int, str, int], reason: str) -> TcpFlow:
        self._ordinal += 1
        if self._ordinal > self.max_sessions:
            from ..core.errors import LimitExceeded

            raise LimitExceeded(
                "Capture contains more TCP sessions than the configured maximum.",
                details={"limit": self.max_sessions},
            )
        flow = TcpFlow(
            key=FlowKey(*key),
            ordinal=self._ordinal,
            split_reason=reason,
            session_identity=f"flow-{self._ordinal:05d}",
        )
        self._flows[key].append(flow)
        return flow

    def _close(self, flow: TcpFlow, pkt: FlowPacket, reason: str) -> None:
        if reason == "fin":
            flow.saw_fin = True
            flow.closure_state = "closing"
        elif reason == "reset":
            flow.saw_rst = True
            flow.closure_state = "reset"
        elif reason == "idle_timeout":
            flow.truncated_end = True
            flow.closure_state = "idle_timeout"
        elif reason == "new_syn":
            # The previous incarnation ended somewhere we did not observe.
            flow.truncated_end = True
            flow.closure_state = "superseded_by_new_syn"

    def _track_state(self, flow: TcpFlow, pkt: FlowPacket) -> None:
        canonical = flow.key.canonical
        # ``from_a`` means the packet travels endpoint_a -> endpoint_b, so the
        # sender's own ISN belongs to the ``a_to_b_*`` fields.  This holds for a
        # bare SYN and for a SYN-ACK alike: a SYN-ACK is simply sent by whichever
        # side answers, and its sequence number is that sender's own ISN.
        from_a = (pkt.source_ip, pkt.source_port) == canonical[:2]
        if pkt.flags & FLAG_SYN:
            if from_a:
                flow.a_to_b_isn = pkt.seq
            else:
                flow.b_to_a_isn = pkt.seq
            if pkt.flags & FLAG_ACK:
                flow.saw_syn_ack = True
            else:
                flow.saw_syn = True
                flow.truncated_start = False
        if pkt.flags & FLAG_FIN:
            flow.saw_fin = True
            direction = "a2b" if from_a else "b2a"
            if direction not in flow.fin_seen:
                flow.fin_seen.add(direction)
                flow.fin_directions = len(flow.fin_seen)
        if pkt.flags & FLAG_RST:
            flow.saw_rst = True
            flow.closure_state = "reset"

    def flows(self) -> Iterator[TcpFlow]:
        for key in sorted(self._flows):
            for flow in self._flows[key]:
                yield flow

    def assign_roles(self) -> None:
        """Decide which endpoint is the client.

        Roles are only asserted when there is evidence: a SYN without ACK tells
        us the initiator.  Without a handshake we prefer the side that sent the
        first payload, and we say so explicitly via ``role_confidence``.
        """
        for flow in self.flows():
            # A bare SYN (no ACK) identifies the initiator directly, whether or
            # not the handshake later completed with a SYN-ACK.
            initiator = self._initiator(flow)
            if initiator is not None:
                flow.client_endpoint = initiator
                flow.server_endpoint = self._other(flow, initiator)
                flow.role_confidence = "syn_observed"
                flow.role_rationale = (
                    "A SYN without ACK was observed; the sender opened the connection."
                )
                continue
            canonical = flow.key.canonical
            first_payload = next((p for p in flow.packets if p.payload), None)
            if first_payload is not None:
                sender = f"{first_payload.source_ip}:{first_payload.source_port}"
                flow.client_endpoint = sender
                flow.server_endpoint = self._other(flow, sender)
                flow.role_confidence = "heuristic_first_payload"
                flow.role_rationale = (
                    "No handshake observed; assumed the endpoint that sent the first "
                    "payload is the client. Treat this as a working assumption."
                )
            else:
                flow.client_endpoint = flow.endpoint_a
                flow.server_endpoint = flow.endpoint_b
                flow.role_confidence = "unknown"
                flow.role_rationale = (
                    "No handshake and no payload observed; endpoint roles cannot be "
                    "determined from this capture."
                )

    def _initiator(self, flow: TcpFlow) -> str | None:
        canonical = flow.key.canonical
        for p in flow.packets:
            if p.flags & FLAG_SYN and not (p.flags & FLAG_ACK):
                if (p.source_ip, p.source_port) == canonical[:2]:
                    return flow.endpoint_a
                return flow.endpoint_b
        return None

    @staticmethod
    def _other(flow: TcpFlow, endpoint: str) -> str:
        return flow.endpoint_b if endpoint == flow.endpoint_a else flow.endpoint_a


def _split_detail(reason: str, pkt: FlowPacket, idle_timeout: float) -> str:
    if reason == "new_syn":
        return (
            f"Packet {pkt.packet_index} carries a SYN for a 5-tuple that already had "
            "traffic: treated as a new connection instance."
        )
    if reason == "fin":
        return (
            f"Packet {pkt.packet_index} carries a FIN after earlier data: the previous "
            "connection instance is considered closed."
        )
    if reason == "reset":
        return f"Packet {pkt.packet_index} carries a RST: connection aborted."
    if reason == "idle_timeout":
        return (
            f"More than {idle_timeout:g}s elapsed before packet {pkt.packet_index}; "
            "treated as a new connection instance."
        )
    return f"Session started at packet {pkt.packet_index}."


def summarise_flow(flow: TcpFlow) -> dict[str, object]:
    return {
        "session_identity": flow.session_identity,
        "endpoint_a": flow.endpoint_a,
        "endpoint_b": flow.endpoint_b,
        "client_endpoint": flow.client_endpoint,
        "server_endpoint": flow.server_endpoint,
        "role_confidence": flow.role_confidence,
        "role_rationale": flow.role_rationale,
        "packet_count": len(flow.packets),
        "bytes_a_to_b": flow.role_bytes("a2b"),
        "bytes_b_to_a": flow.role_bytes("b2a"),
        "start_time": flow.start_time,
        "end_time": flow.end_time,
        "duration_seconds": max(0.0, flow.end_time - flow.start_time),
        "completeness": flow.completeness(),
        "split_reason": flow.split_reason,
        "saw_syn": flow.saw_syn,
        "saw_syn_ack": flow.saw_syn_ack,
        "saw_fin": flow.saw_fin,
        "saw_rst": flow.saw_rst,
        "duplicate_ack_runs": find_duplicate_ack_runs(flow.packets),
        "diagnostics": flow.diagnostics,
    }


def iter_flow_packets(flow: TcpFlow) -> Iterable[FlowPacket]:  # pragma: no cover
    return flow.packets


__all__ = [
    "DEFAULT_IDLE_TIMEOUT",
    "FLOW_VERSION",
    "FlowKey",
    "FlowPacket",
    "FlowSplitter",
    "TcpFlow",
    "describe_flags",
    "summarise_flow",
]