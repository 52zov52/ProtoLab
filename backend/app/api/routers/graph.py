"""Network graph endpoints."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter
from sqlalchemy import select

from ...analyzers.network_graph import build_graph, rank_nodes
from ...models import Capture, Stream, TcpSession
from ...schemas import GraphRequest
from ..context import SessionDep, load_capture

router = APIRouter(prefix="/network")


@router.post("/graph")
def network_graph(payload: GraphRequest, session: SessionDep) -> dict[str, Any]:
    captures = []
    for capture_id in payload.capture_ids:
        captures.append(load_capture(session, capture_id))
    capture_ids = [c.id for c in captures]

    query = select(TcpSession).where(TcpSession.capture_id.in_(capture_ids))
    sessions = list(session.execute(query).scalars().all())
    for row in sessions:
        row.streams = list(
            session.execute(select(Stream).where(Stream.session_id == row.id)).scalars().all()
        )

    graph = build_graph(
        sessions,
        min_bytes=payload.min_bytes,
        protocol_filter=payload.protocol,
        compute_betweenness=payload.include_centrality,
    )
    return {
        "captures": [{"id": c.id, "name": c.name} for c in captures],
        **graph.to_dict(),
        "centrality": rank_nodes(graph) if payload.include_centrality else [],
    }


@router.get("/captures/{capture_id}/graph")
def capture_graph(
    capture_id: str, session: SessionDep, min_bytes: int = 0, include_centrality: bool = True
) -> dict[str, Any]:
    capture = load_capture(session, capture_id)
    rows = list(
        session.execute(
            select(TcpSession).where(TcpSession.capture_id == capture.id)
        ).scalars().all()
    )
    for row in rows:
        row.streams = list(
            session.execute(select(Stream).where(Stream.session_id == row.id)).scalars().all()
        )
    graph = build_graph(rows, min_bytes=min_bytes, compute_betweenness=include_centrality)
    return {
        "captures": [{"id": capture.id, "name": capture.name}],
        **graph.to_dict(),
        "centrality": rank_nodes(graph) if include_centrality else [],
    }


_ = Capture