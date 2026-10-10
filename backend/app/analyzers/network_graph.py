"""Network interaction graph and centrality metrics."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Iterable

GRAPH_VERSION = "network-graph/1.1"
MAX_NODES = 2000


@dataclass
class Node:
    id: str
    kind: str  # "ip" | "endpoint"
    label: str
    bytes_in: int = 0
    bytes_out: int = 0
    connections: int = 0
    peers: set[str] = field(default_factory=set)
    degree: int = 0
    degree_centrality: float = 0.0
    betweenness: float | None = None
    protocols: set[str] = field(default_factory=set)
    sessions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "label": self.label,
            "bytes_in": self.bytes_in,
            "bytes_out": self.bytes_out,
            "bytes_total": self.bytes_in + self.bytes_out,
            "connections": self.connections,
            "unique_peers": len(self.peers),
            "degree": self.degree,
            "degree_centrality": round(self.degree_centrality, 6),
            "betweenness": (
                round(self.betweenness, 6) if self.betweenness is not None else None
            ),
            "protocols": sorted(self.protocols),
            "session_ids": self.sessions[:64],
        }


@dataclass
class Edge:
    source: str
    target: str
    bytes_a_to_b: int
    bytes_b_to_a: int
    packets: int
    sessions: list[str] = field(default_factory=list)
    protocols: set[str] = field(default_factory=set)
    confirmed: bool = True

    @property
    def total_bytes(self) -> int:
        return self.bytes_a_to_b + self.bytes_b_to_a

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "bytes_a_to_b": self.bytes_a_to_b,
            "bytes_b_to_a": self.bytes_b_to_a,
            "bytes_total": self.total_bytes,
            "packets": self.packets,
            "session_ids": self.sessions[:64],
            "protocols": sorted(self.protocols),
            "link_status": "confirmed" if self.confirmed else "assumed",
        }


@dataclass
class Graph:
    nodes: dict[str, Node]
    edges: list[Edge]
    analyzer_version: str = GRAPH_VERSION
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "analyzer_version": self.analyzer_version,
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
            "nodes": [n.to_dict() for n in sorted(self.nodes.values(), key=lambda n: -n.bytes_in - n.bytes_out)],
            "edges": [e.to_dict() for e in self.edges],
            "warnings": self.warnings,
            "interpretation_note": (
                "Degree and betweenness centrality describe how connected a node is "
                "within this capture. A high-centrality node is a candidate for "
                "further investigation, not a C2 server, and centrality alone says "
                "nothing about intent."
            ),
        }


def build_graph(
    sessions: Iterable[Any],
    *,
    node_kind: str = "ip",
    min_bytes: int = 0,
    protocol_filter: str | None = None,
    compute_betweenness: bool = True,
    max_betweenness_nodes: int = 300,
) -> Graph:
    """Build an interaction graph from analysed sessions.

    ``sessions`` are ORM :class:`TcpSession` rows (optionally with their
    streams).  Edge width reflects real observed bytes; there is no synthetic
    traffic.
    """
    nodes: dict[str, Node] = {}
    edges: dict[tuple[str, str], Edge] = {}
    warnings: list[str] = []

    for session in sessions:
        summary = (session.diagnostics or {}).get("summary", {})
        endpoint_a = session.endpoint_a
        endpoint_b = session.endpoint_b
        streams = getattr(session, "streams", []) or []
        protocol = "unknown"
        for stream in streams:
            if stream.protocol_label and stream.protocol_label != "unknown_binary":
                protocol = stream.protocol_label
                break
        if protocol_filter and protocol != protocol_filter:
            continue

        a_ip, a_port = _split(endpoint_a)
        b_ip, b_port = _split(endpoint_b)
        if node_kind == "endpoint":
            source, target = endpoint_a, endpoint_b
        else:
            source, target = a_ip, b_ip
        for identifier in (source, target):
            if identifier not in nodes:
                nodes[identifier] = Node(id=identifier, kind=node_kind, label=identifier)

        key = tuple(sorted((source, target)))
        edge = edges.get(key)
        if edge is None:
            edge = Edge(source=key[0], target=key[1], bytes_a_to_b=0, bytes_b_to_a=0, packets=0)
            edges[key] = edge
        forward = source == endpoint_a
        a_to_b = int(summary.get("bytes_a_to_b", 0) or 0)
        b_to_a = int(summary.get("bytes_b_to_a", 0) or 0)
        if forward:
            edge.bytes_a_to_b += a_to_b
            edge.bytes_b_to_a += b_to_a
        else:
            edge.bytes_a_to_b += b_to_a
            edge.bytes_b_to_a += a_to_b
        edge.packets += int(summary.get("packet_count", 0) or 0)
        edge.sessions.append(session.id)
        edge.protocols.add(protocol)
        edge.confirmed = edge.confirmed and session.role_confidence == "syn_observed"

        nodes[source].bytes_out += a_to_b if forward else b_to_a
        nodes[source].bytes_in += b_to_a if forward else a_to_b
        nodes[target].bytes_in += a_to_b if forward else b_to_a
        nodes[target].bytes_out += b_to_a if forward else a_to_b
        nodes[source].peers.add(target)
        nodes[target].peers.add(source)
        nodes[source].sessions.append(session.id)
        nodes[target].sessions.append(session.id)
        nodes[source].protocols.add(protocol)
        nodes[target].protocols.add(protocol)

    kept_edges = [e for e in edges.values() if e.total_bytes >= min_bytes]
    kept_nodes = {e.source for e in kept_edges} | {e.target for e in kept_edges}
    filtered_nodes = {k: v for k, v in nodes.items() if k in kept_nodes}
    if len(filtered_nodes) > MAX_NODES:
        warnings.append(
            f"The graph has {len(filtered_nodes)} nodes, above the {MAX_NODES} display "
            "limit. Raise the traffic filter to narrow it."
        )
        ranked = sorted(
            filtered_nodes.items(), key=lambda kv: -(kv[1].bytes_in + kv[1].bytes_out)
        )[:MAX_NODES]
        filtered_nodes = dict(ranked)
        warnings.append(
            f"Displaying the {MAX_NODES} highest-traffic nodes; centrality is "
            "computed on the full filtered graph, not on this truncated view."
        )

    for node in filtered_nodes.values():
        node.degree = len(node.peers)
    n = len(filtered_nodes)
    if n > 1:
        for node in filtered_nodes.values():
            node.degree_centrality = node.degree / (n - 1)

    graph = Graph(nodes=filtered_nodes, edges=kept_edges, warnings=warnings)
    if compute_betweenness:
        if n > max_betweenness_nodes:
            graph.warnings.append(
                f"Betweenness centrality was not computed: {n} nodes exceed the "
                f"{max_betweenness_nodes}-node budget. Degree centrality is still "
                "available."
            )
        else:
            _betweenness(graph)
    return graph


def _split(endpoint: str) -> tuple[str, int]:
    host, _, port = endpoint.rpartition(":")
    try:
        return host, int(port)
    except ValueError:
        return endpoint, 0


def _betweenness(graph: Graph) -> None:
    """Brandes' algorithm on the unweighted graph."""
    import heapq

    nodes = {name: node for name, node in graph.nodes.items()}
    index = {name: i for i, name in enumerate(nodes)}
    adjacency: dict[int, set[int]] = defaultdict(set)
    for edge in graph.edges:
        s = index.get(edge.source)
        t = index.get(edge.target)
        if s is None or t is None or s == t:
            continue
        adjacency[s].add(t)
        adjacency[t].add(s)

    for node in nodes.values():
        node.betweenness = 0.0

    names = list(nodes)
    for source in list(adjacency):
        stack: list[int] = []
        predecessors: dict[int, list[int]] = {v: [] for v in adjacency}
        sigma = {v: 0.0 for v in adjacency}
        distance = {v: -1 for v in adjacency}
        sigma[source] = 1.0
        distance[source] = 0
        queue = [(0, source)]
        while queue:
            dist, v = heapq.heappop(queue)
            if dist > distance[v]:
                continue
            stack.append(v)
            for w in adjacency[v]:
                if distance[w] < 0:
                    distance[w] = dist + 1
                    heapq.heappush(queue, (distance[w], w))
                if distance[w] == dist + 1:
                    sigma[w] += sigma[v]
                    predecessors[w].append(v)
        delta = {v: 0.0 for v in adjacency}
        while stack:
            w = stack.pop()
            for v in predecessors[w]:
                if sigma[w]:
                    delta[v] += (sigma[v] / sigma[w]) * (1 + delta[w])
            if w != source:
                target = nodes[names[w]]
                target.betweenness = (target.betweenness or 0.0) + delta[w]

    count = len(adjacency)
    if count > 2:
        for node in nodes.values():
            if node.betweenness is not None:
                node.betweenness /= ((count - 1) * (count - 2))


def rank_nodes(graph: Graph, limit: int = 20) -> list[dict[str, Any]]:
    """Rank by centrality, explicitly labelled as a triage aid."""
    ordered = sorted(
        graph.nodes.values(),
        key=lambda n: (-(n.betweenness or 0.0), -n.degree, -n.bytes_in - n.bytes_out),
    )[:limit]
    out = []
    for rank, node in enumerate(ordered, start=1):
        out.append(
            {
                "rank": rank,
                "node": node.to_dict(),
                "label": (
                    "Candidate for further review: high betweenness means many "
                    "observed paths pass through this host, not that it is a "
                    "command-and-control endpoint."
                ),
            }
        )
    return out