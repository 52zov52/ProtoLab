"""TCP session and stream exploration: state timeline, hex view, provenance."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Query
from sqlalchemy import func, select

from ...analyzers.byte_analysis import align_messages, group_by_length, hexdump
from ...analyzers.framing import FramingConfig, suggest_framing
from ...core.errors import NotFound
from ...models import Capture, Message, Stream, TcpSession
from ...schemas import CompareRequest, DecryptRequest, MessageOut, StreamOut
from ..context import SessionDep, StorageDep, load_capture

router = APIRouter()

MAX_HEX_BYTES = 65536
# A TLS handshake sits at the head of a stream; scanning further would waste
# memory on bulk ciphertext without finding another handshake.
MAX_TLS_SCAN_BYTES = 256 * 1024


def _store(capture: Capture, storage):
    from ...services.stream_store import StreamStore

    paths = storage.capture_paths(capture.project_id, capture.id, capture.format)
    store = StreamStore(paths.stream_blob, paths.stream_index)
    return paths, store


def _load_stream(session, stream_id: str) -> Stream:
    stream = session.get(Stream, stream_id)
    if stream is None:
        raise NotFound(f"Stream {stream_id!r} does not exist.")
    return stream


# --------------------------------------------------------------------------- #
# Streams
# --------------------------------------------------------------------------- #


@router.get("/streams/{stream_id}", response_model=StreamOut)
def get_stream(stream_id: str, session: SessionDep) -> Stream:
    return _load_stream(session, stream_id)


@router.get("/streams/{stream_id}/bytes")
def stream_bytes(
    stream_id: str,
    session: SessionDep,
    storage: StorageDep,
    offset: Annotated[int, Query(ge=0)] = 0,
    length: Annotated[int, Query(ge=1, le=MAX_HEX_BYTES)] = 1024,
) -> dict:
    """A hex window plus the coverage map, with gaps rendered explicitly."""
    stream_row = _load_stream(session, stream_id)
    capture = load_capture(session, _capture_id(session, stream_row))
    paths, store = _store(capture, storage)
    if not store.available:
        raise NotFound("The reconstructed stream artefact is missing.")
    descriptor = store.get(stream_id)
    if descriptor is None:
        raise NotFound(f"Stream {stream_id!r} has no artefact entry.")
    descriptor.capture_id = capture.id
    rebuilt = store.build(descriptor)
    lines = []
    for run_offset, chunk in rebuilt.contiguous_bytes(offset, offset + length):
        lines.extend(
            hexdump(chunk, base_offset=run_offset)
        )
    return {
        "stream_id": stream_id,
        "offset": offset,
        "requested_length": length,
        "stream_length": rebuilt.stream_length,
        "present_bytes": rebuilt.present_bytes,
        "holes": rebuilt.hole_list(),
        "coverage": rebuilt.coverage(),
        "lines": lines,
        "packet_references": rebuilt.packet_references(offset, length),
    }


@router.get("/streams/{stream_id}/tls")
def stream_tls_fingerprints(stream_id: str, session: SessionDep, storage: StorageDep) -> dict:
    """JA3 / JA3S fingerprints observed in one reconstructed stream.

    Fingerprinting reads the plaintext handshake bytes, so it works on an
    encrypted session and needs no key material.  A handshake that was truncated
    in the capture is reported with ``reliable: false`` and no hash rather than
    being hashed from partial bytes.
    """
    from ...analyzers.tls_fingerprinting import (
        BASE_VERSION,
        summarise_handshakes,
    )

    stream_row = _load_stream(session, stream_id)
    capture = load_capture(session, _capture_id(session, stream_row))
    paths, store = _store(capture, storage)
    if not store.available:
        raise NotFound("The reconstructed stream artefact is missing.")
    descriptor = store.get(stream_id)
    if descriptor is None:
        raise NotFound(f"Stream {stream_id!r} has no artefact entry.")
    descriptor.capture_id = capture.id
    rebuilt = store.build(descriptor)

    # Scan the head of the stream: a handshake lives at the start of a TLS
    # session, so the whole stream is never loaded into memory.
    window = rebuilt.contiguous_bytes(0, min(rebuilt.stream_length, MAX_TLS_SCAN_BYTES))
    handshakes: list[dict] = []
    for offset, chunk in window:
        for record in summarise_handshakes(chunk, base_offset=offset):
            record["packet_references"] = rebuilt.packet_references(
                int(record.get("offset_in_stream") or offset), 1
            )
            handshakes.append(record)

    return {
        "stream_id": stream_id,
        "capture_id": capture.id,
        "handshakes": handshakes,
        "count": len(handshakes),
        "fingerprint_database": BASE_VERSION,
        "interpretation_note": (
            "A hash present in the local database means this hash is published for that "
            "client family. It is not proof of the implementation language and never an "
            "indication of maliciousness. A missing or unreliable fingerprint means the "
            "handshake was absent or truncated in this capture, not that the traffic was "
            "not TLS."
        ),
    }


@router.post("/streams/{stream_id}/decrypt")
def stream_decrypt(
    stream_id: str,
    payload: DecryptRequest,
    session: SessionDep,
    storage: StorageDep,
) -> dict:
    """Decrypt the application records of this direction with a supplied key log.

    Everything about the result is explicit. A record is returned with its
    plaintext only when authentication succeeds for the negotiated suite; every
    other record reports the reason it could not be opened, and nothing is ever
    rendered in its place. A direction that carries no handshake means the suite
    and the server random cannot be established from this stream, which is said
    rather than guessed at.
    """
    from ...analyzers.tls_decryption import (
        SessionKeys,
        decrypt_records,
        describe_keylog,
        parse_keylog,
        summarise,
    )
    from ...analyzers.tls_fingerprinting import summarise_handshakes
    from ...models import KeyLog

    stream_row = _load_stream(session, stream_id)
    capture = load_capture(session, _capture_id(session, stream_row))
    keylog = session.get(KeyLog, payload.keylog_id)
    if keylog is None or keylog.project_id != capture.project_id:
        raise NotFound("This key log does not belong to the project of this stream.")

    path = Path(keylog.storage_path)
    if not path.is_file():
        raise NotFound("The key log file is missing from storage; upload it again.")
    entries = parse_keylog(path.read_text(encoding="utf-8", errors="replace"))
    if not any(entries.values()):
        raise NotFound("The key log holds no usable key entries.")

    paths, store = _store(capture, storage)
    if not store.available:
        raise NotFound("The reconstructed stream artefact is missing.")
    descriptor = store.get(stream_id)
    if descriptor is None:
        raise NotFound(f"Stream {stream_id!r} has no artefact entry.")
    descriptor.capture_id = capture.id
    rebuilt = store.build(descriptor)

    def scan(window: list[tuple[int, bytes]]) -> dict:
        """Client/server randoms and the negotiated suite from one direction."""
        found = {"client_random": None, "server_random": None, "suite": None}
        for offset, chunk in window:
            for handshake in summarise_handshakes(chunk, base_offset=offset):
                if handshake.get("kind") == "JA3" and found["client_random"] is None:
                    found["client_random"] = handshake.get("client_random")
                if handshake.get("kind") == "JA3S":
                    found["server_random"] = found["server_random"] or handshake.get(
                        "server_random"
                    )
                    if handshake.get("cipher_suites"):
                        found["suite"] = found["suite"] or handshake["cipher_suites"][0]
        return found

    window: list[tuple[int, bytes]] = list(
        rebuilt.contiguous_bytes(0, min(rebuilt.stream_length, MAX_TLS_SCAN_BYTES))
    )
    seen = scan(window)

    # The suite is a property of the session, not of the direction: a peer that
    # chooses TLS_AES_128_GCM_SHA256 says so in *its* hello. Without that, the
    # client's own records would be reported as unopenable for no reason other
    # than which side happened to talk first.
    peer_direction = "b2a" if stream_row.direction == "a2b" else "a2b"
    suite_from_peer = False
    if seen["suite"] is None:
        peer = session.execute(
            select(Stream)
            .where(Stream.session_id == stream_row.session_id)
            .where(Stream.direction == peer_direction)
        ).scalars().first()
        if peer is not None:
            peer_descriptor = store.get(peer.id)
            if peer_descriptor is not None:
                peer_descriptor.capture_id = capture.id
                peer_rebuilt = store.build(peer_descriptor)
                peer_window = list(
                    peer_rebuilt.contiguous_bytes(
                        0, min(peer_rebuilt.stream_length, MAX_TLS_SCAN_BYTES)
                    )
                )
                peer_scan = scan(peer_window)
                if peer_scan["suite"] is not None:
                    seen["suite"] = peer_scan["suite"]
                    seen["server_random"] = seen["server_random"] or peer_scan["server_random"]
                    suite_from_peer = True

    client_random = seen["client_random"]
    server_random = seen["server_random"]
    suite = seen["suite"]

    direction = "client" if stream_row.direction == "a2b" else "server"
    keys = SessionKeys(
        direction=direction,  # type: ignore[arg-type]
        cipher_suite=suite,
        client_random=bytes.fromhex(client_random) if client_random else None,
        server_random=bytes.fromhex(server_random) if server_random else None,
        tls13_secrets=entries,
    )
    if suite and suite not in (0x1301, 0x1302, 0x1303) and keys.master_secret is None:
        # TLS 1.2 needs the master secret, keyed on the client random.
        secrets = entries.get("CLIENT_RANDOM", [])
        if client_random:
            wanted = bytes.fromhex(client_random)
            for random, secret in secrets:
                if random == wanted:
                    keys.master_secret = secret
                    break

    results = []
    for offset, chunk in window:
        results.extend(decrypt_records(chunk, keys, base_offset=offset))

    return {
        "stream_id": stream_id,
        "capture_id": capture.id,
        "direction": direction,
        "keylog": {
            "id": keylog.id,
            "name": keylog.name,
            "sha256": keylog.sha256,
            "labels": describe_keylog(entries)["labels"],
        },
        "session": {
            **keys.summary(),
            "suite_taken_from_other_direction": suite_from_peer,
        },
        "records": [result.to_dict() for result in results],
        "summary": summarise(results),
        "interpretation": (
            "Decrypted bytes are exactly what the peer sent, proven by the "
            "authentication of the negotiated cipher suite. A record reported as "
            "auth_failed, unsupported or truncated has no plaintext shown, and "
            "nothing is ever rendered in its place."
        ),
    }


def _capture_id(session, stream_row: Stream) -> str:
    row = session.execute(
        select(TcpSession.capture_id).where(TcpSession.id == stream_row.session_id)
    ).scalar()
    if row is None:
        raise NotFound("The parent TCP session for this stream no longer exists.")
    return row


@router.get("/streams/{stream_id}/messages")
def stream_messages(
    stream_id: str,
    session: SessionDep,
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=1000)] = 200,
) -> dict:
    rows = list(
        session.execute(
            select(Message)
            .where(Message.stream_id == stream_id)
            .order_by(Message.index_in_stream)
            .offset(offset)
            .limit(limit)
        )
        .scalars()
        .all()
    )
    return {
        "items": [
            MessageOut(
                id=r.id,
                stream_id=r.stream_id,
                index_in_stream=r.index_in_stream,
                start_offset=r.start_offset,
                end_offset=r.end_offset,
                present_length=r.present_length,
                declared_length=r.declared_length,
                timestamp=r.timestamp,
                framing_method=r.framing_method,
                framing_rule_version=r.framing_rule_version,
                confidence=r.confidence,
                complete=r.complete,
                packet_references=r.packet_references,
                diagnostics=r.diagnostics,
                features=r.features,
            ).model_dump()
            for r in rows
        ],
        "total": session.scalar(
            select(func.count(Message.id)).where(Message.stream_id == stream_id)
        ),
        "offset": offset,
        "limit": limit,
    }


@router.get("/streams/{stream_id}/framing-suggestions")
def framing_suggestions(stream_id: str, session: SessionDep, storage: StorageDep) -> dict:
    """Rank framing rules for this stream with the evidence behind each."""
    stream_row = _load_stream(session, stream_id)
    capture = load_capture(session, _capture_id(session, stream_row))
    paths, store = _store(capture, storage)
    descriptor = store.get(stream_id)
    if descriptor is None:
        raise NotFound("No artefact for this stream.")
    rebuilt = store.build(descriptor)
    suggestions = suggest_framing(rebuilt)
    return {
        "stream_id": stream_id,
        "suggestions": suggestions,
        "disclaimer": (
            "These are candidates scored from observed bytes, not conclusions. "
            "Apply one and validate it against a corpus before treating it as the "
            "protocol's framing."
        ),
    }


@router.get("/streams/{stream_id}/messages/{message_id}/hex")
def message_hex(
    stream_id: str, message_id: str, session: SessionDep, storage: StorageDep
) -> dict:
    message = session.get(Message, message_id)
    if message is None or message.stream_id != stream_id:
        raise NotFound(f"Message {message_id!r} is not part of stream {stream_id!r}.")
    stream_row = _load_stream(session, stream_id)
    capture = load_capture(session, _capture_id(session, stream_row))
    paths, store = _store(capture, storage)
    descriptor = store.get(stream_id)
    if descriptor is None:
        raise NotFound("No artefact for this stream.")
    rebuilt = store.build(descriptor)
    payload = rebuilt.read(message.start_offset, message.end_offset - message.start_offset)
    holes = [
        (h.start, h.end)
        for h in rebuilt.holes
        if h.end > message.start_offset and h.start < message.end_offset
    ]
    return {
        "message_id": message_id,
        "start_offset": message.start_offset,
        "end_offset": message.end_offset,
        "declared_length": message.declared_length,
        "present_length": len(payload),
        "complete": message.complete,
        "hex": payload.hex(),
        "lines": hexdump(payload, base_offset=message.start_offset, holes=holes),
        "packet_references": message.packet_references,
        "features": message.features,
        "diagnostics": message.diagnostics,
    }


@router.post("/streams/{stream_id}/compare")
def compare_messages(
    stream_id: str, payload: CompareRequest, session: SessionDep, storage: StorageDep
) -> dict:
    """Side-by-side byte comparison with per-offset alignment."""
    stream_row = _load_stream(session, stream_id)
    capture = load_capture(session, _capture_id(session, stream_row))
    paths, store = _store(capture, storage)
    descriptor = store.get(stream_id)
    if descriptor is None:
        raise NotFound("No artefact for this stream.")
    rebuilt = store.build(descriptor)

    chosen: list[dict] = []
    for message_id in payload.message_ids:
        message = session.get(Message, message_id)
        if message is None:
            raise NotFound(f"Message {message_id!r} does not exist.")
        blob = rebuilt.read(message.start_offset, message.end_offset - message.start_offset)
        chosen.append(
            {
                "message_id": message.id,
                "index_in_stream": message.index_in_stream,
                "start_offset": message.start_offset,
                "length": len(blob),
                "declared_length": message.declared_length,
                "complete": message.complete,
                "timestamp": message.timestamp,
                "hex": blob.hex(),
            }
        )
    blobs = [bytes.fromhex(item["hex"]) for item in chosen]
    method, rows = align_messages(blobs)
    identical = [i for i, row in enumerate(rows) if not row.changed]
    return {
        "stream_id": stream_id,
        "alignment": {
            "method": method,
            "description": (
                "Bytes are aligned by absolute offset within the message. A null "
                "value means the message is shorter than that offset: those "
                "positions are absent, not zero."
            ),
        },
        "messages": chosen,
        "rows": [
            {
                "offset": row.offset,
                "values": row.values,
                "changed": row.changed,
                "present_count": row.present_count,
            }
            for row in rows
        ],
        "identical_offsets": identical,
        "length_groups": group_by_length(blobs),
    }


@router.get("/streams/{stream_id}/field-statistics")
def field_statistics(
    stream_id: str,
    session: SessionDep,
    storage: StorageDep,
    limit: Annotated[int, Query(ge=1, le=5000)] = 1000,
) -> dict:
    """Per-offset statistics over the framed messages of a stream."""
    from ...analyzers.field_inference import infer_fields

    stream_row = _load_stream(session, stream_id)
    capture = load_capture(session, _capture_id(session, stream_row))
    paths, store = _store(capture, storage)
    descriptor = store.get(stream_id)
    if descriptor is None:
        raise NotFound("No artefact for this stream.")
    rebuilt = store.build(descriptor)
    rows = (
        session.execute(
            select(Message)
            .where(Message.stream_id == stream_id)
            .order_by(Message.index_in_stream)
            .limit(limit)
        )
        .scalars()
        .all()
    )
    blobs = [
        rebuilt.read(r.start_offset, r.end_offset - r.start_offset)
        for r in rows
        if r.complete
    ]
    result = infer_fields(blobs)
    return {
        "stream_id": stream_id,
        "message_count": len(blobs),
        **result.to_dict(),
    }


_ = FramingConfig