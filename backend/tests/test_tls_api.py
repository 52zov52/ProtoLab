"""TLS fingerprinting over the API, exercised on real capture data.

The unit tests in ``test_tls_fingerprinting.py`` cover the JA3 algorithm against
hand-built records.  These cover the path that actually matters to an analyst:
a ClientHello recovered from a PCAP, through reassembly, out of the API - and
the case a hash-from-whatever-you-got implementation would silently get wrong,
a handshake truncated by an incomplete capture.
"""

from __future__ import annotations

import hashlib


def _upload(client, project_id: str, bench_dir, name: str) -> str:
    with (bench_dir / name).open("rb") as handle:
        response = client.post(
            "/api/captures",
            data={"project_id": project_id, "name": name},
            files={"file": (name, handle, "application/octet-stream")},
        )
    assert response.status_code == 201, response.text
    return response.json()["id"]


def _fingerprints(client, capture_id: str) -> list[dict]:
    client.post(f"/api/captures/{capture_id}/analyze", json={})
    out: list[dict] = []
    for session in client.get(f"/api/captures/{capture_id}/sessions").json()["items"]:
        for stream in client.get(f"/api/sessions/{session['id']}/streams").json():
            body = client.get(f"/api/streams/{stream['id']}/tls").json()
            out.extend(body["handshakes"])
    return out


def test_client_hello_yields_a_reliable_ja3(client, project, bench_dir):
    capture_id = _upload(client, project["id"], bench_dir, "tls_handshake.pcap")
    handshakes = _fingerprints(client, capture_id)

    client_hellos = [h for h in handshakes if h["kind"] == "JA3"]
    assert client_hellos, "the ClientHello must be recovered from the capture"

    hello = client_hellos[0]
    assert hello["reliable"] is True
    assert hello["md5"] == hashlib.md5(hello["raw"].encode()).hexdigest()
    # The SNI is visible in cleartext in the handshake, no keys required.
    assert hello["sni"] == "device.example.com"
    assert hello["alpn"] == ["h2", "http/1.1"]
    assert hello["supported_groups"], "supported groups must be extracted"
    # Provenance: the fingerprint points back at the packets it came from.
    assert hello["packet_references"]


def test_server_hello_yields_a_reliable_ja3s(client, project, bench_dir):
    capture_id = _upload(client, project["id"], bench_dir, "tls_handshake.pcap")
    handshakes = _fingerprints(client, capture_id)

    server_hellos = [h for h in handshakes if h["kind"] == "JA3S"]
    assert server_hellos, "the ServerHello must be recovered from the capture"
    server = server_hellos[0]
    assert server["reliable"] is True
    assert server["md5"] == hashlib.md5(server["raw"].encode()).hexdigest()


def test_truncated_handshake_is_reported_unreliable_and_unhashed(client, project, bench_dir):
    """A partial ClientHello must never be hashed into a confident-looking MD5."""
    capture_id = _upload(client, project["id"], bench_dir, "tls_truncated.pcap")
    handshakes = _fingerprints(client, capture_id)

    assert handshakes, "a truncated handshake must still surface a diagnostic"
    for hello in handshakes:
        assert hello["reliable"] is False
        assert hello["md5"] is None, "an unreliable fingerprint must not carry a hash"
        # The reason must name what specifically was lost, not just "unreliable".
        assert "truncated" in hello["reason_if_unreliable"] or "ended" in hello["reason_if_unreliable"]


def test_fingerprint_lookups_never_claim_maliciousness(client, project, bench_dir):
    capture_id = _upload(client, project["id"], bench_dir, "tls_handshake.pcap")
    handshakes = _fingerprints(client, capture_id)

    for hello in handshakes:
        match = hello.get("match")
        if match is None:
            continue
        assert "never an indication of maliciousness" in match["interpretation"]


def test_binary_stream_reports_no_tls_rather_than_guessing(client, imported):
    """The device's own binary protocol is not TLS, and must not be called TLS."""
    capture_id = imported["capture"]["id"]
    handshakes = _fingerprints(client, capture_id)
    assert handshakes == [], "no handshake bytes means no fingerprint, not a fake one"


def test_capture_tls_aggregates_every_stream_of_the_capture(client, project, bench_dir):
    capture_id = _upload(client, project["id"], bench_dir, "tls_handshake.pcap")
    client.post(f"/api/captures/{capture_id}/analyze", json={})
    body = client.get(f"/api/captures/{capture_id}/tls").json()

    kinds = {item["kind"] for item in body["fingerprints"]}
    assert {"JA3", "JA3S"} <= kinds, body
    ja3 = next(item for item in body["fingerprints"] if item["kind"] == "JA3")
    assert ja3["occurrences"] >= 1
    assert ja3["stream_ids"], "a fingerprint must name the stream it came from"
    assert ja3["category"] in {"browser", "library", "bot", "server", "unknown"}
    assert body["verdict"]["client_fingerprints"] >= 1
    assert body["verdict"]["statement"]


def test_capture_tls_counts_unreliable_handshakes_without_inventing_a_hash(
    client, project, bench_dir
):
    capture_id = _upload(client, project["id"], bench_dir, "tls_truncated.pcap")
    client.post(f"/api/captures/{capture_id}/analyze", json={})
    body = client.get(f"/api/captures/{capture_id}/tls").json()

    assert body["unreliable_handshakes"] >= 1
    # Every aggregated fingerprint still carries a real hash; unreliable ones
    # are counted separately instead of being merged under a fake value.
    assert all(item["md5"] for item in body["fingerprints"])


def test_capture_tls_on_a_binary_capture_is_empty_not_a_guess(client, imported):
    capture_id = imported["capture"]["id"]
    body = client.get(f"/api/captures/{capture_id}/tls").json()
    assert body["fingerprints"] == []
    assert body["verdict"]["client_fingerprints"] == 0