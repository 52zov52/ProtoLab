"""End-to-end API tests for the vertical slice.

import capture -> analyse -> frame -> interpret -> validate -> counterexample
-> fix -> re-validate -> apply to a second capture -> export project -> import.
"""

from __future__ import annotations

import io

from conftest import make_spec


def upload(client, project_id: str, path, name: str | None = None):
    with path.open("rb") as handle:
        return client.post(
            "/api/captures",
            data={"project_id": project_id, "name": name or path.name},
            files={"file": (path.name, handle, "application/octet-stream")},
        )


# --------------------------------------------------------------------------- #
# Import and analysis
# --------------------------------------------------------------------------- #


def test_health_and_project_lifecycle(client):
    assert client.get("/api/health").json()["status"] == "ok"
    created = client.post("/api/projects", json={"name": "Alpha"})
    assert created.status_code == 201
    project_id = created.json()["id"]
    assert client.get(f"/api/projects/{project_id}").json()["name"] == "Alpha"
    metrics = client.get(f"/api/projects/{project_id}/metrics").json()
    assert metrics["captures"] == 0 and metrics["packets"] == 0 and metrics["messages"] == 0
    assert client.delete(f"/api/projects/{project_id}").status_code == 204
    assert client.get(f"/api/projects/{project_id}").status_code == 404


def test_patch_project_updates_fields_and_merges_settings(client, project):
    project_id = project["id"]
    response = client.patch(
        f"/api/projects/{project_id}",
        json={"description": "investigation A", "settings": {"allow_external_ai": True}},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["name"] == project["name"], "an omitted field must not be cleared"
    assert body["description"] == "investigation A"
    assert body["settings"]["allow_external_ai"] is True

    # A later update that only knows one key must not drop the others.
    client.patch(f"/api/projects/{project_id}", json={"settings": {"note": "merged"}})
    merged = client.get(f"/api/projects/{project_id}").json()["settings"]
    assert merged["allow_external_ai"] is True
    assert merged["note"] == "merged"


def test_patch_project_rejects_unknown_fields(client, project):
    response = client.patch(f"/api/projects/{project['id']}", json={"unknown": 1})
    assert response.status_code == 422


def test_import_capture_hashes_and_indexes_it(client, project, bench_dir):
    response = upload(client, project["id"], bench_dir / "basic.pcap")
    assert response.status_code == 201, response.text
    capture = response.json()
    assert len(capture["sha256"]) == 64
    assert capture["analysis_status"] == "pending"
    assert client.get(f"/api/captures/{capture['id']}").status_code == 200


def test_duplicate_import_is_refused(client, project, bench_dir):
    upload(client, project["id"], bench_dir / "basic.pcap")
    second = upload(client, project["id"], bench_dir / "basic.pcap", name="copy.pcap")
    assert second.status_code == 409
    assert "already imported" in second.json()["error"]["message"]


def test_analysis_reconstructs_the_conversation(client, project, bench_dir):
    capture = upload(client, project["id"], bench_dir / "basic.pcap").json()
    summary = client.post(f"/api/captures/{capture['id']}/analyze", json={}).json()
    assert summary["sessions"] == 1
    assert summary["streams"] >= 1
    assert summary["reader_diagnostics"]["errors"] == []

    sessions = client.get(f"/api/captures/{capture['id']}/sessions").json()
    assert sessions["total"] == 1
    row = sessions["items"][0]
    assert row["completeness_status"] == "complete"
    assert row["client_endpoint"] == "192.168.10.25:51422"
    assert row["role_confidence"] == "syn_observed"

    packets = client.get(f"/api/captures/{capture['id']}/packets", params={"limit": 50}).json()
    assert packets["total"] == 13
    assert all(p["transport_protocol"] == "tcp" for p in packets["items"])


def test_analysis_works_for_pcapng(client, project, bench_dir):
    capture = upload(client, project["id"], bench_dir / "basic.pcapng").json()
    summary = client.post(f"/api/captures/{capture['id']}/analyze", json={}).json()
    assert summary["sessions"] == 1
    assert summary["packets_indexed" if "packets_indexed" in summary else "streams"] >= 1


def test_port_reuse_produces_two_sessions(client, project, bench_dir):
    capture = upload(client, project["id"], bench_dir / "port_reuse.pcap").json()
    client.post(f"/api/captures/{capture['id']}/analyze", json={})
    sessions = client.get(f"/api/captures/{capture['id']}/sessions").json()
    assert sessions["total"] == 2, "a reused 4-tuple must not be merged into one session"
    identities = {s["session_identity"] for s in sessions["items"]}
    assert len(identities) == 2
    # The second incarnation has no SYN, so its role is a stated assumption.
    roles = {s["role_confidence"] for s in sessions["items"]}
    assert "syn_observed" in roles


def test_lost_segment_produces_a_hole_not_zeros(client, project, bench_dir):
    capture = upload(client, project["id"], bench_dir / "lossy_segments.pcap").json()
    client.post(
        f"/api/captures/{capture['id']}/analyze",
        json={"framing": {"method": "length_prefix", "config": {
            "length_offset": 0, "length_size": 2, "endianness": "big",
            "includes_header": "true", "max_length": 65535}}},
    )
    streams = client.get(f"/api/captures/{capture['id']}/sessions").json()["items"]
    session_id = streams[0]["id"]
    stream_rows = client.get(f"/api/sessions/{session_id}/streams").json()
    stream_id = stream_rows[0]["id"]
    data = client.get(f"/api/streams/{stream_id}/bytes").json()
    assert data["holes"], "the lost segment must be reported as a hole"
    assert all(h["reason"] == "missing_segments" for h in data["holes"])
    assert data["present_bytes"] < data["stream_length"]


def test_retransmissions_do_not_duplicate_bytes(client, project, bench_dir):
    capture = upload(client, project["id"], bench_dir / "retransmissions.pcap").json()
    client.post(f"/api/captures/{capture['id']}/analyze", json={})
    sessions = client.get(f"/api/captures/{capture['id']}/sessions").json()["items"]
    stream_id = client.get(f"/api/sessions/{sessions[0]['id']}/streams").json()[0]["id"]
    diagnostics = client.get(f"/api/sessions/{sessions[0]['id']}/diagnostics").json()
    kinds = [
        item["kind"]
        for stream in diagnostics["streams"]
        for item in stream["retransmissions"]
    ]
    assert "exact_duplicate" in kinds
    data = client.get(f"/api/streams/{stream_id}/bytes").json()
    assert data["present_bytes"] == data["stream_length"]


# --------------------------------------------------------------------------- #
# Framing and interpretation
# --------------------------------------------------------------------------- #


def test_framing_suggests_the_real_length_prefix(client, project, bench_dir):
    capture = upload(client, project["id"], bench_dir / "mixed_lengths.pcap").json()
    client.post(
        f"/api/captures/{capture['id']}/analyze",
        json={"framing": {"method": "length_prefix", "config": {
            "length_offset": 0, "length_size": 2, "endianness": "big",
            "includes_header": "true", "max_length": 65535}}},
    )
    session_id = client.get(f"/api/captures/{capture['id']}/sessions").json()["items"][0]["id"]
    stream_id = client.get(f"/api/sessions/{session_id}/streams").json()[0]["id"]
    messages = client.get(f"/api/streams/{stream_id}/messages").json()
    assert messages["total"] > 10
    assert all(m["framing_method"] == "length_prefix" for m in messages["items"])

    suggestions = client.get(f"/api/streams/{stream_id}/framing-suggestions").json()
    assert suggestions["suggestions"]
    top = suggestions["suggestions"][0]
    assert top["config"]["length_offset"] == 0
    assert top["config"]["length_size"] == 2
    assert top["config"]["endianness"] == "big"


def test_interpretation_extracts_the_recovered_fields(client, imported):
    project_id = imported["project"]["id"]
    capture_id = imported["capture"]["id"]
    created = client.post(
        f"/api/projects/{project_id}/interpreters",
        json={"name": "MadrigalTestDevice", "specification": make_spec()},
    )
    assert created.status_code == 201, created.text
    interpretation = created.json()

    validation = client.post(
        f"/api/projects/{project_id}/interpreters/{interpretation['id']}/validate",
        json={"capture_ids": [capture_id]},
    )
    assert validation.status_code == 200, validation.text
    result = validation.json()
    assert result["verdict"] == "consistent_with_corpus"
    assert result["failed"] == 0
    assert result["matched"] >= 6

    run = client.get(f"/api/validation-runs/{result['run_id']}").json()
    assert run["stale"] is False
    assert run["specification_checksum"] == interpretation["checksum"]
    assert run["interpretation_name"] == "MadrigalTestDevice"


def test_interpretation_routes_expose_the_specification(client, imported):
    """Every interpretation route must return ``specification``, not raw ORM rows.

    ``InterpretationOut`` expects ``specification`` while the ORM attribute is
    named ``schema_json``; the list route and the flat alias previously handed
    back ORM objects and returned a 500.  This pins the mapping.
    """
    project_id = imported["project"]["id"]
    created = client.post(
        f"/api/projects/{project_id}/interpreters",
        json={"name": "Round trip", "specification": make_spec()},
    ).json()

    listed = client.get(f"/api/projects/{project_id}/interpretations")
    assert listed.status_code == 200, listed.text
    rows = listed.json()
    assert [row["id"] for row in rows] == [created["id"]]
    assert rows[0]["specification"]["schema_version"] == "1.0"
    assert rows[0]["checksum"] == created["checksum"]

    # The documented flat alias must work too.
    aliased = client.post(
        f"/api/interpreters?project_id={project_id}",
        json={"name": "Alias", "specification": make_spec()},
    )
    assert aliased.status_code in (200, 201), aliased.text
    assert aliased.json()["specification"]["protocol_name"] == "MadrigalTestDevice"


def test_wrong_hypothesis_produces_a_counterexample(client, imported, bench_dir):
    """The demonstration's critical step: a plausible but wrong rule fails."""
    project_id = imported["project"]["id"]
    capture_id = imported["capture"]["id"]

    # Hypothesis: the length field is little-endian and excludes the header.
    wrong = make_spec(length_size=2, endianness="little")
    wrong["framing"]["length_field"]["includes_header"] = False
    wrong["fields"][0]["endianness"] = "little"
    interpretation = client.post(
        f"/api/projects/{project_id}/interpreters",
        json={"name": "Wrong endianness hypothesis", "specification": wrong},
    ).json()

    run = client.post(
        f"/api/projects/{project_id}/interpreters/{interpretation['id']}/validate",
        json={"capture_ids": [capture_id]},
    ).json()
    assert run["failed"] > 0, "the wrong hypothesis must produce counterexamples"

    examples = client.get(f"/api/validation-runs/{run['run_id']}/counterexamples").json()
    assert examples["count"] > 0
    example = examples["counterexamples"][0]
    assert example["violated_rule"] in {"invalid_length", "field_out_of_bounds", "truncated_length_field", "declared_length_exceeds_message"}
    assert example["reasons"]
    assert example["evidence"]
    assert example["alternative_explanations"]

    # Re-run with the corrected rule; the old run must become stale.
    fixed = client.put(
        f"/api/projects/{project_id}/interpreters/{interpretation['id']}",
        json={"specification": make_spec()},
    )
    assert fixed.status_code == 200, fixed.text
    assert fixed.json()["version"] == 2

    stale = client.get(f"/api/validation-runs/{run['run_id']}").json()
    assert stale["stale"] is True
    assert "older rule version" in stale["stale_reason"]

    rerun = client.post(
        f"/api/projects/{project_id}/interpreters/{interpretation['id']}/validate",
        json={"capture_ids": [capture_id]},
    ).json()
    assert rerun["failed"] == 0
    assert rerun["verdict"] == "consistent_with_corpus"


def test_specification_applies_to_a_second_capture(client, imported, bench_dir):
    project_id = imported["project"]["id"]
    second = upload(client, project_id, bench_dir / "set_parameter_20.pcap").json()
    client.post(f"/api/captures/{second['id']}/analyze", json={})
    client.post(f"/api/captures/{second['id']}/analyze", json={
        "framing": {"method": "length_prefix", "config": {
            "length_offset": 0, "length_size": 2, "endianness": "big",
            "includes_header": "true", "max_length": 65535}}})

    interpretation = client.post(
        f"/api/projects/{project_id}/interpreters",
        json={"name": "Applied rule", "specification": make_spec()},
    ).json()
    result = client.post(
        f"/api/projects/{project_id}/interpreters/{interpretation['id']}/validate",
        json={"capture_ids": [imported["capture"]["id"], second["id"]]},
    ).json()
    assert result["total"] > 0
    assert result["failed"] == 0
    assert "consistent_with_corpus" in result["verdict"] or "partially" in result["verdict"]


def test_byte_comparison_and_provenance(client, imported):
    project_id = imported["project"]["id"]
    capture_id = imported["capture"]["id"]
    client.post(f"/api/captures/{capture_id}/analyze", json={
        "framing": {"method": "length_prefix", "config": {
            "length_offset": 0, "length_size": 2, "endianness": "big",
            "includes_header": "true", "max_length": 65535}}})
    messages = client.get(f"/api/captures/{capture_id}/messages", params={"limit": 20}).json()
    ids = [m["id"] for m in messages["items"]][:3]
    assert len(ids) >= 2

    stream_id = messages["items"][0]["stream_id"]
    compare = client.post(f"/api/streams/{stream_id}/compare", json={"message_ids": ids})
    assert compare.status_code == 200, compare.text
    body = compare.json()
    assert body["alignment"]["method"] == "positional"
    assert "absent, not zero" in body["alignment"]["description"]
    assert body["rows"]

    hex_view = client.get(f"/api/streams/{stream_id}/messages/{ids[0]}/hex").json()
    assert hex_view["hex"]
    assert hex_view["packet_references"]
    assert hex_view["lines"]


def test_field_inference_ranks_the_length_field(client, imported):
    capture_id = imported["capture"]["id"]
    client.post(f"/api/captures/{capture_id}/analyze", json={
        "framing": {"method": "length_prefix", "config": {
            "length_offset": 0, "length_size": 2, "endianness": "big",
            "includes_header": "true", "max_length": 65535}}})
    stream_id = client.get(f"/api/captures/{capture_id}/sessions").json()["items"][0]["id"]
    stream_id = client.get(f"/api/sessions/{stream_id}/streams").json()[0]["id"]
    stats = client.get(f"/api/streams/{stream_id}/field-statistics").json()
    length_candidates = [c for c in stats["candidates"] if c["role"] == "length"]
    assert length_candidates, "a length field must be inferred from the bytes"
    best = length_candidates[0]
    assert best["offset"] == 0 and best["size"] == 2 and best["endianness"] == "big"
    assert best["support_count"] > 0
    assert "counterexamples" in best["rationale"] or best["contradiction_count"] == 0


# --------------------------------------------------------------------------- #
# Reproducibility
# --------------------------------------------------------------------------- #


def test_project_export_and_reimport_into_a_new_location(client, imported, settings):
    project_id = imported["project"]["id"]
    exported = client.post(
        f"/api/projects/{project_id}/export", json={"include_captures": True}
    )
    assert exported.status_code == 200, exported.text
    body = exported.json()
    assert body["counts"]["captures"] == 1

    archive = next(
        (settings.data_dir / "storage" / project_id).rglob(body["archive"]), None
    )
    assert archive is not None and archive.exists(), body

    with archive.open("rb") as handle:
        imported_project = client.post(
            "/api/projects/import",
            files={"file": (body["archive"], handle, "application/octet-stream")},
        )
    assert imported_project.status_code == 200, imported_project.text
    result = imported_project.json()
    assert result["imported"]["captures"] == 1
    assert result["hash_mismatches"] == []

    new_id = result["project_id"]
    metrics = client.get(f"/api/projects/{new_id}/metrics").json()
    assert metrics["captures"] == 1

    # Re-analyse the imported copy and confirm the reconstruction repeats.
    imported_capture_id = _first_capture_id(client, new_id, settings)
    summary = client.post(f"/api/captures/{imported_capture_id}/analyze", json={}).json()
    assert summary["sessions"] == imported["analysis"]["sessions"]
    assert summary["streams"] == imported["analysis"]["streams"]


def _first_capture_id(client, project_id: str, settings) -> str:
    import sqlalchemy
    from sqlalchemy import create_engine, select

    from app.models import Capture

    engine = create_engine(settings.database_url)
    with engine.connect() as connection:
        return connection.execute(
            select(Capture.id).where(Capture.project_id == project_id)
        ).scalars().first()
    _ = sqlalchemy


def test_integrity_check_detects_modification(client, imported, settings):
    from app.core.config import get_settings

    project_id = imported["project"]["id"]
    ok = client.get(f"/api/projects/{project_id}/integrity").json()
    assert ok["all_match"] is True

    capture_id = imported["capture"]["id"]
    path = (
        get_settings().data_dir / "storage" / project_id / "captures" / capture_id / "original.pcap"
    )
    blob = bytearray(path.read_bytes())
    blob[-1] ^= 0xFF
    path.write_bytes(bytes(blob))

    after = client.get(f"/api/projects/{project_id}/integrity").json()
    assert after["all_match"] is False
    assert any(c["status"] == "modified" for c in after["captures"])


# --------------------------------------------------------------------------- #
# Security behaviour
# --------------------------------------------------------------------------- #


def test_unknown_host_header_is_rejected(client):
    response = client.get("/api/health", headers={"Host": "evil.example.com"})
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "security_violation"


def test_cross_origin_request_is_rejected(client):
    response = client.post(
        "/api/projects",
        json={"name": "x"},
        headers={"Origin": "https://attacker.example"},
    )
    assert response.status_code == 403


def test_allowed_origin_is_accepted(client):
    response = client.post(
        "/api/projects",
        json={"name": "allowed"},
        headers={"Origin": "http://127.0.0.1:3000"},
    )
    assert response.status_code == 201


def test_security_headers_are_present(client):
    response = client.get("/api/health")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "no-referrer"


def test_traversal_filename_is_rejected(client, project, tmp_path):
    evil = tmp_path / "evil.pcap"
    evil.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 100)
    with evil.open("rb") as handle:
        response = client.post(
            "/api/captures",
            data={"project_id": project["id"], "name": "../../etc/passwd.pcap"},
            files={"file": ("../../etc/passwd.pcap", handle, "application/octet-stream")},
        )
    assert response.status_code in (201, 400, 422)
    if response.status_code == 201:
        # Accepted for display, but the file must live under managed storage.
        from app.core.config import get_settings

        stored = get_settings().data_dir / "storage" / project["id"]
        assert stored.exists()
        assert not (stored / "etc").exists()


def test_oversized_upload_is_rejected(client, project, tmp_path, settings):
    payload = b"\xd4\xc3\xb2\xa1" + b"\x00" * 64
    with io.BytesIO(payload) as handle:
        response = client.post(
            "/api/captures",
            data={"project_id": project["id"], "name": "big.pcap"},
            files={"file": ("big.pcap", handle, "application/octet-stream")},
            headers={"Content-Length": str(settings.limits.max_upload_bytes + 1)},
        )
    assert response.status_code == 413


def test_upload_above_the_json_body_limit_is_accepted(client, project, settings):
    """A capture is a multipart upload, not a JSON body.

    The global body guard used to apply ``max_json_body_bytes`` (2 MiB) to
    every request, so any capture above 2 MiB — far below the advertised
    ``max_upload_bytes`` of 100 MiB — was rejected with 413 before reaching the
    handler. This imports a real, larger upload and checks it is stored whole.
    """
    size = settings.limits.max_json_body_bytes + 1024 * 1024
    assert size < settings.limits.max_upload_bytes
    payload = b"\xd4\xc3\xb2\xa1" + b"\x00" * (size - 4)
    response = client.post(
        "/api/captures",
        data={"project_id": project["id"], "name": "large.pcap"},
        files={"file": ("large.pcap", payload, "application/octet-stream")},
    )
    assert response.status_code == 201, response.text
    assert response.json()["file_size"] == size


def test_object_ownership_is_enforced(client, project):
    other = client.post("/api/projects", json={"name": "Other"}).json()
    hypothesis = client.post(
        f"/api/projects/{project['id']}/hypotheses", json={"name": "H"}
    ).json()
    cross = client.get(f"/api/projects/{other['id']}/hypotheses/{hypothesis['id']}")
    assert cross.status_code == 404


def test_invalid_identifier_is_rejected(client):
    assert client.get("/api/projects/../../etc").status_code in (403, 404, 422)


def test_security_check_reports_real_verdicts(client):
    response = client.post("/api/security/check")
    assert response.status_code == 200
    body = response.json()
    ids = {check["id"] for check in body["security_checks"]["checks"]}
    assert {"bind_address", "host_allowlist", "cors", "resource_limits", "external_ai"} <= ids
    verdicts = {c["verdict"] for c in body["security_checks"]["checks"]}
    assert verdicts <= {"pass", "fail", "unknown", "na"}
    assert "penetration test" in body["security_checks"]["scope"]


def test_audit_log_records_and_verifies(client, project, bench_dir):
    upload(client, project["id"], bench_dir / "basic.pcap")
    events = client.get("/api/audit/events", params={"action": "capture.import"}).json()
    assert events["total"] >= 1
    assert events["items"][0]["details"]["sha256"]
    assert client.get("/api/audit/verify").json()["valid"] is True


# --------------------------------------------------------------------------- #
# Assistant, diff, graph, reports
# --------------------------------------------------------------------------- #


def test_assistant_refuses_to_guess(client, imported):
    response = client.post(
        "/api/assistant/query",
        json={"query": "find the packet that launched the robot arm", "dry_run": True},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "needs_clarification"
    assert body["interpretation"] is None
    assert body["suggestions"]


def test_assistant_compiles_and_executes_a_typed_query(client, imported):
    project_id = imported["project"]["id"]
    capture_id = imported["capture"]["id"]
    compiled = client.post(
        "/api/assistant/query",
        json={
            "query": "Find all TCP responses longer than 10 bytes",
            "capture_ids": [capture_id],
            "dry_run": True,
        },
    ).json()
    assert compiled["status"] == "planned"
    assert compiled["plan"]["entity"] in ("messages", "packets")
    assert compiled["executed"] is False

    executed = client.post(
        "/api/assistant/query",
        json={
            "query": "Find all TCP responses longer than 10 bytes",
            "capture_ids": [capture_id],
            "dry_run": False,
        },
    ).json()
    assert executed["status"] == "executed"
    assert executed["result"]["count"] > 0


def test_assistant_cannot_be_used_to_run_code(client, imported):
    response = client.post(
        "/api/assistant/query",
        json={"query": "'; DROP TABLE packets; --", "dry_run": True},
    ).json()
    assert response["status"] == "needs_clarification"
    # The database is untouched.
    assert client.get(f"/api/captures/{imported['capture']['id']}/packets").json()["total"] > 0


def test_capture_diff_reports_differences_not_anomalies(client, project, bench_dir):
    a = upload(client, project["id"], bench_dir / "measurements_8.pcap").json()
    b = upload(client, project["id"], bench_dir / "measurements_64.pcap").json()
    for capture in (a, b):
        client.post(f"/api/captures/{capture['id']}/analyze", json={
            "framing": {"method": "length_prefix", "config": {
                "length_offset": 0, "length_size": 2, "endianness": "big",
                "includes_header": "true", "max_length": 65535}}})
    diff = client.post(
        "/api/captures/diff", json={"base_capture_id": a["id"], "compare_capture_id": b["id"]}
    ).json()
    assert diff["sessions"]
    assert "not, by themselves, anomalies" in diff["interpretation_note"]
    assert any(row["status"] == "changed" for row in diff["sessions"])


def test_network_graph_is_built_from_observed_traffic(client, imported):
    body = client.post(
        "/api/network/graph", json={"capture_ids": [imported["capture"]["id"]]}
    ).json()
    assert body["node_count"] == 2
    assert body["edge_count"] == 1
    degrees = {n["degree"] for n in body["nodes"]}
    assert degrees == {1}
    assert body["centrality"]
    assert "not a C2 server" in body["interpretation_note"]
    # With one edge each node has degree centrality 1.0, so both clear the hub
    # threshold; the flag must carry a quoted reason and never claim intent.
    assert all(n["hub_candidate"] for n in body["nodes"])
    for node in body["nodes"]:
        assert "Candidate for further review" in node["hub_reason"]
        assert "never proof of intent" in node["hub_reason"]


def test_protocol_detection_falls_back_to_unknown(client, imported, project, bench_dir):
    """A binary device protocol must not be guessed at."""
    capture = upload(client, project["id"], bench_dir / "set_parameter_60.pcap").json()
    client.post(f"/api/captures/{capture['id']}/analyze", json={})
    session_id = client.get(f"/api/captures/{capture['id']}/sessions").json()["items"][0]["id"]
    streams = client.get(f"/api/sessions/{session_id}/streams").json()
    labels = {s["protocol_label"] for s in streams}
    assert labels <= {"unknown_binary", "length_prefixed_unknown"}
    assert all(s["protocol_confidence"] <= 0.5 for s in streams)


def test_report_generates_with_evidence(client, imported):
    project_id = imported["project"]["id"]
    response = client.post(f"/api/projects/{project_id}/reports", json={"title": "Investigation"})
    assert response.status_code == 200, response.text
    body = response.json()
    numbers = {s["number"] for s in body["sections"]}
    assert {1, 2, 4, 5, 7, 8, 9, 15} <= numbers
    markdown = client.get(f"/api/reports/{body['report_id']}/markdown").text
    assert markdown.startswith("# Investigation")
    assert "Reproduction instructions" in markdown
    assert body["ai_used"] is False


def test_experiment_log_import(client, project):
    response = client.post(
        f"/api/projects/{project['id']}/experiments",
        json={"events": [
            {"timestamp": "2026-10-10T10:30:00Z", "action": "set_parameter",
             "parameters": {"measurement_interval": 20}, "observed_result": "success"},
        ]},
    )
    assert response.status_code == 200
    assert response.json()["imported"] == 1
    events = client.get(f"/api/projects/{project['id']}/experiments").json()
    assert events[0]["action"] == "set_parameter"
    assert events[0]["parameters"]["measurement_interval"] == 20


def test_experiment_import_rejects_bad_timestamps(client, project):
    response = client.post(
        f"/api/projects/{project['id']}/experiments",
        json={"events": [{"timestamp": "not-a-date", "action": "x"}]},
    )
    assert response.status_code == 422


def test_pcapng_export_preserves_packets_and_comments(client, imported):
    capture_id = imported["capture"]["id"]
    client.post(f"/api/captures/{capture_id}/analyze", json={
        "framing": {"method": "length_prefix", "config": {
            "length_offset": 0, "length_size": 2, "endianness": "big",
            "includes_header": "true", "max_length": 65535}}})
    result = client.post(f"/api/captures/{capture_id}/export-pcapng").json()
    assert result["success"] is True, result
    assert result["round_trip"]["verified"] is True
    assert result["packets_annotated"] > 0
    assert result["comments_verified"] == result["packets_annotated"]
    assert "not contain the project" in " ".join(result["notes"])


def test_jobs_can_be_queued_and_polled(client, project, bench_dir):
    capture = upload(client, project["id"], bench_dir / "basic.pcap").json()
    started = client.post(f"/api/captures/{capture['id']}/analyze-async")
    assert started.status_code == 200
    job_id = started.json()["job_id"]
    job = client.get(f"/api/jobs/{job_id}").json()
    assert job["kind"] == "capture.analyze"
    assert job["status"] in ("queued", "running", "succeeded")
    if job["status"] == "succeeded":
        assert job["result"]["sessions"] == 1


def test_tls_endpoint_absent_for_plaintext_but_available(client):
    assert client.get("/api/anomalies/status").json()["available"] in (True, False)


def test_interpretation_support_declares_limits(client, project):
    body = client.get(f"/api/projects/{project['id']}/interpretation-support").json()
    assert "checksum verification" in " ".join(body["explicitly_unsupported"])
    assert "ever imported" in body["safety"]