"""Seed a running backend so the UI can be inspected with real data.

Idempotent-ish: creates a project, imports the baseline capture, analyses it
with the framing rule, imports the action log, creates a hypothesis and an
interpretation, and validates it. Prints the project id so it can be opened
directly in the browser.
"""

from __future__ import annotations

import argparse
import json
import pathlib

import httpx

ROOT = pathlib.Path(__file__).resolve().parents[1]
BENCH = ROOT / "data" / "testbench"

FRAMING = {
    "method": "length_prefix",
    "config": {
        "length_offset": 0,
        "length_size": 2,
        "endianness": "big",
        "includes_header": "true",
        "max_length": 65535,
    },
}

SPEC = {
    "schema_version": "1.0",
    "protocol_name": "MadrigalTestDevice",
    "description": "Recovered from the baseline capture: a 2-byte big-endian length "
                   "that counts itself, one type byte and a 2-byte request id.",
    "framing": {
        "method": "length_prefix",
        "length_field": {"offset": 0, "size": 2, "endianness": "big", "includes_header": True},
    },
    "fields": [
        {
            "name": "length",
            "kind": "uint16",
            "offset": 0,
            "size": 2,
            "endianness": "big",
            "semantic_status": "observed",
            "description": "Total message length including these two bytes.",
        },
        {
            "name": "message_type",
            "kind": "enum",
            "offset": 2,
            "size": 1,
            "semantic_status": "hypothesis",
            "values": {
                "1": "read_parameter",
                "2": "set_parameter",
                "3": "measurements",
                "4": "ack",
                "5": "heartbeat",
            },
        },
        {
            "name": "request_id",
            "kind": "uint16",
            "offset": 3,
            "size": 2,
            "endianness": "big",
            "semantic_status": "hypothesis",
        },
    ],
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default="http://127.0.0.1:8010")
    args = parser.parse_args()

    with httpx.Client(base_url=f"{args.base}/api", timeout=180.0) as client:
        project = client.post(
            "/projects",
            json={
                "name": "Device protocol investigation",
                "description": "Recover the wire format of an undocumented TCP device.",
            },
        ).json()
        pid = project["id"]
        print(f"project_id={pid}")

        actions = json.loads((BENCH / "basic.actions.json").read_text(encoding="utf-8"))
        client.post(f"/projects/{pid}/experiments", json={"events": actions})

        for name in ("basic.pcap", "tls_handshake.pcap"):
            with (BENCH / name).open("rb") as handle:
                response = client.post(
                    "/captures",
                    data={"project_id": pid, "name": name},
                    files={"file": (name, handle, "application/octet-stream")},
                )
            if response.status_code != 201:
                print(f"  {name}: {response.status_code} {response.text[:120]}")
                continue
            capture = response.json()
            client.post(f"/captures/{capture['id']}/analyze", json={"framing": FRAMING})
            print(f"  imported {name} ({capture['id']})")

        captures = [c["id"] for c in client.get(f"/projects/{pid}/captures").json()]
        hypothesis = client.post(
            f"/projects/{pid}/hypotheses",
            json={
                "name": "Length prefix hypothesis",
                "description": "The first two bytes are a big-endian total message length.",
                "status": "testing",
                "scope": {"capture_ids": captures},
            },
        ).json()

        interpretation = client.post(
            f"/projects/{pid}/interpreters",
            json={
                "name": "MadrigalTestDevice",
                "specification": SPEC,
                "hypothesis_id": hypothesis["id"],
            },
        ).json()

        run = client.post(
            f"/projects/{pid}/interpreters/{interpretation['id']}/validate",
            json={"capture_ids": captures},
        ).json()
        print(f"  verdict={run['verdict']} matched={run['matched']} failed={run['failed']}")

        metrics = client.get(f"/projects/{pid}/metrics").json()
        print(f"  metrics: captures={metrics['captures']} packets={metrics['packets']} "
              f"sessions={metrics['tcp_sessions']} messages={metrics['messages']}")
        print(f"\nOpen: http://127.0.0.1:3000/?project={pid}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())