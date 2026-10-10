"""Live smoke test against a running backend.

Complements ``scripts/demo_scenario.py`` (which uses an in-process client) by
exercising the real HTTP stack: uvicorn binding loopback, the Host/Origin
middleware, multipart upload and the full analysis path.

Usage::

    python -m app                                   # in one shell
    python scripts/live_check.py                     # in another

Exits non-zero if any step misbehaves.
"""

from __future__ import annotations

import argparse
import pathlib
import sys

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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default="http://127.0.0.1:8010")
    args = parser.parse_args()
    base = args.base.rstrip("/")

    failures: list[str] = []

    def check(name: str, condition: bool, detail: str = "") -> None:
        mark = "PASS" if condition else "FAIL"
        print(f"  [{mark}] {name}" + (f" - {detail}" if detail else ""))
        if not condition:
            failures.append(name)

    with httpx.Client(base_url=f"{base}/api", timeout=120.0) as client:
        print("health and network posture")
        health = client.get("/health").json()
        check("health responds", health.get("status") == "ok", str(health.get("bind")))
        check("local secure mode", health.get("mode") == "local_secure", health.get("mode", ""))
        check("offline first", health.get("offline_first") is True)

        # The Host allowlist is the defence against DNS rebinding.
        rebound = client.get("/health", headers={"Host": "evil.example.com"})
        check("rejects foreign Host header", rebound.status_code == 403, str(rebound.status_code))
        cross = client.get("/health", headers={"Origin": "https://attacker.example"})
        check("rejects cross-origin browser request", cross.status_code == 403, str(cross.status_code))

        print("project and capture import")
        project = client.post("/projects", json={"name": "Live smoke test"}).json()
        check("project created", bool(project.get("id")), project.get("id", ""))

        capture_path = BENCH / "basic.pcap"
        with capture_path.open("rb") as handle:
            capture = client.post(
                "/captures",
                data={"project_id": project["id"], "name": "basic.pcap"},
                files={"file": ("basic.pcap", handle, "application/octet-stream")},
            ).json()
        check("capture imported", len(capture.get("sha256", "")) == 64, capture.get("sha256", "")[:16])
        check("starts pending", capture.get("analysis_status") == "pending")

        duplicate = client.post(
            "/captures",
            data={"project_id": project["id"], "name": "copy.pcap"},
            files={"file": ("copy.pcap", capture_path.open("rb"), "application/octet-stream")},
        )
        check("duplicate import refused", duplicate.status_code == 409, str(duplicate.status_code))

        print("analysis")
        summary = client.post(f"/captures/{capture['id']}/analyze", json={}).json()
        check("one TCP session", summary.get("sessions") == 1, str(summary.get("sessions")))
        check("no reader errors", summary.get("reader_diagnostics", {}).get("errors") == [])

        framed = client.post(
            f"/captures/{capture['id']}/analyze", json={"framing": FRAMING}
        ).json()
        check("messages framed", framed.get("messages", 0) > 0, str(framed.get("messages")))

        messages = client.get(
            f"/captures/{capture['id']}/messages", params={"limit": 10}
        ).json()
        check("declared length matches payload", all(
            m["declared_length"] == m["present_length"] for m in messages["items"]
        ))

        print("security center")
        security = client.post("/security/check").json()["security_checks"]
        verdicts = {check["id"]: check["verdict"] for check in security["checks"]}
        check("bind address verified", verdicts.get("bind_address") == "pass", verdicts.get("bind_address", ""))
        check("host allowlist verified", verdicts.get("host_allowlist") == "pass", verdicts.get("host_allowlist", ""))
        check("scope is not a pentest", "penetration test" in security["scope"])

        print()
        if failures:
            print(f"{len(failures)} check(s) failed: {', '.join(failures)}")
            return 1
        print("All live checks passed against the running backend.")
        return 0


if __name__ == "__main__":
    sys.exit(main())