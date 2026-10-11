"""Exploratory: import the sample_protocol captures and print what the app derives.

Run from the repository root:
    python scripts/explore_sample_protocol.py
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
SAMPLE = ROOT / "sample_protocol"


def main() -> int:
    data_dir = Path(tempfile.mkdtemp(prefix="mplab-explore-"))
    os.environ["MPLAB_DATA_DIR"] = str(data_dir)
    try:
        from app.core.config import reset_settings

        reset_settings()
        from app.api.main import create_app
        from app.core.config import Settings

        app = create_app(Settings(data_dir=data_dir))
        from fastapi.testclient import TestClient

        with TestClient(app, base_url="http://testserver") as client:
            project = client.post("/api/projects", json={"name": "Термостенд"}).json()
            pid = project["id"]

            for rel in [
                "research/01_configuration.pcap",
                "research/02_variations.pcapng",
                "research/03_combined_messages.pcap",
                "additional/04_new_observations.pcapng",
            ]:
                path = SAMPLE / rel
                with path.open("rb") as handle:
                    response = client.post(
                        "/api/captures",
                        data={"project_id": pid, "name": path.name},
                        files={"file": (path.name, handle, "application/octet-stream")},
                    )
                assert response.status_code == 201, response.text
                capture = response.json()
                analysis = client.post(
                    f"/api/captures/{capture['id']}/analyze", json={}
                )
                print("=" * 78)
                print(f"CAPTURE {rel}  analyze={analysis.status_code}")
                print(json.dumps(analysis.json(), indent=2, ensure_ascii=False)[:2000])

                sessions = client.get(f"/api/captures/{capture['id']}/sessions").json()
                for s in sessions["items"]:
                    sid = s["id"]
                    streams = client.get(f"/api/sessions/{sid}/streams").json()
                    if isinstance(streams, dict):
                        streams = streams.get("items", [])
                    print(f"  session {s['session_identity']} {s['endpoint_a']}<->{s['endpoint_b']} "
                          f"complete={s['completeness_status']} role={s['role_confidence']} "
                          f"diag={json.dumps(s.get('diagnostics'), ensure_ascii=False)[:200]}")
                    for st in streams:
                        stid = st["id"]
                        sug = client.get(f"/api/streams/{stid}/framing-suggestions").json()
                        print(f"    stream {st['direction']} len={st['stream_length']} "
                              f"present={st['present_bytes']} proto={st.get('protocol_label')}")
                        for cand in (sug.get("suggestions") or [])[:3]:
                            print(f"      cand score={cand['score']:.3f} {cand['method']} {cand['config']} {cand.get('evidence')}")

            # Try the top framing candidate of the first stream and show messages.
            captures = client.get(f"/api/projects/{pid}/captures").json()
            cap = captures[0]
            sessions = client.get(f"/api/captures/{cap['id']}/sessions").json()
            if sessions["items"]:
                sid = sessions["items"][0]["id"]
                streams = client.get(f"/api/sessions/{sid}/streams").json()
                if isinstance(streams, dict):
                    streams = streams.get("items", [])
                items = streams
                if items:
                    stid = items[0]["id"]
                    sug = client.get(f"/api/streams/{stid}/framing-suggestions").json()
                    top = (sug.get("suggestions") or [None])[0]
                    if top:
                        print("=" * 78)
                        print("APPLY TOP FRAMING:", top["method"], top["config"])
                        client.post(
                            f"/api/captures/{cap['id']}/analyze",
                            json={"framing": {"method": top["method"], "config": top["config"]}},
                        )
                        msgs = client.get(f"/api/captures/{cap['id']}/messages?limit=40").json()
                        print("messages:", msgs["total"])
                        for m in msgs["items"][:20]:
                            hx = client.get(f"/api/streams/{m['stream_id']}/messages/{m['id']}/hex").json()
                            print(f"  #{m['index_in_stream']:>3} [{m['start_offset']}..{m['end_offset']}] "
                                  f"len={m['present_length']} declared={m['declared_length']} "
                                  f"complete={m['complete']} hex={hx['hex'][:80]}")
                        stats = client.get(f"/api/streams/{stid}/field-statistics").json()
                        print("field candidates:")
                        for c in (stats.get("candidates") or [])[:12]:
                            print(f"  {c['role']:<12} {c['name']:<16} @{c['offset']} {c['size']}B "
                                  f"{c.get('endianness')} conf={c['confidence']:.2f} "
                                  f"support={c.get('support_count')} contra={c.get('contradiction_count')} :: {c['rationale'][:90]}")
    finally:
        shutil.rmtree(data_dir, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
