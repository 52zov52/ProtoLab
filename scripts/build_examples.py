"""Build the example artefacts under ``examples/`` (§31 п.9–14).

This turns the "Термостенд" sample into the set of things a reviewer can open
and reproduce, using only the public API:

    examples/thermostand.mplab               portable project archive
    examples/thermostand_spec.json           the accepted specification (machine-readable)
    examples/thermostand_rejected_spec.json  the plausible-but-wrong rule
    examples/thermostand_counterexamples.json what the wrong rule contradicted itself on
    examples/thermostand_application.json    the accepted rule applied to a new record
    examples/thermostand_report.md           final report (Markdown)
    examples/thermostand_report.json         final report (JSON)
    examples/README.md                        what each artefact is

Every claim in the generated README comes from the run that produced it: the
script asserts the corrected rule has no failures and the wrong rule *does*
produce counterexamples, and refuses to write a misleading example otherwise.

Run from the repository root::

    python scripts/build_examples.py
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

SAMPLE = ROOT / "sample_protocol"
BASELINE = SAMPLE / "research" / "01_configuration.pcap"
ADDITIONAL = SAMPLE / "additional" / "04_new_observations.pcapng"

# Opcodes at byte 7, correlated by hand with ``action_journal.csv``: the nine
# requests in session s1 read read-config, set-config, read-values, ... in that
# exact order and the wire opcodes follow the same rhythm (0x10, 0x20, 0x30).
# Any opcode the corpus does not show still validates; it just stays unnamed.
OPCODE_NAMES = {0x10: "read_config", 0x20: "set_config", 0x30: "read_values"}


def opcode_label(value: int) -> str:
    return OPCODE_NAMES.get(value, f"opcode_0x{value:02x}")


def build_spec(framing_config: dict, opcodes: list[int], *, wrong: bool) -> dict:
    """The Термостенд layout as an interpretation.

    The wrong variant differs in the single field the docs call out as the most
    often mis-guessed: whether the declared length counts the header.  Everything
    else is identical, so the counterexamples point at that one decision.
    """
    length_field: dict = {
        "offset": int(framing_config["length_offset"]),
        "size": int(framing_config["length_size"]),
        "endianness": framing_config["endianness"],
        "includes_header": True if wrong else False,
    }
    if not wrong and framing_config.get("header_size") is not None:
        length_field["header_size"] = int(framing_config["header_size"])

    enum_values = {str(code): opcode_label(code) for code in opcodes}
    return {
        "schema_version": "1.0",
        "protocol_name": "Thermostand",
        "description": (
            "Two-byte magic 0xA65C, a big-endian payload length that counts only "
            "the payload, a request id, a flags byte and a command byte; the fixed "
            "header is 8 bytes. Wrong variant: the length is read as if it counted "
            "the header, which the corpus contradicts."
            if wrong
            else "Two-byte magic 0xA65C, a big-endian payload length that counts only "
            "the payload, a request id, a flags byte and a command byte; the fixed "
            "header is 8 bytes, so total = 8 + payload_length. Recovered from "
            "sample_protocol/research/01_configuration.pcap."
        ),
        "framing": {
            "method": "length_prefix",
            "length_field": length_field,
        },
        "fields": [
            {
                "name": "magic",
                "kind": "uint16",
                "offset": 0,
                "size": 2,
                "endianness": "big",
                "semantic_status": "observed",
                "description": "Constant 0xA65C on every message; a strong boundary signal.",
                "constraint": {
                    "kind": "constant",
                    "value": 0xA65C,
                    "description": "The device always sends 0xA65C here.",
                },
            },
            {
                "name": "payload_length",
                "kind": "uint16",
                "offset": 2,
                "size": 2,
                "endianness": "big",
                "semantic_status": "observed",
                "description": "Bytes of payload after the 8-byte header.",
            },
            {
                "name": "request_id",
                "kind": "uint16",
                "offset": 4,
                "size": 2,
                "endianness": "big",
                "semantic_status": "hypothesis",
                "description": "Increments across a session; echoed so pairs can be correlated.",
            },
            {
                "name": "flags",
                "kind": "uint8",
                "offset": 6,
                "size": 1,
                "semantic_status": "unknown",
                "description": "Observed values 0x00/0x01; meaning not established from the bytes alone.",
            },
            {
                "name": "command",
                "kind": "enum",
                "offset": 7,
                "size": 1,
                "semantic_status": "hypothesis",
                "description": "Operation selector. Names correlate the opcodes with action_journal.csv.",
                "values": enum_values,
            },
        ],
        "message_types": [
            {
                "name": opcode_label(code),
                "when": {"field": "command", "operator": "equals", "value": {"raw": code}},
            }
            for code in opcodes
        ],
    }


def upload(client, project_id: str, path: Path) -> dict:
    with path.open("rb") as handle:
        response = client.post(
            "/api/captures",
            data={"project_id": project_id, "name": path.name},
            files={"file": (path.name, handle, "application/octet-stream")},
        )
    assert response.status_code == 201, response.text
    return response.json()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=ROOT / "examples")
    args = parser.parse_args()

    if not BASELINE.exists():
        print(f"the sample capture is missing: {BASELINE}", file=sys.stderr)
        return 2

    out = args.out
    out.mkdir(parents=True, exist_ok=True)
    workdir = Path(tempfile.mkdtemp(prefix="mplab-examples-"))

    try:
        from fastapi.testclient import TestClient

        from app.api.main import create_app
        from app.core.config import Settings

        app = create_app(Settings(data_dir=workdir / "data"))
        context = app.state.context

        with TestClient(app, base_url="http://testserver") as client:
            project = client.post(
                "/api/projects", json={"name": "Thermostand example"}
            ).json()
            pid = project["id"]

            baseline = upload(client, pid, BASELINE)
            client.post(f"/api/captures/{baseline['id']}/analyze", json={})

            # 1. Let the app propose the framing; do not seed it.
            sessions = client.get(f"/api/captures/{baseline['id']}/sessions").json()["items"]
            streams = client.get(f"/api/sessions/{sessions[0]['id']}/streams").json()
            streams = streams["items"] if isinstance(streams, dict) else streams
            a2b = next(s for s in streams if s["direction"] == "a2b")
            suggestions = client.get(
                f"/api/streams/{a2b['id']}/framing-suggestions"
            ).json()["suggestions"]
            top = suggestions[0]
            assert top["method"] == "length_prefix", top
            framing = {"method": top["method"], "config": dict(top["config"])}
            print(
                "derived framing:",
                f"offset={framing['config']['length_offset']}",
                f"size={framing['config']['length_size']}",
                f"endianness={framing['config']['endianness']}",
                f"includes_header={framing['config']['includes_header']}",
                f"header_size={framing['config'].get('header_size')}",
            )

            # 2. Apply it and read the opcodes actually present.
            client.post(f"/api/captures/{baseline['id']}/analyze", json={"framing": framing})
            messages = client.get(
                f"/api/captures/{baseline['id']}/messages", params={"limit": 1000}
            ).json()
            opcodes: set[int] = set()
            for message in messages["items"]:
                raw = client.get(
                    f"/api/streams/{message['stream_id']}/messages/{message['id']}/hex"
                ).json()["hex"].replace(" ", "")
                opcodes.add(int(raw[14:16], 16))  # byte 7
            ordered_opcodes = sorted(opcodes)
            print("opcodes on the wire:", [hex(c) for c in ordered_opcodes])

            spec = build_spec(framing["config"], ordered_opcodes, wrong=False)
            wrong_spec = build_spec(framing["config"], ordered_opcodes, wrong=True)

            # 3. State the hypothesis and the first (wrong) rule.
            hypothesis = client.post(
                f"/api/projects/{pid}/hypotheses",
                json={
                    "name": "Payload length counts only the payload",
                    "description": (
                        "The 2-byte big-endian field at offset 2 counts only the payload, "
                        "so the total message length is 8 + payload_length."
                    ),
                    "status": "proposed",
                    "scope": {"capture_ids": [baseline["id"]]},
                },
            ).json()
            interpretation = client.post(
                f"/api/projects/{pid}/interpreters",
                json={
                    "name": "Thermostand message layout",
                    "specification": wrong_spec,
                    "hypothesis_id": hypothesis["id"],
                },
            ).json()
            run_wrong = client.post(
                f"/api/projects/{pid}/interpreters/{interpretation['id']}/validate",
                json={"capture_ids": [baseline["id"]]},
            ).json()
            counterexamples = client.get(
                f"/api/validation-runs/{run_wrong['run_id']}/counterexamples"
            ).json()
            print(
                f"wrong rule: verdict={run_wrong['verdict']} "
                f"failed={run_wrong['failed']} counterexamples={counterexamples['count']}"
            )
            if counterexamples["count"] < 1:
                raise SystemExit("the wrong rule produced no counterexamples; refusing to write it")

            # 4. Correct it and re-validate.
            fixed = client.put(
                f"/api/projects/{pid}/interpreters/{interpretation['id']}",
                json={"specification": spec},
            ).json()
            run_fixed = client.post(
                f"/api/projects/{pid}/interpreters/{interpretation['id']}/validate",
                json={"capture_ids": [baseline["id"]]},
            ).json()
            print(
                f"fixed rule: verdict={run_fixed['verdict']} "
                f"matched={run_fixed['matched']} failed={run_fixed['failed']}"
            )
            if run_fixed["failed"] != 0:
                raise SystemExit("the corrected rule still fails; refusing to publish the example")
            client.put(
                f"/api/projects/{pid}/hypotheses/{hypothesis['id']}",
                json={"status": "supported"},
            )

            # 5. Apply the accepted rule to a record it has never seen.
            additional = upload(client, pid, ADDITIONAL)
            client.post(f"/api/captures/{additional['id']}/analyze", json={"framing": framing})
            run_additional = client.post(
                f"/api/projects/{pid}/interpreters/{interpretation['id']}/validate",
                json={"capture_ids": [additional["id"]]},
            ).json()
            print(
                f"additional record: verdict={run_additional['verdict']} "
                f"matched={run_additional['matched']} failed={run_additional['failed']}"
            )

            # 6. Report over the capture and the accepted interpretation.
            report = client.post(
                f"/api/projects/{pid}/reports",
                json={
                    "title": "Термостенд: recovered exchange",
                    "capture_ids": [baseline["id"]],
                    "interpretation_ids": [interpretation["id"]],
                },
            ).json()
            report_md = client.get(f"/api/reports/{report['report_id']}/markdown").text
            report_json = client.get(f"/api/reports/{report['report_id']}/json").text

            # 7. Portable project archive.
            archive = client.post(
                f"/api/projects/{pid}/export", json={"include_captures": True}
            ).json()
            archive_path = (
                context.storage.capture_paths(pid, "archive", "pcap").export_dir
                / archive["archive"]
            )
            assert archive_path.exists(), archive_path

            # 8. Persist the accepted specification exactly as the app exports it.
            exported = client.get(
                f"/api/projects/{pid}/interpreters/{interpretation['id']}"
            ).json()

        # -- write artefacts -------------------------------------------------- #
        shutil.copyfile(archive_path, out / "thermostand.mplab")
        (out / "thermostand_spec.json").write_text(
            json.dumps(exported["specification"], indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        (out / "thermostand_rejected_spec.json").write_text(
            json.dumps(wrong_spec, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        (out / "thermostand_counterexamples.json").write_text(
            json.dumps(counterexamples, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        (out / "thermostand_application.json").write_text(
            json.dumps(run_additional, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        (out / "thermostand_report.md").write_text(report_md, encoding="utf-8")

        raw_report = json.loads(report_json)
        (out / "thermostand_report.json").write_text(
            json.dumps(raw_report, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

        readme = _readme(
            framing=framing,
            opcodes=ordered_opcodes,
            exported=exported,
            run_wrong=run_wrong,
            run_fixed=run_fixed,
            run_additional=run_additional,
            counterexamples=counterexamples,
            archive=archive,
            report=report,
        )
        (out / "README.md").write_text(readme, encoding="utf-8")

        print(f"\nwrote {len(list(out.iterdir()))} files to {out}")
        return 0
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def _readme(
    *,
    framing: dict,
    opcodes: list[int],
    exported: dict,
    run_wrong: dict,
    run_fixed: dict,
    run_additional: dict,
    counterexamples: dict,
    archive: dict,
    report: dict,
) -> str:
    opcode_lines = "\n".join(
        f"| `0x{code:02X}` | `{opcode_label(code)}` |" for code in opcodes
    )
    return f"""# Примеры (§31 п.9–14)

Эти файлы порождены `scripts/build_examples.py` на реальном наборе
`sample_protocol/` (Термостенд). Их можно открыть в приложении и повторить путь
исследователя целиком.

| Файл | Что это | Как открыть |
| --- | --- | --- |
| `thermostand.mplab` | Портируемый архив проекта | `POST /api/projects/import` (или «Import project» в UI) |
| `thermostand_spec.json` | Принятая спецификация, как её экспортирует приложение (с контрольной суммой) | создать интерпретацию из этого JSON |
| `thermostand_rejected_spec.json` | Правдоподобный, но неверный вариант правила | создать интерпретацию и запустить проверку |
| `thermostand_counterexamples.json` | Контрпримеры, которые неверное правило породило на корпусе | открыть по `run_id` из файла |
| `thermostand_application.json` | Применение принятого правила к записи, которой оно не видело | `POST /api/interpreters/{{id}}/validate` |
| `thermostand_report.md` | Итоговый отчёт (Markdown) | открыть текстом или через `/api/reports/{{id}}/markdown` |
| `thermostand_report.json` | Тот же отчёт в JSON | `/api/reports/{{id}}/json` |

## Что было выведено из байтов

Обрамление предложено приложением, а не задано заранее:

- `length_offset = {framing['config']['length_offset']}`
- `length_size = {framing['config']['length_size']}`
- `endianness = {framing['config']['endianness']}`
- `includes_header = {framing['config']['includes_header']}`
- `header_size = {framing['config'].get('header_size')}`

Коды операций на проводе:

| Байт 7 | Имя (гипотеза) |
| --- | --- |
{opcode_lines}

Имена соотнесены с `action_journal.csv`: девять запросов сессии `s1` идут как
`read-config`, `set-config`, `read-values`, … а опкоды на проводе повторяют этот
ритм (0x10, 0x20, 0x30). Это **гипотеза**, отмеченная в спецификации как
`semantic_status: hypothesis`.

## Проверка на корпусе

- Неверное правило (`includes_header: true`): вердикт `{run_wrong['verdict']}`,
  провалов `{run_wrong['failed']}`, контрпримеров `{counterexamples['count']}`.
- Исправленное правило: вердикт `{run_fixed['verdict']}`, совпало
  `{run_fixed['matched']}`, провалов `{run_fixed['failed']}`.
- Применение к новой записи: вердикт `{run_additional['verdict']}`, совпало
  `{run_additional['matched']}`, провалов `{run_additional['failed']}`.

Контрольная сумма принятой спецификации: `{exported.get('checksum', '')}`.
Архив `{archive.get('archive', '')}`. Отчёт `{report.get('report_id', '')}`.

> «Согласуется с корпусом» — утверждение об этом корпусе, а не доказательство
> универсальной корректности. Так это и записано в отчёте.
"""


if __name__ == "__main__":
    raise SystemExit(main())
