"""Performance benchmark for the capture-analysis pipeline (Этап 3, §22/§29).

This is not a mock: it builds a **real** libpcap file with the same generator that
produces ``data/testbench``, then runs the **shipping** :class:`CaptureAnalyzer`
(the code behind ``POST /api/captures/{id}/analyze``) with the same options the
endpoint uses, timing each stage through the analyzer's own progress callback.

It reports, as measured on the machine that runs it:

* generation time and the resulting capture size / packet / session counts;
* wall-clock time per analysis stage (read+decode, packet insert, reassembly +
  persist + frame);
* process peak working set (RSS) and Python peak allocation (``tracemalloc``);
* the latency of the read paths the UI depends on (packet page, session list,
  network graph, report generation).

Nothing is extrapolated: if a number was not measured on this run it is not
printed. Use ``--json`` for machine-readable output.

Typical full-profile run (≈250k packets / ≈1000 sessions)::

    python scripts/benchmark_analysis.py --conversations 1000 --messages 120

Quick sanity run::

    python scripts/benchmark_analysis.py --conversations 50 --messages 40
"""

from __future__ import annotations

import argparse
import ctypes
import gc
import importlib.util
import json
import shutil
import struct
import sys
import tempfile
import time
import tracemalloc
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from fastapi.testclient import TestClient  # noqa: E402

from app.api.main import create_app  # noqa: E402
from app.core.config import Settings  # noqa: E402
from app.services.capture_analysis import AnalysisOptions, CaptureAnalyzer  # noqa: E402


# --------------------------------------------------------------------------- #
# Memory helpers (stdlib only)
# --------------------------------------------------------------------------- #


class _ProcessMemoryCounters(ctypes.Structure):
    _fields_ = [
        ("cb", ctypes.c_ulong),
        ("PageFaultCount", ctypes.c_ulong),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t),
        ("PeakPagefileUsage", ctypes.c_size_t),
    ]


_WIN_MEMORY = None


def _windows_memory() -> tuple[int, int] | None:
    """(working set, peak working set) in bytes on Windows, else ``None``."""
    global _WIN_MEMORY
    if _WIN_MEMORY is None:
        try:
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            psapi = ctypes.WinDLL("psapi", use_last_error=True)
            kernel32.GetCurrentProcess.restype = ctypes.c_void_p
            psapi.GetProcessMemoryInfo.argtypes = [
                ctypes.c_void_p,
                ctypes.POINTER(_ProcessMemoryCounters),
                ctypes.c_ulong,
            ]
            psapi.GetProcessMemoryInfo.restype = ctypes.c_int
            _WIN_MEMORY = (kernel32, psapi)
        except Exception:  # pragma: no cover - defensive
            _WIN_MEMORY = False
    if not _WIN_MEMORY:
        return None
    kernel32, psapi = _WIN_MEMORY
    counters = _ProcessMemoryCounters()
    counters.cb = ctypes.sizeof(counters)
    handle = kernel32.GetCurrentProcess()
    if not psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
        return None
    return int(counters.WorkingSetSize), int(counters.PeakWorkingSetSize)


def working_set_bytes() -> int | None:
    """Current working set (RSS) in bytes, or ``None`` where unavailable."""
    if sys.platform == "win32":
        values = _windows_memory()
        return None if values is None else values[0]
    try:
        import resource

        # ru_maxrss is KiB on Linux, bytes on macOS.
        value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return int(value) * 1024 if sys.platform != "darwin" else int(value)
    except Exception:  # pragma: no cover - platform dependent
        return None


def peak_working_set_bytes() -> int | None:
    if sys.platform == "win32":
        values = _windows_memory()
        return None if values is None else values[1]
    return working_set_bytes()


def human_mib(value: int | None) -> str:
    return "n/a" if value is None else f"{value / (1024 * 1024):.1f} MiB"


# --------------------------------------------------------------------------- #
# Capture generation (reuses the tracked testbench generator)
# --------------------------------------------------------------------------- #


def load_generator():
    spec = importlib.util.spec_from_file_location(
        "bench_generate", ROOT / "tools" / "testbench" / "generate.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses resolve their module via sys.modules
    spec.loader.exec_module(module)
    return module


def build_capture(gen, path: Path, *, conversations: int, messages: int, payload: int) -> dict:
    """Build a real capture with distinct 4-tuples so each conversation is a session."""
    writer = gen.PcapWriter()
    base_clock = 1_767_225_600.0
    client_pool = 20
    server_ip = "192.168.10.5"
    server_port = 9500
    # A small extra body per message raises the capture size toward the profile
    # without changing the protocol shape.
    filler = bytes((i * 37 + 11) & 0xFF for i in range(payload))

    for index in range(conversations):
        client_ip = f"192.168.10.{20 + (index % client_pool)}"
        client_port = 40000 + (index % 20000)
        client, server = gen._hosts(client_ip, server_ip, client_port, server_port)
        conversation = gen.Conversation(writer, client, server)
        conversation.clock = base_clock + index * 2.0
        conversation.handshake()
        for req in range(1, messages + 1):
            # Filler goes *inside* the framed body, so the length prefix still
            # describes the whole message: framing and message counts stay real.
            request = gen.msg(
                gen.TYPE_READ, req, struct.pack(">BH", gen.OP_READ, 0x0001) + filler
            )
            response = gen.msg(
                gen.TYPE_READ,
                req,
                struct.pack(">BIB", gen.OP_VALUE, 1000 + req, gen.STATUS_OK) + filler,
            )
            conversation.send(client, server, request)
            conversation.send(server, client, response)
        conversation.close()

    writer.write(path)
    return {
        "conversations": conversations,
        "messages_per_conversation": messages,
        "packets": len(writer._records),
    }


# --------------------------------------------------------------------------- #
# Benchmark
# --------------------------------------------------------------------------- #


class ProgressRecorder:
    """Record wall-clock time at every progress callback the analyzer emits."""

    def __init__(self) -> None:
        self.started = time.perf_counter()
        self.samples: list[tuple[float, str]] = []

    def __call__(self, fraction: float, label: str) -> None:
        self.samples.append((time.perf_counter() - self.started, f"{fraction:.2f} {label}"))

    def seconds_between(self, first: str, second: str) -> float | None:
        points = [(t, label) for t, label in self.samples if label.startswith(first)]
        marks = [(t, label) for t, label in self.samples if label.startswith(second)]
        if not points or not marks:
            return None
        return marks[0][0] - points[0][0]


def timed(label: str, fn):
    start = time.perf_counter()
    result = fn()
    return result, time.perf_counter() - start


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--conversations", type=int, default=1000)
    parser.add_argument("--messages", type=int, default=120, help="messages per conversation")
    parser.add_argument("--payload", type=int, default=32, help="extra filler bytes per message")
    parser.add_argument("--keep", action="store_true", help="keep the temporary workspace")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of a report")
    args = parser.parse_args()

    gen = load_generator()
    workdir = Path(tempfile.mkdtemp(prefix="mplab-bench-"))
    capture_path = workdir / "large.pcap"
    results: dict[str, object] = {"scale": vars(args).copy()}

    try:
        print(f"Temporary workspace: {workdir}")
        print(
            f"Generating {args.conversations} conversations x {args.messages} messages "
            f"(+{args.payload} filler bytes/message) ..."
        )
        gc.collect()
        build_info, gen_seconds = timed(
            "generate",
            lambda: build_capture(
                gen,
                capture_path,
                conversations=args.conversations,
                messages=args.messages,
                payload=args.payload,
            ),
        )
        size_bytes = capture_path.stat().st_size
        results["generation_seconds"] = round(gen_seconds, 3)
        results["capture_bytes"] = size_bytes
        results["packets"] = build_info["packets"]
        print(
            f"  generated in {gen_seconds:.1f}s, {human_mib(size_bytes)}, "
            f"{build_info['packets']} packets"
        )

        settings = Settings(data_dir=workdir / "data")
        app = create_app(settings)
        context = app.state.context

        with TestClient(app, base_url="http://testserver") as client:
            project = client.post("/api/projects", json={"name": "Benchmark"}).json()

            def upload():
                with capture_path.open("rb") as handle:
                    return client.post(
                        "/api/captures",
                        data={"project_id": project["id"], "name": "large.pcap"},
                        files={"file": ("large.pcap", handle, "application/octet-stream")},
                    ).json()

            capture, upload_seconds = timed("upload", upload)
            results["upload_seconds"] = round(upload_seconds, 3)
            print(f"  uploaded in {upload_seconds:.1f}s as capture {capture['id']}")

            # --- the real analyzer, same options as the endpoint -------------- #
            session = context.open_session()
            from app.models import Capture  # local import keeps module import cheap

            capture_row = session.get(Capture, capture["id"])
            # The framing rule the analyst derives for this protocol (2-byte
            # big-endian length that counts itself, 5-byte header). Passing it
            # means the run also exercises message framing and persistence.
            framing = {
                "method": "length_prefix",
                "config": {
                    "length_offset": 0,
                    "length_size": 2,
                    "endianness": "big",
                    "includes_header": "true",
                    "max_length": 65535,
                },
            }
            options = AnalysisOptions(
                flow_policy="syn_fin_rst_idle",
                framing=framing,
                detect_protocol=True,
                max_sessions=settings.limits.max_tcp_sessions_per_capture,
                max_messages_per_stream=settings.limits.max_messages_per_stream,
            )

            gc.collect()
            baseline_rss = working_set_bytes()
            tracemalloc.start()
            recorder = ProgressRecorder()
            analyzer = CaptureAnalyzer(
                session,
                capture_row,
                context.storage.capture_paths(
                    capture_row.project_id, capture_row.id, capture_row.format
                ).original,
                context.storage,
                options,
                settings.limits,
                progress=recorder,
            )
            recorder.started = time.perf_counter()
            summary = analyzer.run()
            analysis_seconds = time.perf_counter() - recorder.started
            _, python_peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            peak_rss = peak_working_set_bytes()
            session.close()

            def at(prefix: str) -> float | None:
                for timestamp, label in recorder.samples:
                    if label.startswith(prefix):
                        return timestamp
                return None

            stages: dict[str, float] = {}
            t_read, t_index, t_reconstruct = at("0.05"), at("0.40"), at("0.55")
            if t_read is not None and t_index is not None:
                stages["read_and_decode_packets"] = round(t_index - t_read, 3)
            if t_index is not None and t_reconstruct is not None:
                stages["insert_packets"] = round(t_reconstruct - t_index, 3)
            if t_reconstruct is not None:
                stages["reconstruct_and_frame"] = round(analysis_seconds - t_reconstruct, 3)
            results["stage_seconds"] = stages
            results["analysis_seconds"] = round(analysis_seconds, 3)
            results["analysis_summary"] = {k: summary[k] for k in ("sessions", "streams", "messages")}
            results["rss_after_analysis"] = peak_rss
            results["python_peak_bytes"] = python_peak
            print(
                f"  analysed in {analysis_seconds:.1f}s: "
                f"{summary['sessions']} sessions, {summary['streams']} streams, "
                f"{summary['messages']} messages"
            )
            print(
                f"  peak RSS {human_mib(peak_rss)} "
                f"(baseline {human_mib(baseline_rss)}), "
                f"Python peak {human_mib(python_peak)}"
            )

            # --- read paths the UI depends on -------------------------------- #
            reads: dict[str, float] = {}

            def time_read(name: str, fn) -> None:
                start = time.perf_counter()
                response = fn()
                reads[name] = round((time.perf_counter() - start) * 1000, 1)
                assert response.status_code == 200, (
                    name,
                    response.status_code,
                    response.text[:200],
                )

            time_read(
                "packets_page_1000",
                lambda: client.get(
                    f"/api/captures/{capture['id']}/packets", params={"limit": 1000}
                ),
            )
            time_read(
                "sessions_list",
                lambda: client.get(f"/api/captures/{capture['id']}/sessions"),
            )
            time_read(
                "network_graph",
                lambda: client.post(
                    "/api/network/graph",
                    json={"capture_ids": [capture["id"]], "include_centrality": False},
                ),
            )
            time_read(
                "report_generate",
                lambda: client.post(
                    f"/api/projects/{project['id']}/reports",
                    json={"title": "Benchmark report", "capture_ids": [capture["id"]]},
                ),
            )
            results["read_paths_ms"] = reads

        results["peak_rss_bytes"] = peak_working_set_bytes()

        if args.json:
            print(json.dumps(results, indent=2, default=str))
        else:
            print("\nAnalysis stages (wall clock):")
            for name, seconds in results["stage_seconds"].items():  # type: ignore[union-attr]
                print(f"  {name:<24} {seconds:>8.2f} s")
            print("\nRead-path latency (server-side, one request each):")
            for name, ms in results["read_paths_ms"].items():  # type: ignore[union-attr]
                print(f"  {name:<20} {ms:>8.1f} ms")
        return 0
    finally:
        if not args.keep:
            shutil.rmtree(workdir, ignore_errors=True)
        else:
            print(f"Kept workspace: {workdir}")


if __name__ == "__main__":
    raise SystemExit(main())
