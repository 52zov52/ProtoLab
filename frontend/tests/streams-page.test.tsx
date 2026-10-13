/**
 * Scenario coverage for the Stream Explorer (§23).
 *
 * Two promises this tool makes and must not quietly break:
 *
 *  1. A hole is shown as a hole. The bytes that were never captured are never
 *     replaced with zeros, and the tool says they are unrecoverable.
 *  2. Hiding a protocol label removes the stream from the selector, but it
 *     removes nothing from the data — the label is a view preference.
 */
import { beforeEach, describe, expect, it, vi, type Mock } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useEffect, type ReactNode } from "react";

import StreamsPage from "@/app/streams/page";
import { ProtocolFilterProvider } from "@/hooks/use-protocol-filter";
import { WorkspaceProvider, useWorkspace } from "@/hooks/use-workspace";
import { api } from "@/lib/api";

vi.mock("next/navigation", () => ({
  useSearchParams: () => new URLSearchParams(),
  useRouter: () => ({ push: vi.fn() }),
}));

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return {
    ...actual,
    api: {
      health: vi.fn(),
      getProject: vi.fn(),
      updateProject: vi.fn(),
      getSession: vi.fn(),
      sessionStreams: vi.fn(),
      listMessages: vi.fn(),
      streamBytes: vi.fn(),
      framingSuggestions: vi.fn(),
      tlsFingerprints: vi.fn(),
      analyze: vi.fn(),
    },
  };
});

function WithSession({ children }: { children: ReactNode }) {
  const workspace = useWorkspace();
  useEffect(() => {
    // Project first: selecting a session clears the project-derived state.
    workspace.selectProject("proj1", "Termostand");
    workspace.selectSession("sess1");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  return <>{children}</>;
}

function renderPage() {
  return render(
    <WorkspaceProvider>
      <ProtocolFilterProvider>
        <WithSession>
          <StreamsPage />
        </WithSession>
      </ProtocolFilterProvider>
    </WorkspaceProvider>,
  );
}

function stream(id: string, label: string) {
  return {
    id,
    session_id: "sess1",
    direction: "a2b",
    local_endpoint: "10.0.0.1:49152",
    remote_endpoint: "10.0.0.2:80",
    protocol_label: label,
    protocol_confidence: 0.5,
    present_bytes: 40,
    stream_length: 44,
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  window.localStorage.clear();
  (api.health as Mock).mockResolvedValue({ status: "ok" });
  (api.getProject as Mock).mockResolvedValue({
    id: "proj1",
    name: "Termostand",
    description: "",
    schema_version: 1,
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
    settings: {},
  });
  (api.updateProject as Mock).mockResolvedValue({});
  (api.sessionStreams as Mock).mockResolvedValue([stream("stream1", "tls")]);
  (api.streamBytes as Mock).mockResolvedValue({
    lines: [
      { offset: 0, hex: ["45", "00"], ascii: ["E."], length: 2 },
      { offset: 16, hex: ["ff", "12"], ascii: [".."], length: 2 },
    ],
    holes: [{ start: 4, end: 8, length: 4, reason: "not captured" }],
    packet_references: [{ packet_index: 0, start_offset: 0, end_offset: 4 }],
    present_bytes: 40,
    stream_length: 44,
  });
  (api.framingSuggestions as Mock).mockResolvedValue({ suggestions: [], disclaimer: "" });
  (api.tlsFingerprints as Mock).mockResolvedValue({ handshakes: [], interpretation_note: "" });
  (api.listMessages as Mock).mockResolvedValue({ items: [], total: 0 });
  (api.analyze as Mock).mockResolvedValue({});
});

describe("Streams page", () => {
  it("names the tool a session comes from", () => {
    render(
      <WorkspaceProvider>
        <ProtocolFilterProvider>
          <StreamsPage />
        </ProtocolFilterProvider>
      </WorkspaceProvider>,
    );
    expect(screen.getByText("No TCP session selected")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Go to TCP Sessions" })).toBeInTheDocument();
  });

  it("shows a coverage gap as a gap and says it cannot be recovered", async () => {
    renderPage();
    expect(await screen.findByText("Coverage gaps")).toBeInTheDocument();
    expect(screen.getByText("4 … 8 (4 bytes)")).toBeInTheDocument();
    expect(
      screen.getByText(
        "These bytes were never captured. They are not recoverable from this file, and nothing in the analysis substitutes a guess for them.",
      ),
    ).toBeInTheDocument();
  });

  it("hides a label the analyst hid, without removing the data", async () => {
    // The preference is stored on the project and is a view choice only.
    (api.getProject as Mock).mockResolvedValue({
      id: "proj1",
      name: "Termostand",
      description: "",
      schema_version: 1,
      created_at: "2026-01-01T00:00:00Z",
      updated_at: "2026-01-01T00:00:00Z",
      settings: { hidden_protocols: ["tls"] },
    });

    renderPage();

    expect(
      await screen.findByText("All streams are hidden by the protocol filter."),
    ).toBeInTheDocument();
    // Nothing was deleted: the data is still reachable by showing the label.
    expect(api.streamBytes).not.toHaveBeenCalled();

    await userEvent.click(screen.getByRole("button", { name: "Show all" }));

    expect(api.updateProject).toHaveBeenCalledWith(
      "proj1",
      expect.objectContaining({ settings: { hidden_protocols: [] } }),
    );
    await screen.findByText("protocol: tls (0.50)");
  });

  it("lists every protocol label present as a toggle", async () => {
    (api.sessionStreams as Mock).mockResolvedValue([
      stream("stream1", "tls"),
      stream("stream2", "http1"),
    ]);
    renderPage();
    const toggles = await screen.findAllByTitle("Hide this protocol");
    expect(toggles).toHaveLength(2);
  });
});
