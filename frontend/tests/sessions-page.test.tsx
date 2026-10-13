/**
 * Scenario coverage for the TCP Sessions tool (§23).
 *
 * The state diagram is unit-tested in `tcp-state-diagram.test.tsx`. What is
 * asserted here is the page:
 *
 *  1. With no capture the tool names the tool the capture comes from.
 *  2. A capture that yields no sessions gets an explicit empty state, which
 *     distinguishes "not analysed" from "nothing there".
 *  3. Selecting a session loads what the capture observed — and nothing more:
 *     the diagram and the flags come from the timeline, not from a model.
 *  4. A failed list request is surfaced with a Retry, verbatim.
 */
import { beforeEach, describe, expect, it, vi, type Mock } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useEffect, type ReactNode } from "react";

import SessionsPage from "@/app/sessions/page";
import { WorkspaceProvider, useWorkspace } from "@/hooks/use-workspace";
import { ApiError, api } from "@/lib/api";

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
      listSessions: vi.fn(),
      timeline: vi.fn(),
      diagnostics: vi.fn(),
    },
  };
});

function WithCapture({ children }: { children: ReactNode }) {
  const workspace = useWorkspace();
  useEffect(() => {
    workspace.selectCapture("cap1");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  return <>{children}</>;
}

function renderPage() {
  return render(
    <WorkspaceProvider>
      <WithCapture>
        <SessionsPage />
      </WithCapture>
    </WorkspaceProvider>,
  );
}

const SESSION = {
  id: "sess1",
  // Deliberately not identical to the "client -> server" line rendered under
  // it: the two would otherwise be indistinguishable to a text query.
  session_identity: "TCP conn #1 (SYN seen)",
  client_endpoint: "10.0.0.1:49152",
  server_endpoint: "10.0.0.2:80",
  completeness_status: "complete",
  role_confidence: "high",
  start_time: 1700000000,
  end_time: 1700000002,
};

const TIMELINE = {
  saw_syn: true,
  saw_fin: true,
  saw_rst: false,
  role_confidence: "high",
  role_rationale: "The client sent the first SYN.",
  disclaimer: "Only observed packets are shown.",
  events: [
    {
      packet_index: 0,
      timestamp: 1700000000.1,
      direction: "a2b",
      source: "10.0.0.1",
      destination: "10.0.0.2",
      sequence: 1000,
      acknowledgment: 0,
      flags: 0x02,
      flags_text: "SYN",
      window: 64240,
      payload_length: 0,
      options: null,
    },
    {
      packet_index: 1,
      timestamp: 1700000000.2,
      direction: "b2a",
      source: "10.0.0.2",
      destination: "10.0.0.1",
      sequence: 500,
      acknowledgment: 1001,
      flags: 0x12,
      flags_text: "SYN, ACK",
      window: 28960,
      payload_length: 0,
      options: "MSS 1460",
    },
  ],
};

const DIAGNOSTICS = {
  explanations: {
    retransmission: "The same bytes were sent twice.",
    hole: "Those bytes were never captured.",
    conflict: "Two segments disagreed about a byte.",
    out_of_order: "A segment arrived before its predecessor.",
    zero_window: "The peer asked the sender to stop.",
  },
  streams: [
    {
      stream_id: "stream1",
      direction: "a2b",
      conflict_policy: "prefer_first",
      retransmissions: [{ packet_index: 4 }],
      out_of_order: [],
      duplicates: [],
      zero_windows: [],
      holes: [{ start: 40, end: 44, reason: "not captured" }],
      conflicts: [],
    },
  ],
};

beforeEach(() => {
  vi.clearAllMocks();
  window.localStorage.clear();
  (api.health as Mock).mockResolvedValue({ status: "ok" });
  (api.listSessions as Mock).mockResolvedValue({ items: [SESSION], total: 1 });
  (api.timeline as Mock).mockResolvedValue(TIMELINE);
  (api.diagnostics as Mock).mockResolvedValue(DIAGNOSTICS);
});

describe("Sessions page", () => {
  it("names the tool a capture comes from", () => {
    render(
      <WorkspaceProvider>
        <SessionsPage />
      </WorkspaceProvider>,
    );
    expect(screen.getByText("No capture selected")).toBeInTheDocument();
    expect(
      screen.getByText(
        "Pick a capture on the Captures page first; TCP sessions are derived from it.",
      ),
    ).toBeInTheDocument();
  });

  it("distinguishes 'no sessions' from 'nothing loaded'", async () => {
    (api.listSessions as Mock).mockResolvedValue({ items: [], total: 0 });
    renderPage();
    expect(await screen.findByText("No TCP sessions")).toBeInTheDocument();
    expect(
      screen.getByText("This capture has not been analysed, or contains no TCP traffic."),
    ).toBeInTheDocument();
  });

  it("surfaces a list failure with the server's message and a retry", async () => {
    (api.listSessions as Mock).mockRejectedValue(
      new ApiError(500, "internal_error", "capture unreadable"),
    );
    renderPage();
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("capture unreadable");
    expect(screen.getByRole("button", { name: "Retry" })).toBeInTheDocument();
  });

  it("asks for a session before showing a diagram", async () => {
    renderPage();
    expect(await screen.findByText("Select a session")).toBeInTheDocument();
    expect(screen.queryByText("Observed state diagram")).not.toBeInTheDocument();
  });

  it("shows the observed timeline and diagnostics for a selected session", async () => {
    renderPage();

    const row = await screen.findByText("TCP conn #1 (SYN seen)");
    await userEvent.click(row);

    expect(api.timeline).toHaveBeenCalledWith("sess1");
    expect(api.diagnostics).toHaveBeenCalledWith("sess1");

    expect(await screen.findByText("Observed state diagram")).toBeInTheDocument();
    // The observed packets, not a reconstruction of either stack.
    expect(screen.getByText("SYN", { selector: "td" })).toBeInTheDocument();
    expect(screen.getByText("SYN, ACK", { selector: "td" })).toBeInTheDocument();
    expect(screen.getByText("MSS 1460")).toBeInTheDocument();

    // Diagnostics report what they found, including a gap, with the record.
    expect(await screen.findByText("retransmissions")).toBeInTheDocument();
    expect(screen.getByText("gap 40..44 (not captured)")).toBeInTheDocument();
    expect(screen.getByText("conflict policy: prefer_first")).toBeInTheDocument();
  });
});
