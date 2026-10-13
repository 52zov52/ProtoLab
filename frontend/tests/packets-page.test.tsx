/**
 * Scenario coverage for the Packets tool (§23).
 *
 * The table itself is unit-tested in `packet-table.test.tsx`; what is asserted
 * here is the page an analyst actually uses:
 *
 *  1. With no capture the tool says which tool to open, not an empty table.
 *  2. A failed list request is surfaced with a Retry, verbatim.
 *  3. Clicking a row fetches that packet's original bytes and shows them, so a
 *     displayed value can always be traced to the captured file.
 *  4. A filter becomes part of the request rather than a client-side illusion.
 */
import { beforeEach, describe, expect, it, vi, type Mock } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useEffect, type ReactNode } from "react";

import PacketsPage from "@/app/packets/page";
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
      listPackets: vi.fn(),
      packetBytes: vi.fn(),
    },
  };
});

function packet(index: number, payload: number): Record<string, unknown> {
  return {
    packet_index: index,
    timestamp: 1700000000.5,
    captured_length: 64 + payload,
    original_length: 64 + payload,
    source_address: "10.0.0.1",
    destination_address: "10.0.0.2",
    source_port: 49152,
    destination_port: 80,
    transport_protocol: "TCP",
    tcp_sequence: 1000 * index,
    tcp_acknowledgment: 500,
    tcp_flags: 0x18,
    tcp_window: 64240,
    payload_length: payload,
    truncated: false,
    session_id: "sess1",
  };
}

/** Selects a capture the way the Capture picker does. */
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
        <PacketsPage />
      </WithCapture>
    </WorkspaceProvider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  window.localStorage.clear();
  (api.health as Mock).mockResolvedValue({ status: "ok" });
  (api.listPackets as Mock).mockResolvedValue({
    items: [packet(0, 4), packet(1, 0)],
    total: 2,
    offset: 0,
    limit: 250,
  });
  (api.packetBytes as Mock).mockResolvedValue(new Uint8Array([1, 2, 3, 4]));
});

describe("Packets page", () => {
  it("names the tool to open when no capture is selected", () => {
    render(
      <WorkspaceProvider>
        <PacketsPage />
      </WorkspaceProvider>,
    );
    expect(screen.getByText("No capture selected")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Go to Captures" })).toBeInTheDocument();
  });

  it("surfaces a list failure with the server's message and a retry", async () => {
    (api.listPackets as Mock).mockRejectedValue(
      new ApiError(500, "internal_error", "capture file missing"),
    );
    renderPage();
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("capture file missing");
    expect(screen.getByRole("button", { name: "Retry" })).toBeInTheDocument();
  });

  it("fetches the original bytes of a packet that is clicked", async () => {
    renderPage();
    const row = await screen.findByTitle("Packet #0");
    await userEvent.click(row);

    expect(api.packetBytes).toHaveBeenCalledWith("cap1", 0);
    expect(await screen.findByText("Packet #0 · 4 byte(s)")).toBeInTheDocument();
  });

  it("puts the transport filter into the request it makes", async () => {
    renderPage();
    await screen.findByTitle("Packet #0");

    await userEvent.selectOptions(screen.getByRole("combobox"), "TCP");

    await vi.waitFor(() =>
      expect(api.listPackets).toHaveBeenCalledWith(
        "cap1",
        expect.stringContaining("transport=TCP"),
      ),
    );
  });

  it("says so when the filters match nothing, instead of showing a blank table", async () => {
    (api.listPackets as Mock).mockResolvedValue({
      items: [],
      total: 0,
      offset: 0,
      limit: 250,
    });
    renderPage();
    expect(
      await screen.findByText("No packets match the current filters."),
    ).toBeInTheDocument();
  });
});
