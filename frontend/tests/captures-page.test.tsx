/**
 * Scenario coverage for the Captures tool (§23).
 *
 * These render the real page inside the real workspace provider and stub only
 * the transport (`@/lib/api`).  The assertions encode promises an analyst
 * depends on:
 *
 *  1. With no project selected the tool says so, instead of showing an empty
 *     list that looks like "no data".
 *  2. A project with no captures gets an explicit empty state, not a blank panel.
 *  3. A failed list request is surfaced verbatim with a Retry, not swallowed.
 *  4. A rejected import tells the analyst why.
 */
import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import CapturesPage from "@/app/captures/page";
import { WorkspaceProvider } from "@/hooks/use-workspace";
import { ApiError, api } from "@/lib/api";

vi.mock("next/navigation", () => ({
  useSearchParams: () => new URLSearchParams(),
}));

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return {
    ...actual,
    api: {
      health: vi.fn(),
      metrics: vi.fn(),
      projectCaptures: vi.fn(),
      listSessions: vi.fn(),
      getCapture: vi.fn(),
      importCapture: vi.fn(),
      analyze: vi.fn(),
      analyzeAsync: vi.fn(),
      deleteCapture: vi.fn(),
    },
  };
});

const METRICS = {
  project_id: "proj1",
  captures: 0,
  packets: 0,
  tcp_sessions: 0,
  streams: 0,
  messages: 0,
  hypotheses: 0,
  interpretations: 0,
  validation_runs: 0,
  counterexamples: 0,
  sessions_with_reconstruction_problems: 0,
  bytes_stored: 0,
  analyst_versions: {},
};

function selectProject(id = "proj1") {
  window.localStorage.setItem(
    "mplab.workspace",
    JSON.stringify({ projectId: id, projectName: "Demo" }),
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  window.localStorage.clear();
  (api.health as Mock).mockResolvedValue({ status: "ok" });
  (api.metrics as Mock).mockResolvedValue(METRICS);
  (api.projectCaptures as Mock).mockResolvedValue([]);
  (api.listSessions as Mock).mockResolvedValue([]);
  (api.getCapture as Mock).mockResolvedValue(null);
});

afterEach(() => {
  window.localStorage.clear();
});

function renderPage() {
  return render(
    <WorkspaceProvider>
      <CapturesPage />
    </WorkspaceProvider>,
  );
}

describe("Captures page", () => {
  it("asks the analyst to pick a project when none is selected", async () => {
    renderPage();
    expect(await screen.findByText("No project selected")).toBeInTheDocument();
  });

  it("shows an explicit empty state instead of a blank list", async () => {
    selectProject();
    renderPage();
    expect(await screen.findByText("No captures yet")).toBeInTheDocument();
  });

  it("surfaces a list failure with the server's message and a retry", async () => {
    selectProject();
    (api.projectCaptures as Mock).mockRejectedValue(
      new ApiError(500, "internal_error", "connection refused"),
    );
    renderPage();
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("connection refused");
    expect(screen.getByRole("button", { name: "Retry" })).toBeInTheDocument();
  });

  it("reports why an import failed", async () => {
    selectProject();
    (api.importCapture as Mock).mockRejectedValue(new Error("file too large"));
    const { container } = renderPage();

    const input = container.querySelector('input[type="file"]') as HTMLInputElement;
    const file = new File([new Uint8Array([1, 2, 3])], "x.pcap", {
      type: "application/octet-stream",
    });
    await userEvent.upload(input, file);

    expect(await screen.findByText("file too large")).toBeInTheDocument();
  });
});
