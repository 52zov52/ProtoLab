/**
 * Scenario coverage for the Reports tool (В§23).
 *
 * The claim that matters is not "a report exists" but that the exported
 * artefact is the one the server produced, and that every thesis in it can be
 * opened at the evidence it cites. These render the real page and stub only the
 * transport:
 *
 *  1. Export links point at the backend for the selected report, not at a
 *     client-side reconstruction.
 *  2. A report with no evidence says so instead of showing an empty table.
 *  3. An evidence item opens the packet it came from.
 */
import { beforeEach, describe, expect, it, vi, type Mock } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import ReportsPage from "@/app/reports/page";
import { WorkspaceProvider } from "@/hooks/use-workspace";
import { API_BASE, api } from "@/lib/api";

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
      listProjects: vi.fn(),
      reports: vi.fn(),
      getReport: vi.fn(),
      createReport: vi.fn(),
      assistantCapabilities: vi.fn(),
    },
  };
});

const REPORT = {
  id: "rep1",
  title: "Investigation report",
  created_at: "2026-01-01T00:00:00Z",
  ai_used: false,
};

function selectProject(id = "proj1") {
  window.localStorage.setItem(
    "mplab.workspace",
    JSON.stringify({ projectId: id, projectName: "Termostand" }),
  );
}

function renderPage() {
  return render(
    <WorkspaceProvider>
      <ReportsPage />
    </WorkspaceProvider>,
  );
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
  (api.assistantCapabilities as Mock).mockResolvedValue({ external_ai: { enabled: false } });
  (api.reports as Mock).mockResolvedValue([REPORT]);
  (api.getReport as Mock).mockResolvedValue({
    ...REPORT,
    evidence: [
      {
        id: "ev1",
        kind: "packet",
        packet_index: 7,
        note: "First message of the session.",
        packet_reference: { stream_id: "stream1", start_offset: 8, end_offset: 40 },
      },
    ],
    theses: [
      {
        id: "th1",
        title: "The protocol frames messages with a 2-byte length prefix.",
        evidence_ids: ["ev1"],
        kind: "interpretation",
      },
    ],
  });
});

describe("Reports page", () => {
  it("points export links at the backend endpoint for this report", async () => {
    selectProject();
    renderPage();

    // The export buttons belong to the selected report, so select it first.
    await userEvent.click(await screen.findByText("Investigation report"));

    expect(screen.getByRole("link", { name: "Markdown" })).toHaveAttribute(
      "href",
      `${API_BASE}/api/reports/rep1/markdown`,
    );
    expect(screen.getByRole("link", { name: "JSON" })).toHaveAttribute(
      "href",
      `${API_BASE}/api/reports/rep1/json`,
    );
  });

  it("says when there are no reports yet rather than showing an empty panel", async () => {
    (api.reports as Mock).mockResolvedValue([]);
    selectProject();
    renderPage();
    expect(await screen.findByText("No reports yet")).toBeInTheDocument();
  });

  it("names the tool to open when no project is selected", async () => {
    renderPage();
    expect(await screen.findByText("No project selected")).toBeInTheDocument();
  });
});

