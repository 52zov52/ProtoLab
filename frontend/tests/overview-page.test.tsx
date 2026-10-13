/**
 * Scenario coverage for the Overview tool's project picker (§23).
 *
 * The Overview is where an analyst lands, so the picker is what keeps the
 * application usable when the selection is wrong, stale or empty. These render
 * the real page and stub only the transport:
 *
 *  1. With no project the tool explains what to open rather than showing zeros.
 *  2. Switching project from the picker becomes the active project, and the
 *     panels ask for *that* project's numbers.
 *  3. Creating a project makes it the active one.
 *  4. Deleting the active project clears the selection instead of leaving the
 *     tool pointing at something the server no longer has.
 */
import { beforeEach, describe, expect, it, vi, type Mock } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import OverviewPage from "@/app/page";
import { WorkspaceProvider } from "@/hooks/use-workspace";
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
      listProjects: vi.fn(),
      createProject: vi.fn(),
      getProject: vi.fn(),
      updateProject: vi.fn(),
      deleteProject: vi.fn(),
      metrics: vi.fn(),
      integrity: vi.fn(),
      anomaliesStatus: vi.fn(),
      projectCaptures: vi.fn(),
      getCapture: vi.fn(),
    },
  };
});

const NAMES: Record<string, string> = {
  proj1: "Termostand",
  proj2: "Modbus gateway",
  proj3: "New investigation",
};

function project(id: string) {
  return {
    id,
    name: NAMES[id] ?? id,
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
    capture_count: 1,
    hypothesis_count: 0,
    interpretation_count: 0,
    message_count: 0,
  };
}

const METRICS = {
  project_id: "proj1",
  captures: 1,
  packets: 2,
  tcp_sessions: 1,
  streams: 2,
  messages: 3,
  hypotheses: 0,
  interpretations: 0,
  validation_runs: 0,
  counterexamples: 0,
  sessions_with_reconstruction_problems: 0,
  bytes_stored: 128,
  analyst_versions: {},
};

function selectProject(id = "proj1") {
  window.localStorage.setItem(
    "mplab.workspace",
    JSON.stringify({ projectId: id, projectName: NAMES[id] ?? id }),
  );
}

function renderPage() {
  return render(
    <WorkspaceProvider>
      <OverviewPage />
    </WorkspaceProvider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  window.localStorage.clear();
  (api.health as Mock).mockResolvedValue({ status: "ok" });
  (api.listProjects as Mock).mockImplementation(() =>
    Promise.resolve([project("proj1"), project("proj2")]),
  );
  // The name comes from the server, not from the id in storage: the picker and
  // the workspace agree on the authoritative value.
  (api.getProject as Mock).mockImplementation((id: string) =>
    Promise.resolve({
      id,
      name: NAMES[id] ?? id,
      description: "",
      schema_version: 1,
      created_at: "2026-01-01T00:00:00Z",
      updated_at: "2026-01-01T00:00:00Z",
      settings: {},
    }),
  );
  (api.createProject as Mock).mockResolvedValue({
    id: "proj3",
    name: NAMES.proj3,
    description: "",
    schema_version: 1,
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
    settings: {},
  });
  (api.deleteProject as Mock).mockResolvedValue(null);
  (api.metrics as Mock).mockResolvedValue(METRICS);
  (api.integrity as Mock).mockResolvedValue({ all_match: true, captures: [] });
  (api.anomaliesStatus as Mock).mockResolvedValue({ available: true });
  (api.projectCaptures as Mock).mockResolvedValue([]);
  (api.getCapture as Mock).mockResolvedValue(null);
});

describe("Overview page", () => {
  it("explains what to open when no project is selected", async () => {
    renderPage();
    expect(await screen.findByText("Start an investigation")).toBeInTheDocument();
    expect(screen.getByText("Investigation project")).toBeInTheDocument();
  });

  it("makes a project picked in the picker the active one", async () => {
    selectProject();
    renderPage();

    await userEvent.click(await screen.findByText("Modbus gateway"));

    await vi.waitFor(() => expect(api.metrics).toHaveBeenCalledWith("proj2"));
    expect(
      JSON.parse(window.localStorage.getItem("mplab.workspace") ?? "{}"),
    ).toMatchObject({ projectId: "proj2", projectName: "Modbus gateway" });
    expect(await screen.findByText("current")).toBeInTheDocument();
  });

  it("makes a newly created project the active one", async () => {
    renderPage();

    await userEvent.type(screen.getByPlaceholderText("Project name"), "New investigation");
    await userEvent.click(screen.getByRole("button", { name: "Create project" }));

    expect(api.createProject).toHaveBeenCalledWith("New investigation", "");
    await vi.waitFor(() => expect(api.metrics).toHaveBeenCalledWith("proj3"));
  });

  it("clears the selection when the active project is deleted", async () => {
    selectProject();
    (api.listProjects as Mock).mockResolvedValue([project("proj1")]);
    renderPage();

    // The panels load for the project that is active at the time...
    await vi.waitFor(() => expect(api.metrics).toHaveBeenCalledWith("proj1"));
    const callsBefore = (api.metrics as Mock).mock.calls.length;

    await userEvent.click(await screen.findByRole("button", { name: "Delete" }));
    await userEvent.click(await screen.findByRole("button", { name: "Delete project?" }));

    expect(api.deleteProject).toHaveBeenCalledWith("proj1");
    await vi.waitFor(() =>
      expect(window.localStorage.getItem("mplab.workspace")).toBeNull(),
    );
    expect(await screen.findByText("Start an investigation")).toBeInTheDocument();
    // ...and nothing asks for that project again afterwards.
    expect((api.metrics as Mock).mock.calls.length).toBe(callsBefore);
  });

  it("loads every panel for the project that is actually selected", async () => {
    selectProject("proj2");
    renderPage();
    await vi.waitFor(() => expect(api.metrics).toHaveBeenCalledWith("proj2"));
    await vi.waitFor(() => expect(api.integrity).toHaveBeenCalledWith("proj2"));
  });
});
