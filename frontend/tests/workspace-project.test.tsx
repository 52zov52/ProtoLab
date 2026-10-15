/**
 * The active project must exist.
 *
 * An id reaches the workspace from a URL (`?project=`) and from localStorage —
 * both of which outlive the local database. The relevant promises:
 *
 *  1. An id the server does not know about is dropped, so the "open a project"
 *     state (and with it the tool that creates a project) is reachable again.
 *  2. An unreachable backend is *not* a missing project: the selection is kept
 *     rather than thrown away on a transient outage, and the persisted entry
 *     survives with it.
 *  3. An id that does exist is named from the server, not from the URL, so a
 *     deep link shows the project in the sidebar instead of "none selected".
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";

import { WorkspaceProvider, useWorkspace } from "@/hooks/use-workspace";
import { ApiError, api } from "@/lib/api";

vi.mock("@/lib/api", () => {
  class ApiError extends Error {
    constructor(
      public readonly status: number,
      public readonly code: string,
      message: string,
      public readonly details: unknown = null,
    ) {
      super(message);
    }
  }
  return {
    ApiError,
    api: {
      health: vi.fn().mockResolvedValue({ status: "ok" }),
      getProject: vi.fn(),
      getSession: vi.fn(),
      jobs: vi.fn().mockResolvedValue([]),
    },
  };
});

function Probe() {
  const { projectId, projectName } = useWorkspace();
  return (
    <div>
      <span data-testid="project-id">{projectId ?? "none"}</span>
      <span data-testid="project-name">{projectName ?? "none"}</span>
    </div>
  );
}

beforeEach(() => {
  window.localStorage.clear();
  window.history.pushState({}, "", "/");
  vi.mocked(api.getProject).mockReset();
});

const renderWorkspace = () =>
  render(
    <WorkspaceProvider>
      <Probe />
    </WorkspaceProvider>,
  );

describe("active project validation", () => {
  it("drops a stored project the server does not know", async () => {
    window.localStorage.setItem(
      "mplab.workspace",
      JSON.stringify({ projectId: "stale1", projectName: "Old project" }),
    );
    vi.mocked(api.getProject).mockRejectedValue(
      new ApiError(404, "not_found", "Project 'stale1' does not exist."),
    );

    renderWorkspace();

    // The id is selected first (from storage), so the app has to answer for it.
    await waitFor(() =>
      expect(screen.getByTestId("project-id")).toHaveTextContent("none"),
    );
    expect(screen.getByTestId("project-name")).toHaveTextContent("none");
    // ...and must not resurrect it on the next reload. Waiting rather than
    // asserting in the same tick: the selection clears first and the persisted
    // entry follows, and asserting between the two is a coin toss.
    await waitFor(() => expect(window.localStorage.getItem("mplab.workspace")).toBeNull());
  });

  it("drops a project id that arrived in the URL", async () => {
    window.history.pushState({}, "", "/?project=stale2");
    vi.mocked(api.getProject).mockRejectedValue(
      new ApiError(404, "not_found", "Project 'stale2' does not exist."),
    );

    renderWorkspace();

    await waitFor(() =>
      expect(screen.getByTestId("project-id")).toHaveTextContent("none"),
    );
    // ...and the address bar stops naming a project that is not there, so a
    // reload does not put it straight back.
    expect(new URLSearchParams(window.location.search).get("project")).toBeNull();
  });

  it("keeps the selection when the backend is unreachable", async () => {
    window.localStorage.setItem(
      "mplab.workspace",
      JSON.stringify({ projectId: "kept1", projectName: "Kept project" }),
    );
    vi.mocked(api.getProject).mockRejectedValue(
      new ApiError(503, "unavailable", "Backend unreachable."),
    );

    renderWorkspace();

    await waitFor(() => expect(api.getProject).toHaveBeenCalled());
    expect(screen.getByTestId("project-id")).toHaveTextContent("kept1");
    expect(screen.getByTestId("project-name")).toHaveTextContent("Kept project");
    expect(window.localStorage.getItem("mplab.workspace")).toContain("kept1");
  });

  it("names the project from the server for a deep link", async () => {
    window.history.pushState({}, "", "/?project=known1");
    vi.mocked(api.getProject).mockResolvedValue({
      id: "known1",
      name: "Thermostand",
      description: "",
      schema_version: 1,
      created_at: "2026-01-01T00:00:00Z",
      updated_at: "2026-01-01T00:00:00Z",
      settings: {},
    });

    renderWorkspace();

    await waitFor(() =>
      expect(screen.getByTestId("project-name")).toHaveTextContent("Thermostand"),
    );
    expect(screen.getByTestId("project-id")).toHaveTextContent("known1");
  });
});
