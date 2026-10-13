/**
 * Scenario coverage for the Anomaly Detection tool (§23).
 *
 * The product's claim is that scores *rank how unusual* an entity is and carry no
 * severity, so the tool has to show the ranking and the features behind it, and
 * has to refuse a capture that cannot supply every trained feature. It also must
 * degrade honestly when scikit-learn is missing rather than showing zeros.
 *
 *  1. Without the analytics extra the tool says so, with the install command.
 *  2. Scoring a capture renders the ranked result and the per-entity
 *     explanation, not just a raw JSON blob.
 *  3. Without a project the tool names what is missing.
 */
import { beforeEach, describe, expect, it, vi, type Mock } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import AnomaliesPage from "@/app/anomalies/page";
import { WorkspaceProvider } from "@/hooks/use-workspace";
import { api } from "@/lib/api";

const search = vi.hoisted(() => ({ value: "project=proj1" }));

vi.mock("next/navigation", () => ({
  useSearchParams: () => new URLSearchParams(search.value),
  useRouter: () => ({ push: vi.fn() }),
}));

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return {
    ...actual,
    api: {
      health: vi.fn(),
      getProject: vi.fn(),
      projectCaptures: vi.fn(),
      anomaliesStatus: vi.fn(),
      anomaliesModels: vi.fn(),
      anomaliesTrain: vi.fn(),
      anomaliesScore: vi.fn(),
    },
  };
});

function selectProject(id = "proj1") {
  window.localStorage.setItem(
    "mplab.workspace",
    JSON.stringify({ projectId: id, projectName: "Termostand" }),
  );
}

function renderPage() {
  return render(
    <WorkspaceProvider>
      <AnomaliesPage />
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
  (api.projectCaptures as Mock).mockResolvedValue([
    { id: "cap1", name: "basic.pcap", analysis_status: "completed" },
    { id: "cap2", name: "lossy_segments.pcap", analysis_status: "completed" },
  ]);
  (api.anomaliesStatus as Mock).mockResolvedValue({ available: true });
  (api.anomaliesModels as Mock).mockResolvedValue([
    { id: "model1", name: "Baseline", algorithm: "isolation_forest", params: {} },
  ]);
  (api.anomaliesScore as Mock).mockResolvedValue({
    model_id: "model1",
    model_name: "Baseline",
    scope: "messages",
    scored: 2,
    anomalies: [
      {
        entity_id: "aaaaaaaaaaaaaaaa",
        entity_type: "message",
        score: 0.42,
        explanation: [{ feature: "payload_length", value: 128, baseline_mean: 32 }],
        navigate_to: { stream_id: "stream1", capture_id: "cap1" },
      },
      {
        entity_id: "bbbbbbbbbbbbbbbb",
        entity_type: "message",
        score: 0.31,
        explanation: [{ feature: "inter_arrival", value: 90, baseline_mean: 4 }],
        navigate_to: { stream_id: "stream2", capture_id: "cap1" },
      },
    ],
    interpretation:
      "Scores rank how unusual each entity is relative to the training corpus. They are not probabilities and carry no severity ordering.",
  });
});

describe("Anomaly detection page", () => {
  it("names what is missing when no project is selected", () => {
    search.value = "";
    render(
      <WorkspaceProvider>
        <AnomaliesPage />
      </WorkspaceProvider>,
    );
    expect(screen.getByText("No project selected")).toBeInTheDocument();
  });

  it("degrades honestly when scikit-learn is missing", async () => {
    (api.anomaliesStatus as Mock).mockResolvedValue({
      available: false,
      availability_note: "The analytics extra was not installed.",
    });
    selectProject();
    renderPage();

    expect(await screen.findByText("Unavailable")).toBeInTheDocument();
    expect(screen.getByText("scikit-learn is not installed")).toBeInTheDocument();
    expect(screen.getByText("The analytics extra was not installed.")).toBeInTheDocument();
    // Nothing that cannot be computed is presented as a number.
    expect(screen.queryByText("Scored result")).not.toBeInTheDocument();
  });

  it("shows the ranked result with the features behind each score", async () => {
    selectProject();
    renderPage();

    await userEvent.selectOptions(
      await screen.findByRole("combobox", { name: "Model" }),
      await screen.findByRole("option", { name: "Baseline" }),
    );
    // Two capture lists exist (training corpus and scoring corpus); take the one
    // that belongs to the scoring form.
    const scoreSection = screen.getByText("Captures to score").parentElement as HTMLElement;
    await userEvent.click(
      within(scoreSection).getByRole("checkbox", { name: /basic.pcap/ }),
    );
    await userEvent.click(screen.getByRole("button", { name: "Score captures" }));

    expect(api.anomaliesScore).toHaveBeenCalledWith(
      expect.objectContaining({ model_id: "model1", capture_ids: ["cap1"], scope: "messages" }),
    );

    // The ranking itself…
    expect(await screen.findByText("0.4200")).toBeInTheDocument();
    expect(screen.getByText("0.3100")).toBeInTheDocument();
    // …the explanation the score is built from…
    expect(screen.getByText(/payload_length: 128\.000/)).toBeInTheDocument();
    // …and the caveat that a score is not a severity.
    const panel = screen.getByText("Scored result").closest("section") as HTMLElement;
    expect(
      within(panel).getByText(/not probabilities and carry no severity/),
    ).toBeInTheDocument();
  });
});
