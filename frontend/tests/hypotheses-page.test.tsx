/**
 * Scenario coverage for the Hypotheses & Rules tool (§23).
 *
 * The researcher path these pin down:
 *
 *  1. A rule that is not valid JSON never reaches the server, and the editor
 *     stops claiming the draft is valid.
 *  2. A rule the server rejects is reported with the server's message.
 *  3. Create a rule, select a corpus, run the validation, and read the
 *     counterexamples it produced — the loop that turns a guess into evidence.
 */
import { beforeEach, describe, expect, it, vi, type Mock } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import HypothesesPage from "@/app/hypotheses/page";
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
      hypotheses: vi.fn(),
      interpretations: vi.fn(),
      interpretationSupport: vi.fn(),
      createInterpretation: vi.fn(),
      updateInterpretation: vi.fn(),
      validate: vi.fn(),
      validationRun: vi.fn(),
      counterexamples: vi.fn(),
      createHypothesis: vi.fn(),
      updateHypothesis: vi.fn(),
    },
  };
});

const METRICS = {
  project_id: "proj1",
  captures: 1,
  packets: 10,
  tcp_sessions: 1,
  streams: 2,
  messages: 4,
  hypotheses: 0,
  interpretations: 0,
  validation_runs: 0,
  counterexamples: 0,
  sessions_with_reconstruction_problems: 0,
  bytes_stored: 100,
  analyst_versions: {},
};

const CAPTURE = {
  id: "cap1",
  project_id: "proj1",
  name: "session.pcap",
  sha256: "a".repeat(64),
  file_size: 100,
  format: "pcap",
  imported_at: "2026-01-01T00:00:00+00:00",
  analysis_status: "completed",
};

const COUNTEREXAMPLES = {
  run_id: "run1",
  count: 1,
  disclaimer: "One message contradicted the rule; that is the point of running it.",
  counterexamples: [
    {
      result_id: "res1",
      message_id: "msg123456789",
      start_offset: 0,
      end_offset: 12,
      violated_rule: "length",
      reasons: [{ message: "declared length disagrees with the message boundary" }],
      explanation: "The length field was read from the wrong offset.",
      alternative_explanations: ["the stream is missing a segment"],
    },
  ],
};

beforeEach(() => {
  vi.clearAllMocks();
  window.localStorage.clear();
  window.localStorage.setItem(
    "mplab.workspace",
    JSON.stringify({ projectId: "proj1", projectName: "Demo" }),
  );
  (api.health as Mock).mockResolvedValue({ status: "ok" });
  (api.metrics as Mock).mockResolvedValue(METRICS);
  (api.projectCaptures as Mock).mockResolvedValue([CAPTURE]);
  (api.hypotheses as Mock).mockResolvedValue([]);
  (api.interpretations as Mock).mockResolvedValue([]);
  (api.interpretationSupport as Mock).mockResolvedValue(null);
});

function renderPage() {
  return render(
    <WorkspaceProvider>
      <HypothesesPage />
    </WorkspaceProvider>,
  );
}

describe("Hypotheses & Rules page", () => {
  it("refuses invalid JSON without calling the server", async () => {
    renderPage();
    const editor = await screen.findByLabelText("Interpretation specification");

    await userEvent.clear(editor);
    await userEvent.type(editor, "{{");
    expect(screen.queryByText(/Valid JSON/)).toBeNull();

    await userEvent.click(screen.getByRole("button", { name: "create" }));

    expect(api.createInterpretation).not.toHaveBeenCalled();
    expect(screen.queryByText(/Valid JSON/)).toBeNull();
  });

  it("reports a specification the server rejects", async () => {
    (api.createInterpretation as Mock).mockRejectedValue(
      new ApiError(422, "validation_failed", "the framing block is not valid"),
    );
    renderPage();
    await screen.findByLabelText("Interpretation specification");

    await userEvent.click(screen.getByRole("button", { name: "create" }));

    expect(await screen.findByText("the framing block is not valid")).toBeInTheDocument();
  });

  it("walks rule -> corpus -> counterexamples", async () => {
    (api.createInterpretation as Mock).mockResolvedValue({ id: "i1", name: "NewProtocol" });
    (api.validate as Mock).mockResolvedValue({
      run_id: "run1",
      verdict: "contradicted",
      total: 4,
      matched: 3,
      partial: 0,
      failed: 1,
      unparsed: 0,
    });
    (api.validationRun as Mock).mockResolvedValue({
      id: "run1",
      interpretation_name: "NewProtocol",
      interpretation_version: 1,
      specification_checksum: "b".repeat(64),
      status: "completed",
      analyzer_version: "validation/1.0",
      stale: false,
    });
    (api.counterexamples as Mock).mockResolvedValue(COUNTEREXAMPLES);

    renderPage();

    // 1. Create the rule from the starter specification.
    await userEvent.click(await screen.findByRole("button", { name: "create" }));
    expect(api.createInterpretation).toHaveBeenCalledTimes(1);

    // 2. Choose the capture as the corpus.
    const checkbox = await screen.findByRole("checkbox");
    await userEvent.click(checkbox);

    // 3. Run the validation.
    await userEvent.click(screen.getByRole("button", { name: /Run validation/ }));
    expect(api.validate).toHaveBeenCalledWith("proj1", "i1", { capture_ids: ["cap1"] });

    // 4. Read the counterexample the rule produced.
    expect(await screen.findByText(/broke the rule/)).toBeInTheDocument();
    expect(
      screen.getByText(/declared length disagrees with the message boundary/),
    ).toBeInTheDocument();
    expect(
      screen.getByText(COUNTEREXAMPLES.disclaimer),
    ).toBeInTheDocument();
  });
});
