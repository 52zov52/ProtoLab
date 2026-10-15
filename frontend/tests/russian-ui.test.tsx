/**
 * A Russian interface must not show English sentences.
 *
 * The existing coverage test checks that every `t("…")` literal has a Russian
 * entry. It cannot catch the other way English reaches a reader: prose the API
 * sends and the UI renders verbatim. The wire format is English by design, so a
 * new field could ship untranslated and every key test would still pass.
 *
 * These tests render the two pages that display the most API prose and assert
 * the reader sees Russian.
 */
import { beforeEach, describe, expect, it, vi, type Mock } from "vitest";
import { render, screen } from "@testing-library/react";

import AnomaliesPage from "@/app/anomalies/page";
import AssistantPage from "@/app/assistant/page";
import { WorkspaceProvider } from "@/hooks/use-workspace";
import { api } from "@/lib/api";
import { LocaleProvider, translate } from "@/lib/i18n";
import { RU_MESSAGES } from "@/lib/i18n/ru";
import { setActiveLocale } from "@/lib/format";

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
      assistantCapabilities: vi.fn(),
      anomaliesStatus: vi.fn(),
      anomaliesModels: vi.fn(),
      anomaliesScore: vi.fn(),
    },
  };
});

/** A sentence is four or more words; names and numbers are English on purpose. */
const SENTENCE =
  /[A-Za-z][A-Za-z'’-]*(?:[ ,;:/()\-]+[A-Za-z0-9'’.()\-]+){3,}/;

const EXECUTION_MODEL =
  "Requests are compiled into a typed query plan, schema-validated, checked against a field/operator allowlist, and executed through a fixed analytics API. No SQL, shell command or Python is ever generated from user text or from model output.";

const AVAILABILITY_NOTE =
  "scikit-learn is not installed in this deployment, so every baseline is trained as a robust per-feature profile (median and MAD). Install the 'analytics' extra for the Isolation Forest.";

const LIMITATIONS = [
  "Searches run against plaintext payloads only; encrypted TLS content is not scanned unless a matching key log was supplied and decryption ran.",
  "A JWT that decodes is not a JWT that is authentic; signatures are not verified here.",
];

function selectProject(id = "proj1") {
  window.localStorage.setItem(
    "mplab.workspace",
    JSON.stringify({ projectId: id, projectName: "Termostand" }),
  );
}

function renderRussian(page: React.ReactNode) {
  return render(
    <LocaleProvider>
      <WorkspaceProvider>{page}</WorkspaceProvider>
    </LocaleProvider>,
  );
}

/** Every run of English prose in what the reader can actually see. */
function englishSentencesIn(container: HTMLElement): string[] {
  const text = container.textContent ?? "";
  return text
    .split(/(?<=\.)\s+/)
    .map((chunk) => chunk.trim())
    .filter(
      (chunk) =>
        chunk.length > 20 && SENTENCE.test(chunk) && !/[а-яА-ЯёЁ]/.test(chunk),
    );
}

beforeEach(() => {
  vi.clearAllMocks();
  window.localStorage.clear();
  selectProject();
  // The provider resolves the locale from storage in an effect; the API layer
  // reads the module-level one that `setActiveLocale` keeps in step.
  window.localStorage.setItem("mplab.locale", "ru");
  setActiveLocale("ru");
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
  ]);
  (api.anomaliesStatus as Mock).mockResolvedValue({
    available: false,
    algorithm: "robust_profile",
    sklearn_installed: false,
    min_samples: { isolation_forest: 50, robust_profile: 20 },
    availability_note: AVAILABILITY_NOTE,
  });
  (api.anomaliesModels as Mock).mockResolvedValue([]);
  (api.assistantCapabilities as Mock).mockResolvedValue({
    version: "assistant/1.3",
    entities: ["messages", "streams"],
    fields: {},
    operators: [],
    execution_model: EXECUTION_MODEL,
    external_ai: {
      enabled: true,
      configured: true,
      provider: "openai-compatible",
      model: "vendor/free-model",
      note: "External AI is off by default. Even when enabled it may only narrate already-validated results; it cannot execute queries, write files, or alter the investigation.",
      default: "disabled",
    },
    limitations: LIMITATIONS,
  });
});

describe("a Russian interface speaks Russian", () => {
  it("translates the prose the assistant capabilities endpoint returns", () => {
    for (const sentence of [EXECUTION_MODEL, ...LIMITATIONS]) {
      const russian = translate("ru", sentence);
      expect(russian, `untranslated: ${sentence.slice(0, 40)}`).toMatch(
        /[а-яА-ЯёЁ]/,
      );
    }
    expect(translate("ru", EXECUTION_MODEL)).not.toMatch(SENTENCE);
  });

  it("translates the anomaly availability note", () => {
    expect(translate("ru", AVAILABILITY_NOTE)).toMatch(/[а-яА-ЯёЁ]/);
  });

  it("keeps the availability note consistent with the badge beside it", () => {
    // The badge and the note describe the same installation from two sources:
    // one is a frontend label, one is the API's own sentence. When the mock
    // says scikit-learn is missing, they must not disagree on the page.
    expect(RU_MESSAGES["scikit-learn is not installed"]).toMatch(/[а-яА-ЯёЁ]/);
    expect(translate("ru", AVAILABILITY_NOTE)).toMatch(/не установлен/);
  });

  it("shows the assistant capabilities panel in Russian", async () => {
    const { container } = renderRussian(<AssistantPage />);

    await screen.findByText(/Запрос компилируется/);
    expect(englishSentencesIn(container)).toEqual([]);
  });

  it("shows the anomaly availability note in Russian", async () => {
    const { container } = renderRussian(<AnomaliesPage />);

    await screen.findByText(/не установлен в этом развёртывании/);
    expect(englishSentencesIn(container)).toEqual([]);
  });

  it("names the provider instead of reporting a literal 'disabled'", async () => {
    const { container } = renderRussian(<AssistantPage />);

    await screen.findByText(/Запрос компилируется/);
    const text = container.textContent ?? "";
    // The API always sent `default: "disabled"`; the badge used to render that
    // string regardless of state, so an enabled endpoint read as "disabled".
    expect(text).toContain("openai-compatible");
    expect(text).not.toMatch(/>\s*disabled\s*</);
  });

  it("would notice a sentence it had not seen before", () => {
    // A guard that cannot fail is a guard nobody knows works.
    expect(englishSentencesIn(document.body).length).toBe(0);
    const probe = document.createElement("div");
    probe.textContent = "Only 24 samples were available in this corpus today";
    expect(englishSentencesIn(probe)).toHaveLength(1);
  });
});