/**
 * A suggested query must work when it is clicked.
 *
 * The assistant's examples were English strings. In a Russian interface the
 * button showed a Russian sentence and put the *English* one in the query box -
 * and nothing looked wrong, because the compiler accepts both languages. The
 * two quietly diverged.
 *
 * `backend/tests/test_suggested_queries.py` checks the other half: that every
 * suggestion is a query the compiler can actually run.
 */

import { beforeEach, describe, expect, it, vi, type Mock } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import AssistantPage from "@/app/assistant/page";
import { WorkspaceProvider } from "@/hooks/use-workspace";
import { api } from "@/lib/api";
import { LocaleProvider } from "@/lib/i18n";
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
      assistantQueryIn: vi.fn(),
    },
  };
});

const LABEL = "Найти все TCP-ответы длиннее 1000 байт";
const ENGLISH = "Find all TCP responses longer than 1000 bytes";

function renderRussian() {
  return render(
    <LocaleProvider>
      <WorkspaceProvider>
        <AssistantPage />
      </WorkspaceProvider>
    </LocaleProvider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  window.localStorage.clear();
  window.localStorage.setItem(
    "mplab.workspace",
    JSON.stringify({ projectId: "proj1", projectName: "Termostand" }),
  );
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
  (api.projectCaptures as Mock).mockResolvedValue([]);
  (api.assistantCapabilities as Mock).mockResolvedValue({
    version: "assistant/1.3",
    entities: ["messages"],
    fields: {},
    operators: [],
    execution_model: "Requests are compiled into a typed query plan.",
    external_ai: {
      enabled: false,
      configured: false,
      provider: null,
      note: "External AI is off by default.",
      default: "disabled",
    },
    limitations: [],
  });
  (api.assistantQueryIn as Mock).mockResolvedValue({
    status: "needs_clarification",
    question: "…",
    suggestions: [],
    note: "…",
  });
});

describe("assistant suggestions", () => {
  it("offers Russian labels in a Russian interface", async () => {
    renderRussian();
    expect(await screen.findByText(LABEL)).toBeTruthy();
  });

  it("puts the Russian question in the box, not the English one", async () => {
    const user = userEvent.setup();
    const { container } = renderRussian();

    await user.click(await screen.findByText(LABEL));

    // The query field is a textarea: a request can run to 1000 characters and a
// single-line input would hide most of what is being asked.
const box = container.querySelector("textarea") as HTMLTextAreaElement;
    expect(box, "the query input was not rendered").toBeTruthy();
    // The label on screen and the text submitted are the same sentence.
    expect(box.value).toBe(LABEL);
    expect(box.value).not.toBe(ENGLISH);
    expect(box.value).toMatch(/[а-яА-ЯёЁ]/);
  });

  it("submits the Russian question", async () => {
    const user = userEvent.setup();
    renderRussian();

    await user.click(await screen.findByText(LABEL));
    await user.click(screen.getByText("Запустить"));

    await vi.waitFor(() => {
      expect(api.assistantQueryIn).toHaveBeenCalled();
    });
    const body = (api.assistantQueryIn as Mock).mock.calls[0][0] as Record<
      string,
      unknown
    >;
    // The locale is added inside the API client, which is mocked here; it has
    // its own test below. What the component owns is the question text.
    expect(body.query).toBe(LABEL);
  });

  it("the API client attaches the active locale", async () => {
    // The model defaults to English, so without this a Russian interface gets
    // a Russian question answered in English.
    const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
    const realApi = actual.api;
    const fetchMock = vi.fn(
      async () =>
        new Response(JSON.stringify({}), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
    );
    vi.stubGlobal("fetch", fetchMock);
    setActiveLocale("ru");

    await realApi.assistantQueryIn({ query: LABEL, dry_run: false }).catch(() => {});

    const call = fetchMock.mock.calls[0] as unknown as [
      string,
      { body?: string },
    ];
    const body = JSON.parse(call[1].body ?? "{}") as Record<string, unknown>;
    expect(body.locale).toBe("ru");
    expect(body.query).toBe(LABEL);
    vi.unstubAllGlobals();
  });
});