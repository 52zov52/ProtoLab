/**
 * Localization guarantees (§8 Этап 8).
 *
 *  1. Language selection: the switcher changes the active language, reflects it
 *     in `<html lang>`, and remembers the choice across a reload.
 *  2. Coverage: every `t("…")` literal in the source has a Russian entry, so a
 *     string can never be silently left in English when Russian is selected.
 */
import fs from "node:fs";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { LocaleProvider, LOCALE_STORAGE_KEY, useI18n } from "@/lib/i18n";
import { RU_MESSAGES } from "@/lib/i18n/ru";

function Probe() {
  const { locale, setLocale, t } = useI18n();
  return (
    <div>
      <p data-testid="locale">{locale}</p>
      <p data-testid="overview">{t("Overview")}</p>
      <p data-testid="greeting">{t("Request failed")}</p>
      <button type="button" onClick={() => setLocale("ru")}>
        to-ru
      </button>
      <button type="button" onClick={() => setLocale("en")}>
        to-en
      </button>
    </div>
  );
}

beforeEach(() => {
  window.localStorage.clear();
  document.documentElement.lang = "";
});

afterEach(() => {
  window.localStorage.clear();
});

describe("locale selection", () => {
  it("defaults to English and sets the document language", async () => {
    render(
      <LocaleProvider>
        <Probe />
      </LocaleProvider>,
    );
    await waitFor(() => expect(document.documentElement.lang).toBe("en"));
    expect(screen.getByTestId("overview")).toHaveTextContent("Overview");
  });

  it("switches to Russian and remembers the choice", async () => {
    render(
      <LocaleProvider>
        <Probe />
      </LocaleProvider>,
    );
    await userEvent.click(screen.getByRole("button", { name: "to-ru" }));

    await waitFor(() => expect(screen.getByTestId("overview")).toHaveTextContent("Обзор"));
    expect(screen.getByTestId("greeting")).toHaveTextContent("Запрос не выполнен");
    expect(screen.getByTestId("locale")).toHaveTextContent("ru");
    expect(document.documentElement.lang).toBe("ru");
    expect(window.localStorage.getItem(LOCALE_STORAGE_KEY)).toBe("ru");
  });

  it("applies a stored preference on load", async () => {
    window.localStorage.setItem(LOCALE_STORAGE_KEY, "ru");
    render(
      <LocaleProvider>
        <Probe />
      </LocaleProvider>,
    );
    await waitFor(() => expect(screen.getByTestId("overview")).toHaveTextContent("Обзор"));
    expect(document.documentElement.lang).toBe("ru");
  });
});

describe("translation coverage", () => {
  it("has a Russian entry for every t(…) literal in app/ and components/", () => {
    const roots = ["app", "components"].map((dir) =>
      path.join(process.cwd(), dir),
    );

    // Match a call `t(` followed by a complete quoted string literal. The
    // literal is then evaluated, so escapes (`\n`, `\"`, …) are resolved to the
    // same value the runtime key has. Template literals (dynamic keys) do not
    // match and are intentionally skipped.
    const callPattern =
      /(?<![\w.])t\(\s*("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')/g;

    const missing = new Set<string>();
    let seen = 0;

    const walk = (dir: string) => {
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          walk(full);
          continue;
        }
        if (!/\.tsx?$/.test(entry.name)) continue;
        const source = fs.readFileSync(full, "utf8");
        for (const match of source.matchAll(callPattern)) {
          // Evaluate the literal so escapes resolve to the runtime key value.
          const key = new Function(`"use strict";return (${match[1]});`)() as string;
          if (typeof key !== "string" || key.length === 0) continue;
          seen += 1;
          if (!(key in RU_MESSAGES)) missing.add(key);
        }
      }
    };

    for (const root of roots) walk(root);

    expect(seen).toBeGreaterThan(50);
    expect([...missing].sort()).toEqual([]);
  });
});
