/**
 * Russian counts in three, and a fixed noun form is wrong for two of them.
 *
 * "24 примеров" is the kind of error a reader spots immediately and stops
 * trusting the rest of the interface. Found live on the anomaly page, where the
 * API interpolates a sample count into a sentence that travels to the UI.
 *
 * The rule under test is the standard Russian one, including the 11-14 case
 * that a naive `count % 10` gets wrong: 11 примеров is correct, not 11 пример.
 */

import { describe, expect, it } from "vitest";

import { pluralForm, translate } from "@/lib/i18n";
import { RU_MESSAGES } from "@/lib/i18n/ru";

const SAMPLE_WARNING =
  "Only {count} samples were available, and an Isolation Forest needs 50 before its scores mean anything, so a robust per-feature profile was trained instead. Treat these scores as noisy: add captures to the corpus and retrain for the forest.";

describe("Russian plural forms", () => {
  it.each([
    [1, "one"],
    [2, "few"],
    [4, "few"],
    [5, "many"],
    [11, "many"],
    [12, "many"],
    [14, "many"],
    [21, "one"],
    [22, "few"],
    [25, "many"],
    [101, "one"],
    [111, "many"],
    [0, "many"],
    [124, "few"],
  ])("%i takes the %s form", (count, form) => {
    expect(pluralForm(count)).toBe(form);
  });

  it("says 1 пример, 2 примера and 5 примеров", () => {
    // Ordered longest-first, and no \b: JavaScript's \b is defined on ASCII
    // \w, so it never matches next to a Cyrillic letter.
    const endings = [1, 2, 5].map(
      (count) =>
        translate("ru", SAMPLE_WARNING, { count }).match(
          /примеров|примера|пример/,
        )?.[0],
    );
    expect(endings).toEqual(["пример", "примера", "примеров"]);
  });

  it("keeps the number in the sentence", () => {
    expect(translate("ru", SAMPLE_WARNING, { count: 24 })).toContain("24");
    expect(translate("ru", SAMPLE_WARNING, { count: 24 })).toContain("примера");
  });

  it("falls back to the interpolated English when nothing is declared", () => {
    const noVariants = "There are {count} packets in this capture.";
    expect(translate("ru", noVariants, { count: 3 })).toBe(
      "There are 3 packets in this capture.",
    );
  });

  it("English ignores plural forms entirely", () => {
    expect(translate("en", SAMPLE_WARNING, { count: 2 })).toBe(
      SAMPLE_WARNING.replace("{count}", "2"),
    );
  });

  it("every declared variant keeps the placeholder", () => {
    for (const [key, value] of Object.entries(RU_MESSAGES)) {
      if (!key.includes("::")) continue;
      const placeholders = new Set(
        (key.match(/\{\w+\}/g) ?? []).map((p) => p.slice(1, -1)),
      );
      for (const placeholder of placeholders) {
        expect(value, `${key} drops ${placeholder}`).toContain(
          `{${placeholder}}`,
        );
      }
    }
  });

  it("a source with variants declares all three", () => {
    const withOne = Object.keys(RU_MESSAGES).filter((k) => k.endsWith(":: one"));
    for (const key of withOne) {
      const base = key.replace(" :: one", "");
      expect(RU_MESSAGES, `${base} has no "few"`).toHaveProperty(
        `${base} :: few`,
      );
      expect(RU_MESSAGES, `${base} has no "many"`).toHaveProperty(
        `${base} :: many`,
      );
    }
    expect(withOne.length).toBeGreaterThan(0);
  });
});