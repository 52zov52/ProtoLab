/**
 * Evidence-to-navigation mapping for reports.
 *
 * Only kinds with a real destination may produce a link; inventing one would
 * send a reader to an unrelated page, which is worse than showing a bare id.
 */
import { describe, expect, it } from "vitest";

import { evidenceLabel, evidenceTarget, shortId } from "@/lib/evidence-links";

const PROJECT = "prj-123";

describe("evidenceTarget", () => {
  it("links a session and asks the workspace to select it", () => {
    const target = evidenceTarget({ kind: "session", id: "ses-9" }, PROJECT);
    expect(target.href).toBe(`/sessions?project=${PROJECT}`);
    expect(target.select).toBe("session");
  });

  it("links a capture and asks the workspace to select it", () => {
    const target = evidenceTarget({ kind: "capture", id: "cap-9" }, PROJECT);
    expect(target.href).toBe(`/captures?project=${PROJECT}`);
    expect(target.select).toBe("capture");
  });

  it("sends interpretations and validation evidence to the hypotheses page", () => {
    for (const kind of ["interpretation", "validation_run", "validation_result"]) {
      expect(evidenceTarget({ kind, id: "x" }, PROJECT).href).toBe(
        `/hypotheses?project=${PROJECT}`,
      );
    }
  });

  it("never invents a destination for a kind the app does not show", () => {
    const target = evidenceTarget({ kind: "experiment", id: "exp-1" }, PROJECT);
    expect(target.href).toBeNull();
    expect(target.select).toBeNull();
    expect(target.label).toBe("experiment log");
  });

  it("encodes the project id", () => {
    expect(evidenceTarget({ kind: "session", id: "s" }, "a b&c").href).toBe(
      "/sessions?project=a%20b%26c",
    );
  });
});

describe("evidenceLabel", () => {
  it("falls back to the raw kind when it is unknown", () => {
    expect(evidenceLabel("something_new")).toBe("something_new");
  });
});

describe("shortId", () => {
  it("truncates long ids and leaves short ones alone", () => {
    expect(shortId("abcdefghijkl")).toBe("abcdefghij…");
    expect(shortId("short")).toBe("short");
  });
});
