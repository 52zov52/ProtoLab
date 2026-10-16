/**
 * Every page must settle on a hard load.
 *
 * The shell renders inside a `<Suspense>` boundary, because most pages read the
 * query string and suspend while the server streams. A page that never suspends
 * is a problem there: the server renders it into the fallback position and the
 * client never replaces it, so the application sits on "Loading…" forever. No
 * console error, no failed request, a server response that looks correct - and
 * reaching the same page by clicking through the interface works, because the
 * boundary is not re-entered.
 *
 * Five pages were affected: `/packets`, `/security`, `/sessions`, `/settings`
 * and `/tls`. They now call `useStreamingBoundary()`, and this test is what stops
 * the sixth from joining them by accident.
 */

import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, resolve } from "node:path";

import { describe, expect, it } from "vitest";

const APP = resolve(process.cwd(), "app");

function pages(): { route: string; source: string }[] {
  const found: { route: string; source: string }[] = [];
  for (const entry of readdirSync(APP)) {
    const directory = join(APP, entry);
    const file = join(directory, "page.tsx");
    try {
      if (!statSync(directory).isDirectory() || !statSync(file).isFile()) continue;
    } catch {
      continue;
    }
    found.push({ route: entry, source: readFileSync(file, "utf8") });
  }
  const rootPage = join(APP, "page.tsx");
  found.push({ route: "/", source: readFileSync(rootPage, "utf8") });
  return found;
}

const ALL = pages();

describe("every page takes part in the shell's streaming boundary", () => {
  /**
   * `/overview` redirects rather than rendering, so it cannot join a boundary
   * and does not need to: it navigates to the root page, which does.
   */
  const REDIRECTS = new Set(["overview"]);

  const PAGES = ALL.filter((page) => !REDIRECTS.has(page.route));

  it("the pages were actually read", () => {
    expect(ALL.length).toBeGreaterThan(10);
  });

  it.each(PAGES.map((page) => [page.route, page.source] as const))(
    "%s either reads the query string or joins the boundary explicitly",
    (_route, source) => {
      const readsQuery = /useSearchParams\(\)/.test(source);
      const joinsBoundary = /useStreamingBoundary\(\)/.test(source);
      expect(
        readsQuery || joinsBoundary,
        "this page never suspends, so the server renders it into the shell's " +
          "Suspense fallback and the client never replaces it: the application " +
          "hangs on the loading state on every hard load",
      ).toBe(true);
    },
  );

  it("the redirect alias is a redirect, not a page that renders", () => {
    const source = ALL.find((page) => page.route === "overview")?.source ?? "";
    expect(source).toContain("redirect(");
    // If someone replaces the redirect with real content, it needs the boundary
    // like every other page and this exclusion has to go with it.
    expect(source).not.toContain("useI18n");
  });

  it("the boundary helper does exactly one thing", () => {
    const source = readFileSync(join(process.cwd(), "lib", "i18n.tsx"), "utf8");
    // If the helper grew a second responsibility, this page would need to know
    // which half of it applies.
    const helper = source.match(
      /export function useStreamingBoundary\(\): void \{([\s\S]*?)\n\}/,
    );
    expect(helper, "useStreamingBoundary is not defined").toBeTruthy();
    expect(helper?.[1]).toContain("useSearchParams()");
    expect(helper?.[1].split("\n").filter((line) => line.trim()).length).toBe(1);
  });
});