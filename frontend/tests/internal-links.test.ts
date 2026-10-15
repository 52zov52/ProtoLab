/**
 * Every internal link must point at a page that exists.
 *
 * The corpus-too-small panel offered "Open the Protocol Bench" and pointed it at
 * /protocol-bench, which does not exist: the page is /workbench. The link was
 * written by hand, tested by clicking a *button* that led somewhere else, and
 * nothing between those two points checked the route.
 *
 * A 404 on the one panel that exists to tell an analyst what to do next is worse
 * than no panel, so every href the app renders is resolved against the real
 * route table here. Reading the filesystem rather than a hand-kept list is the
 * point: the list cannot rot, the filesystem is the truth.
 */

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, resolve } from "node:path";

import { describe, expect, it } from "vitest";

const APP = resolve(process.cwd(), "app");

/** Routes Next serves, derived from `app/<segment>/page.tsx`. */
function routes(): Set<string> {
  const found = new Set<string>(["/"]);
  const walk = (directory: string, prefix: string) => {
    for (const entry of readdirSync(directory)) {
      const path = join(directory, entry);
      if (statSync(path).isDirectory()) {
        // A route group like (marketing) is not part of the URL.
        if (entry.startsWith("(") && entry.endsWith(")")) continue;
        walk(path, `${prefix}/${entry}`);
      } else if (entry === "page.tsx") {
        found.add(prefix === "" ? "/" : prefix);
      }
    }
  };
  walk(APP, "");
  return found;
}

function sourceFiles(): string[] {
  const files: string[] = [];
  const walk = (directory: string) => {
    for (const entry of readdirSync(directory)) {
      const path = join(directory, entry);
      if (statSync(path).isDirectory()) walk(path);
      else if (/\.tsx?$/.test(entry)) files.push(path);
    }
  };
  walk(APP);
  const components = join(process.cwd(), "components");
  for (const entry of readdirSync(components)) {
    if (entry.endsWith(".tsx")) files.push(join(components, entry));
  }
  return files;
}

/**
 * `href="/somewhere"`, `` href={`/somewhere${x}`} `` and `href={someConstant}`.
 *
 * The last form is the one that hid a 404: the link was assigned to a variable
 * first, so a scanner looking only at literals sees nothing to check. Resolving
 * a string constant is what closes that gap - the same blind spot a `t()`
 * variable created earlier.
 */
function internalHrefs(source: string): string[] {
  const hrefs: string[] = [];

  const push = (value: string) => {
    if (!value.startsWith("/") || value.startsWith("//")) return;
    hrefs.push(value);
  };

  for (const match of source.matchAll(/href\s*=\s*["'`]([^"'`]+)["'`]/g)) {
    push(match[1]);
  }
  for (const match of source.matchAll(/href=\{`([^`]+)`\}/g)) {
    push(match[1]);
  }

  // Constants a link may be assigned to: const benchHref = "/workbench";
  const constants = new Map<string, string>();
  for (const match of source.matchAll(
    /(?:const|let)\s+(\w+)\s*=\s*["'`](\/[^"'`]*)["'`]/g,
  )) {
    constants.set(match[1], match[2]);
  }
  for (const match of source.matchAll(/href=\{([A-Za-z_$][\w$]*)\}/g)) {
    const value = constants.get(match[1]);
    if (value) push(value);
  }
  return hrefs;
}

const KNOWN = routes();

describe("internal links resolve to real pages", () => {
  it("the route table was actually read", () => {
    // A scanner that found nothing would pass every case below vacuously.
    expect(KNOWN.size).toBeGreaterThan(10);
    expect(KNOWN.has("/anomalies")).toBe(true);
    expect(KNOWN.has("/workbench")).toBe(true);
  });

  it.each(
    sourceFiles().flatMap((file) =>
      internalHrefs(readFileSync(file, "utf8")).map((href) => ({
        file: file.replace(`${process.cwd()}\\`, "").replace(/\//g, "\\"),
        href,
      })),
    ),
  )("$file -> $href", ({ href }) => {
    // Only the path matters; query strings and hashes are not routes.
    const path = href.split(/[?#]/)[0].replace(/\/$/, "") || "/";
    expect(
      KNOWN.has(path),
      `${href} is not a route; the app serves ${[...KNOWN].sort().join(", ")}`,
    ).toBe(true);
  });
});

describe("cross-page links carry what the target reads", () => {
  /**
   * `/workbench` and `/streams` read `session` from the query string, not
   * `project`. A link that passes `project` to a page expecting `session` opens
   * the right page with no selection, which looks like the page being broken.
   */
  const TARGET_PARAMS: Record<string, string[]> = {
    "/workbench": ["session"],
    "/streams": ["session"],
  };

  it.each(Object.entries(TARGET_PARAMS))(
    "%s reads %s from the URL",
    (route, expected) => {
      const source = readFileSync(join(APP, route.slice(1), "page.tsx"), "utf8");
      for (const param of expected) {
        expect(source, `${route} does not read ?${param}`).toContain(
          `get("${param}")`,
        );
      }
    },
  );
});