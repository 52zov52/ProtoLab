/**
 * Turn a report evidence reference into a place the reader can go.
 *
 * Evidence items are `{kind, id, ...}` and come straight from the report JSON.
 * Only kinds that actually lead somewhere in this app get a link; everything
 * else keeps its bare id so no target is invented. A click never asserts that
 * the evidence is correct, only that it exists at that address.
 */

export interface EvidenceItem {
  kind: string;
  id: string;
  [key: string]: unknown;
}

export interface EvidenceTarget {
  /** Human label for the reference. */
  label: string;
  /** Absolute route to open, or null when the app has no page for this kind. */
  href: string | null;
  /** Which workspace selection to make before navigating, if any. */
  select: "session" | "capture" | null;
}

const KIND_LABELS: Record<string, string> = {
  project: "project",
  capture: "capture",
  session: "TCP session",
  interpretation: "interpretation",
  validation_run: "validation run",
  validation_result: "counterexample",
  experiment: "experiment log",
  message: "message",
};

export function evidenceLabel(kind: string): string {
  return KIND_LABELS[kind] ?? kind;
}

export function evidenceTarget(item: EvidenceItem, projectId: string): EvidenceTarget {
  const label = evidenceLabel(item.kind);
  const project = `project=${encodeURIComponent(projectId)}`;
  switch (item.kind) {
    case "session":
      return { label, href: `/sessions?${project}`, select: "session" };
    case "capture":
      return { label, href: `/captures?${project}`, select: "capture" };
    case "interpretation":
    case "validation_run":
    case "validation_result":
      return { label, href: `/hypotheses?${project}`, select: null };
    case "project":
      return { label, href: `/settings?${project}`, select: null };
    default:
      // No page shows this kind yet, so do not fabricate a destination.
      return { label, href: null, select: null };
  }
}

/** Short, unambiguous-enough display form of an opaque id. */
export function shortId(id: string): string {
  return id.length > 10 ? `${id.slice(0, 10)}…` : id;
}
